package protocols

import (
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// LDAP root DSE simulation. Only explicitly requested attributes are returned,
// in request order and matched case-sensitively. Filters are not evaluated,
// matching the reference.

var ldapDefaultAttrs = map[string][]string{
	"configurationNamingContext":    {"CN=Configuration,DC=server,DC=local"},
	"currentTime":                   {"20220121031412.0Z"},
	"defaultNamingContext":          {"DC=server,DC=local"},
	"dnsHostName":                   {"server.local"},
	"domainControllerFunctionality": {"7"},
	"domainFunctionality":           {"3"},
	"dsServiceName":                 {"CN=NTDS Settings,CN=Servers,CN=Sites,CN=Configuration,DC=server,DC=local"},
	"forestFunctionality":           {"2"},
	"highestCommittedUSN":           {"14168611"},
	"isGlobalCatalogReady":          {"TRUE"},
	"isSynchronized":                {"TRUE"},
	"ldapServiceName":               {"SERVER.LOCAL"},
	"namingContexts":                {"DC=server,DC=local", "CN=Configuration,DC=server,DC=local", "CN=Schema,CN=Configuration,DC=server,DC=local", "DC=DomainDnsZones,DC=server,DC=local", "DC=ForestDnsZones,DC=server,DC=local"},
	"rootDomainNamingContext":       {"DC=server,DC=local"},
	"schemaNamingContext":           {"CN=Schema,CN=Configuration,DC=server,DC=local"},
	"serverName":                    {"CN=Servers,CN=Sites,CN=Configuration,DC=server,DC=local"},
	"subschemaSubentry":             {"CN=Aggregate,CN=Schema,CN=Configuration,DC=server,DC=local"},
	"supportedCapabilities":         {"1.2.840.113556.1.4.800", "1.2.840.113556.1.4.1670", "1.2.840.113556.1.4.1791", "1.2.840.113556.1.4.1935", "1.2.840.113556.1.4.2080", "1.2.840.113556.1.4.2237"},
	"supportedControl":              {"1.2.840.113556.1.4.319", "1.2.840.113556.1.4.801", "1.2.840.113556.1.4.473", "1.2.840.113556.1.4.528", "1.2.840.113556.1.4.417", "1.2.840.113556.1.4.619", "1.2.840.113556.1.4.841", "1.2.840.113556.1.4.529", "1.2.840.113556.1.4.805", "1.2.840.113556.1.4.521", "1.2.840.113556.1.4.970", "1.2.840.113556.1.4.1338", "1.2.840.113556.1.4.474", "1.2.840.113556.1.4.1339", "1.2.840.113556.1.4.1340", "1.2.840.113556.1.4.1413", "2.16.840.1.113730.3.4.9", "2.16.840.1.113730.3.4.10", "1.2.840.113556.1.4.1504", "1.2.840.113556.1.4.1852", "1.2.840.113556.1.4.802", "1.2.840.113556.1.4.1907", "1.2.840.113556.1.4.1948", "1.2.840.113556.1.4.1974", "1.2.840.113556.1.4.1341", "1.2.840.113556.1.4.2026", "1.2.840.113556.1.4.2064", "1.2.840.113556.1.4.2065", "1.2.840.113556.1.4.2066", "1.2.840.113556.1.4.2090", "1.2.840.113556.1.4.2205", "1.2.840.113556.1.4.2204", "1.2.840.113556.1.4.2206", "1.2.840.113556.1.4.2211", "1.2.840.113556.1.4.2239", "1.2.840.113556.1.4.2255", "1.2.840.113556.1.4.2256", "1.2.840.113556.1.4.2309"},
	"supportedLDAPPolicies":         {"MaxPoolThreads", "MaxPercentDirSyncRequests", "MaxDatagramRecv", "MaxReceiveBuffer", "InitRecvTimeout", "MaxConnections", "MaxConnIdleTime", "MaxPageSize", "MaxBatchReturnMessages", "MaxQueryDuration", "MaxDirSyncDuration", "MaxTempTableSize", "MaxResultSetSize", "MinResultSets", "MaxResultSetsPerConn", "MaxNotificationPerConn", "MaxValRange", "MaxValRangeTransitive", "ThreadMemoryLimit", "SystemMemoryLimitPercent"},
	"supportedLDAPVersion":          {"3", "2"},
	"supportedSASLMechanisms":       {"GSSAPI", "GSS-SPNEGO", "EXTERNAL", "DIGEST-MD5"},
}

const (
	ldapResultSuccess            = 0
	ldapResultProtocolError      = 2
	ldapResultInappropriateAuth  = 48
	ldapResultInvalidCredentials = 49
	ldapResultInsufficientAccess = 50
	ldapInsufficientAccessText   = "Insufficient Access Rights"
)

func init() {
	AddProtocol(NewProtocolInfo("ldap", serveLDAP, 389),
		ProtocolParams{Name: "attrs", DefaultValue: ldapDefaultAttrs})
}

func ldapAttributes(params map[string]any) map[string][]string {
	if configured, ok := params["attrs"]; ok && configured != nil {
		wire, err := json.Marshal(configured)
		if err == nil {
			var m map[string][]string
			if json.Unmarshal(wire, &m) == nil {
				return m
			}
		}
	}
	return ldapDefaultAttrs
}

func ldapResult(id int, op byte, code int, diagnostic string) []byte {
	return berTLV(0x30, berIntBytes(0x02, id), berTLV(op, berIntBytes(0x0a, code), berTLV(0x04), berTLV(0x04, []byte(diagnostic))))
}

func serveLDAP(session *SessionConnection) error {
	defer session.DeleteActivity()
	if err := session.Conn.SetReadDeadline(time.Time{}); err != nil {
		return err
	}
	attrs := ldapAttributes(session.Params)
	remote := session.Conn.RemoteAddr()
	for {
		// Read one message without consuming bytes queued after a terminal call.
		wire, err := readBERMessage(session.Conn)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		msg, err := decodeBER(wire)
		if err != nil || msg.Tag != 0x30 || len(msg.Children) < 2 || msg.Children[0].Tag != 0x02 {
			return errors.New("invalid LDAP message")
		}
		id, op := berInt(msg.Children[0]), msg.Children[1]
		var reply []byte
		switch op.Tag {
		case 0x60: // BindRequest
			if len(op.Children) < 3 {
				return errors.New("invalid LDAP bind")
			}
			version, dn, auth := berInt(op.Children[0]), string(op.Children[1].Value), op.Children[2]
			code := ldapResultSuccess
			if version != 3 || auth.Tag != 0x80 {
				code = ldapResultInappropriateAuth
			} else {
				logSessionEvent(session.ConfigInfo, remote, "bind", logrus.Fields{"dn": dn, "pw": string(auth.Value)})
				if dn != "" || len(auth.Value) != 0 {
					code = ldapResultInvalidCredentials
				}
			}
			reply = ldapResult(id, 0x61, code, "")
		case 0x63: // SearchRequest
			if len(op.Children) < 8 {
				return errors.New("invalid LDAP search")
			}
			base := op.Children[0].Value
			var requested []string
			for _, a := range op.Children[7].Children {
				requested = append(requested, string(a.Value))
			}
			logSessionEvent(session.ConfigInfo, remote, "search", logrus.Fields{
				"base_dn": string(base), "attrs": strings.Join(requested, ","), "dn": "",
			})
			var entries [][]byte
			for _, name := range requested {
				values, found := attrs[name]
				if !found {
					continue
				}
				if name == "currentTime" {
					values = []string{time.Now().UTC().Format("20060102150405.0Z")}
				}
				var set [][]byte
				for _, v := range values {
					set = append(set, berTLV(0x04, []byte(v)))
				}
				entries = append(entries, berTLV(0x30, berTLV(0x04, []byte(name)), berTLV(0x31, set...)))
			}
			entry := berTLV(0x30, berIntBytes(0x02, id), berTLV(0x64, berTLV(0x04, base), berTLV(0x30, entries...)))
			reply = append(entry, ldapResult(id, 0x65, ldapResultSuccess, "")...)
		case 0x66, 0x68, 0x6c: // ModifyRequest, AddRequest, ModifyDNRequest
			reply = ldapResult(id, op.Tag+1, ldapResultInsufficientAccess, ldapInsufficientAccessText)
		case 0x4a: // DelRequest has a primitive tag. DelResponse is constructed.
			reply = ldapResult(id, 0x6b, ldapResultInsufficientAccess, ldapInsufficientAccessText)
		case 0x6e: // CompareRequest
			if len(op.Children) != 2 || op.Children[0].Tag != 0x04 || op.Children[1].Tag != 0x30 {
				return errors.New("invalid LDAP compare")
			}
			reply = ldapResult(id, 0x6f, ldapResultInsufficientAccess, ldapInsufficientAccessText)
		case 0x77: // ExtendedRequest, including StartTLS
			reply = ldapResult(id, 0x78, ldapResultProtocolError, "Protocol Error")
		default: // Unbind, Abandon and unsupported operations end the session.
			return nil
		}
		if err := session.Conn.SetWriteDeadline(time.Now().Add(30 * time.Second)); err != nil {
			return err
		}
		if _, err := session.Conn.Write(reply); err != nil {
			return err
		}
	}
}
