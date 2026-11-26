package protocols

import (
	"bytes"
	"encoding/asn1"
	"errors"
	"math/rand/v2"
	"slices"
)

const snmpDescription = "RouterOS x86"

var snmpObjects = [...]asn1.ObjectIdentifier{
	{1, 3, 6, 1, 2, 1, 1, 1, 0}, // sysDescr.0
	{1, 3, 6, 1, 2, 1, 1, 3, 0}, // sysUpTime.0
}

func init() {
	AddProtocol(NewProtocolInfo("snmp", serveSNMP, 161),
		ProtocolParams{Name: "accounts", DefaultValue: []string{"admin:123456"}},
		ProtocolParams{Name: "enterpriseId", DefaultValue: snmpEnterpriseID},
		ProtocolParams{Name: "engineId", DefaultValue: snmpEngineName},
		ProtocolParams{Name: "sys_desc", DefaultValue: snmpDescription})
}

type snmpPacket struct {
	Version   int
	Community []byte
	PDU       asn1.RawValue
}

type snmpGet struct {
	RequestID asn1.RawValue
	Status    int
	Index     int
	Bindings  []snmpBinding
}

type snmpBinding struct {
	OID   asn1.RawValue
	Value asn1.RawValue
}

func serveSNMP(conn *UDPConnection, request []byte) error {
	if len(request) < 8 || len(request) > 4096 {
		return nil
	}
	var envelope asn1.RawValue
	if rest, err := asn1.Unmarshal(request, &envelope); err == nil && len(rest) == 0 &&
		envelope.Class == 0 && envelope.Tag == asn1.TagSequence &&
		bytes.HasPrefix(envelope.Bytes, []byte{2, 1, 3}) {
		return serveSNMPv3(conn, request)
	}
	var packet snmpPacket
	if rest, err := asn1.Unmarshal(request, &packet); err != nil || len(rest) != 0 ||
		(packet.Version != 0 && packet.Version != 1) ||
		packet.PDU.Class != asn1.ClassContextSpecific || !packet.PDU.IsCompound ||
		(packet.PDU.Tag != 0 && packet.PDU.Tag != 1 && !(packet.Version == 1 && packet.PDU.Tag == 5)) {
		return nil
	}
	pdu := packet.PDU
	sequence, err := asn1.Marshal(asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true, Bytes: pdu.Bytes})
	if err != nil {
		return err
	}
	var get snmpGet
	if rest, err := asn1.Unmarshal(sequence, &get); err != nil || len(rest) != 0 ||
		len(get.Bindings) == 0 || len(get.Bindings) > 8 {
		return nil
	}
	var ok bool
	if get.RequestID, ok = snmpFixedInteger(get.RequestID); !ok {
		return nil
	}

	desc := conn.GetStringParams("sys_desc", snmpDescription)
	if len(desc) > 255 {
		return errors.New("simulated SNMP description exceeds limit")
	}
	if !snmpReadBindings(&get, pdu.Tag, desc) {
		return nil
	}
	body, err := asn1.Marshal(get)
	if err != nil {
		return err
	}
	var raw asn1.RawValue
	if _, err := asn1.Unmarshal(body, &raw); err != nil {
		return err
	}
	packet.PDU = asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 2, IsCompound: true, Bytes: raw.Bytes}
	reply, err := asn1.Marshal(packet)
	if err != nil {
		return err
	}
	_, err = conn.Write(reply)
	return err
}

func snmpReadBindings(get *snmpGet, tag int, desc string) bool {
	var oids [8]asn1.ObjectIdentifier
	for i, item := range get.Bindings {
		if tail, err := asn1.Unmarshal(item.OID.FullBytes, &oids[i]); err != nil || len(tail) != 0 {
			return false
		}
	}
	get.Status, get.Index = 0, 0
	value := func(object int) asn1.RawValue {
		if object == 0 {
			return asn1.RawValue{Tag: asn1.TagOctetString, Bytes: []byte(desc)}
		}
		// The reference generates a new unsigned 31-bit TimeTicks value
		// per response rather than a process-uptime counter.
		return snmpTimeTicks(int(rand.Uint32() & 0x7fffffff))
	}
	if tag == 0 {
		for i := range get.Bindings {
			switch {
			case slices.Equal(oids[i], snmpObjects[0]):
				get.Bindings[i].Value = value(0)
			case slices.Equal(oids[i], snmpObjects[1]):
				get.Bindings[i].Value = value(1)
			default:
				get.Status = 2
				get.Bindings[i].Value = asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 1}
			}
		}
		return true
	}

	// The measured GetNext and GetBulk start after the last input OID
	// and return at most the number of input bindings.
	count := len(get.Bindings)
	last := get.Bindings[count-1]
	get.Bindings = nil
	for i, object := range snmpObjects {
		if slices.Compare(object, oids[count-1]) <= 0 {
			continue
		}
		oid, err := asn1.Marshal(object)
		if err != nil {
			return false
		}
		get.Bindings = append(get.Bindings, snmpBinding{OID: asn1.RawValue{FullBytes: oid}, Value: value(i)})
		if len(get.Bindings) == count {
			break
		}
	}
	if len(get.Bindings) == 0 {
		last.Value = asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 2}
		get.Bindings = []snmpBinding{last}
	}
	return true
}

func snmpTimeTicks(ticks int) asn1.RawValue {
	return asn1.RawValue{FullBytes: berIntBytes(0x43, ticks)}
}
