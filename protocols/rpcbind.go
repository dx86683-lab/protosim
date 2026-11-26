package protocols

import (
	"encoding/binary"
	"net"
	"net/netip"
	"strconv"
	"time"
)

func rpcbindLocalIP(local net.Addr) netip.Addr {
	if local == nil {
		return netip.Addr{}
	}
	host, _, err := net.SplitHostPort(local.String())
	if err != nil {
		return netip.Addr{}
	}
	address, _ := netip.ParseAddr(host)
	return address.Unmap().WithZone("")
}

func rpcbindReply(xid, version, procedure, protocol uint32, local netip.Addr, args []byte, mappings []portmapMapping) ([]byte, bool) {
	switch procedure {
	case 0: // NULL
		if len(args) == 0 {
			return rpcAcceptedReply(xid, 0, nil), false
		}
	case 1, 2, 3, 9, 11:
		if version == rpcbindVersion3 && (procedure == 9 || procedure == 11) {
			return rpcAcceptedReply(xid, 3, nil), false
		}
		program, requestedVersion, ok := parseRPCBindMappingArgs(args)
		if !ok {
			break
		}
		switch procedure {
		case 1, 2: // SET and UNSET on the read-only table
			return rpcAcceptedReply(xid, 0, nfsWords(0)), false
		case 3, 9: // GETADDR and GETVERSADDR
			port := rpcbindFindPort(mappings, program, requestedVersion, protocol, procedure == 9)
			return rpcAcceptedReply(xid, 0, rpcbindAppendString(nil, rpcbindUniversalAddress(local, port))), false
		case 11: // GETADDRLIST
			return rpcAcceptedReply(xid, 0, rpcbindAddressList(mappings, program, requestedVersion, local)), false
		}
	case 4: // DUMP
		if len(args) == 0 {
			return rpcAcceptedReply(xid, 0, rpcbindDump(mappings, local)), true
		}
	case 5: // CALLIT and BCAST are silent when forwarding is unavailable.
		return nil, false
	case 6: // GETTIME
		if len(args) == 0 {
			return rpcAcceptedReply(xid, 0, nfsWords(uint32(time.Now().Unix()))), false
		}
	default:
		return rpcAcceptedReply(xid, 3, nil), false
	}
	return rpcAcceptedReply(xid, 4, nil), false
}

func parseRPCBindMappingArgs(args []byte) (program, version uint32, ok bool) {
	if len(args) < 8 {
		return 0, 0, false
	}
	program, version = binary.BigEndian.Uint32(args), binary.BigEndian.Uint32(args[4:])
	args = args[8:]
	for range 3 { // netid, universal address, owner
		if _, ok := takeNFSOpaque(&args); !ok {
			return 0, 0, false
		}
	}
	return program, version, len(args) == 0
}

func rpcbindFindPort(mappings []portmapMapping, program, version, protocol uint32, exact bool) uint32 {
	var fallback uint32
	for _, mapping := range mappings {
		if mapping.program != program || mapping.protocol != protocol || mapping.port == 0 || mapping.port > 65535 {
			continue
		}
		if mapping.version == version {
			return mapping.port
		}
		if !exact && fallback == 0 {
			fallback = mapping.port
		}
	}
	return fallback
}

func rpcbindUniversalAddress(local netip.Addr, port uint32) string {
	if !local.IsValid() || port == 0 || port > 65535 {
		return ""
	}
	return local.String() + "." + strconv.FormatUint(uint64(port>>8), 10) + "." + strconv.FormatUint(uint64(port&255), 10)
}

func rpcbindAppendString(wire []byte, value string) []byte {
	return nfsOpaque(wire, []byte(value))
}

func rpcbindTransport(protocol uint32, local netip.Addr) (netid, family, name string, semantics uint32) {
	name, semantics = "tcp", 3 // NC_TPI_COTS_ORD
	if protocol == portmapUDP {
		name, semantics = "udp", 1 // NC_TPI_CLTS
	}
	if local.Is6() {
		return name + "6", "inet6", name, semantics
	}
	return name, "inet", name, semantics
}

func rpcbindDump(mappings []portmapMapping, local netip.Addr) []byte {
	var reply []byte
	for _, mapping := range mappings {
		address := rpcbindUniversalAddress(local, mapping.port)
		if address == "" {
			continue
		}
		netid, _, _, _ := rpcbindTransport(mapping.protocol, local)
		reply = append(reply, nfsWords(1, mapping.program, mapping.version)...)
		reply = rpcbindAppendString(reply, netid)
		reply = rpcbindAppendString(reply, address)
		reply = rpcbindAppendString(reply, "superuser")
	}
	return binary.BigEndian.AppendUint32(reply, 0)
}

func rpcbindAddressList(mappings []portmapMapping, program, version uint32, local netip.Addr) []byte {
	var reply []byte
	for _, mapping := range mappings {
		if mapping.program != program || mapping.version != version {
			continue
		}
		address := rpcbindUniversalAddress(local, mapping.port)
		if address == "" {
			continue
		}
		netid, family, name, semantics := rpcbindTransport(mapping.protocol, local)
		reply = binary.BigEndian.AppendUint32(reply, 1)
		reply = rpcbindAppendString(reply, address)
		reply = rpcbindAppendString(reply, netid)
		reply = binary.BigEndian.AppendUint32(reply, semantics)
		reply = rpcbindAppendString(reply, family)
		reply = rpcbindAppendString(reply, name)
	}
	return binary.BigEndian.AppendUint32(reply, 0)
}
