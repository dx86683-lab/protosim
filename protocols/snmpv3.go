package protocols

import (
	"encoding/asn1"
	"encoding/binary"
	"time"
)

const snmpEngineName = "snmp_Server"
const snmpEnterpriseID = 20408

type snmpV3Packet struct {
	Version int
	Header  snmpV3Header
	USM     []byte
	Scope   snmpV3Scope
}

type snmpV3Header struct {
	ID      asn1.RawValue
	MaxSize int
	Flags   []byte
	Model   int
}

type snmpV3Scope struct {
	Engine, Name []byte
	PDU          asn1.RawValue
}

type snmpUSM struct {
	Engine              []byte
	Boots, Clock        asn1.RawValue
	User, Auth, Privacy []byte
}

func snmpFixedInteger(value asn1.RawValue) (asn1.RawValue, bool) {
	if value.Class != 0 || value.IsCompound || value.Tag != asn1.TagInteger || len(value.Bytes) == 0 || len(value.Bytes) > 4 {
		return asn1.RawValue{}, false
	}
	var data [4]byte
	if value.Bytes[0]&0x80 != 0 {
		data = [4]byte{255, 255, 255, 255}
	}
	copy(data[4-len(value.Bytes):], value.Bytes)
	return asn1.RawValue{Tag: asn1.TagInteger, Bytes: data[:]}, true
}

func serveSNMPv3(conn *UDPConnection, request []byte) error {
	var p snmpV3Packet
	if tail, err := asn1.Unmarshal(request, &p); err != nil || len(tail) != 0 ||
		p.Version != 3 || len(p.Header.Flags) != 1 || p.Header.Flags[0]&3 != 0 ||
		p.Header.MaxSize < 0 || p.Scope.PDU.Class != asn1.ClassContextSpecific ||
		!p.Scope.PDU.IsCompound || p.Scope.PDU.Tag > 8 || p.Scope.PDU.Tag == 4 {
		return nil
	}
	if p.Header.MaxSize == 0 {
		p.Header.MaxSize = 65535
	}
	var ok bool
	if p.Header.ID, ok = snmpFixedInteger(p.Header.ID); !ok {
		return nil
	}
	var usm snmpUSM
	if tail, err := asn1.Unmarshal(p.USM, &usm); err != nil || len(tail) != 0 || len(usm.User) > 32 {
		return nil
	}
	sequence, err := asn1.Marshal(asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true, Bytes: p.Scope.PDU.Bytes})
	if err != nil {
		return err
	}
	var get snmpGet
	if tail, err := asn1.Unmarshal(sequence, &get); err != nil || len(tail) != 0 || len(get.Bindings) > 8 {
		return nil
	}
	if get.RequestID, ok = snmpFixedInteger(get.RequestID); !ok {
		return nil
	}
	name := conn.GetStringParams("engineid", conn.GetStringParams("engineId", snmpEngineName))
	enterprise := conn.GetIntParams("enterpriseid", conn.GetIntParams("enterpriseId", snmpEnterpriseID))
	if len(name) > 27 || enterprise < 0 || enterprise > 0x7fffffff {
		return nil
	}
	engine := binary.BigEndian.AppendUint32(nil, uint32(enterprise)|0x80000000)
	engine = append(append(engine, 5), name...)
	requestTag := p.Scope.PDU.Tag
	tag := 2 // Response.
	empty := len(get.Bindings) == 0
	echoClock := false
	switch {
	case empty && requestTag == 0:
		tag = 8 // Discovery Report.
		get.Bindings = []snmpBinding{{
			OID:   asn1.RawValue{Tag: asn1.TagOID, Bytes: []byte{0x2b, 6, 1, 6, 3, 15, 1, 1, 4, 0}},
			Value: asn1.RawValue{Class: asn1.ClassApplication, Tag: 1, Bytes: []byte{0}},
		}}
	case empty && (requestTag == 1 || requestTag == 5):
		return nil
	case !empty && len(usm.User) != 0:
		get.Status, get.Index = 16, 0
		echoClock = true
	default:
		echoClock = empty
		switch requestTag {
		case 0, 1, 5:
			status, index := get.Status, get.Index
			desc := conn.GetStringParams("sys_desc", snmpDescription)
			if len(desc) > 255 || !snmpReadBindings(&get, requestTag, desc) {
				return nil
			}
			if requestTag != 5 && get.Status == 0 {
				get.Status, get.Index = status, index
			}
		case 2, 8:
			get.Status, get.Index = 13, 0
		case 3:
			if !empty && get.Status == 0 {
				get.Status = 4
			}
		case 6:
			if !empty && get.Status == 0 {
				get.Status = 13
			}
		case 7:
			tag = 7 // Trap.
		}
	}
	usm.Engine = engine
	usm.Auth, usm.Privacy = nil, nil
	clock := time.Now().Unix()
	if echoClock {
		incomingClock, clockOK := snmpFixedInteger(usm.Clock)
		incomingBoots, bootsOK := snmpFixedInteger(usm.Boots)
		if !clockOK || incomingClock.Bytes[0]&0x80 != 0 || !bootsOK || incomingBoots.Bytes[0]&0x80 != 0 {
			return nil
		}
		clock = int64(binary.BigEndian.Uint32(incomingClock.Bytes))
		encodedBoots, err := asn1.Marshal(int64(binary.BigEndian.Uint32(incomingBoots.Bytes)))
		if err != nil {
			return err
		}
		usm.Boots = asn1.RawValue{FullBytes: encodedBoots}
	} else {
		usm.Boots = asn1.RawValue{Tag: asn1.TagInteger, Bytes: []byte{1}}
	}
	encodedClock, err := asn1.Marshal(clock)
	if err != nil {
		return err
	}
	usm.Clock = asn1.RawValue{FullBytes: encodedClock}
	p.USM, err = asn1.Marshal(usm)
	if err != nil {
		return err
	}
	body, err := asn1.Marshal(get)
	if err != nil {
		return err
	}
	var raw asn1.RawValue
	if _, err := asn1.Unmarshal(body, &raw); err != nil {
		return err
	}
	p.Scope.PDU = asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: tag, IsCompound: true, Bytes: raw.Bytes}
	reply, err := asn1.Marshal(p)
	if err != nil {
		return err
	}
	_, err = conn.Write(reply)
	return err
}
