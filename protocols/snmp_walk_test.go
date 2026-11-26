package protocols

import (
	"bytes"
	_ "embed"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestSNMPTimeTicksEncoding(t *testing.T) {
	for _, tc := range []struct {
		ticks int
		wire  string
	}{
		{0, "430100"},
		{127, "43017f"},
		{128, "43020080"},
		{0x0868, "43020868"},
		{0x8000, "4303008000"},
		{0x800000, "430400800000"},
		{0x7fffffff, "43047fffffff"},
	} {
		encoded, err := asn1.Marshal(snmpTimeTicks(tc.ticks))
		if err != nil || hex.EncodeToString(encoded) != tc.wire {
			t.Errorf("TimeTicks %d = %x (%v), want %s", tc.ticks, encoded, err, tc.wire)
		}
	}
}

func TestSNMPWalkNormalizesCapturedShortTimeTicks(t *testing.T) {
	// The test host returned this GetBulk reply with a two-byte TimeTicks.
	const captured = "302b02010104067075626c6963a21e0204000000230201000201003010300e06082b0601020101030043020868"
	const expected = "302d02010104067075626c6963a2200204000000230201000201003012301006082b06010201010300430400000000"
	packet, err := hex.DecodeString(captured)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := normalizeSNMPTimeTicks(packet)
	if err != nil || hex.EncodeToString(wire) != expected {
		t.Fatalf("normalized response = %x (%v), want %s", wire, err, expected)
	}
	for name, input := range map[string]string{
		"truncated":         captured[:len(captured)-2],
		"bad nested length": strings.Replace(captured, "3010300e", "3010300d", 1),
		"negative ticks":    strings.Replace(captured, "43020868", "43028868", 1),
		"padded ticks":      strings.Replace(captured, "43020868", "43020068", 1),
	} {
		t.Run(name, func(t *testing.T) {
			invalid, err := hex.DecodeString(input)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := normalizeSNMPTimeTicks(invalid); err == nil {
				t.Fatalf("accepted invalid response %x", invalid)
			}
		})
	}
}

//go:embed fixtures/reference-snmp-walk.json
var snmpWalkFixtures []byte

func TestReferenceSNMPWalk(t *testing.T) {
	var cases []struct{ Name, Request, Response string }
	if err := json.Unmarshal(snmpWalkFixtures, &cases); err != nil {
		t.Fatal(err)
	}
	decode := func(t *testing.T, input string) []byte {
		t.Helper()
		result, err := hex.DecodeString(input)
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			want := decode(t, tc.Response)
			got := roundTripDatagram(t, "snmp", nil, decode(t, tc.Request))
			got, err := normalizeSNMPTimeTicks(got)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != len(want) {
				t.Fatalf("SNMP response length %d, want %d; %x", len(got), len(want), got)
			}
			if strings.HasPrefix(tc.Name, "v3-") {
				clockMarker := decode(t, "0201010204")
				offset := bytes.Index(want, clockMarker)
				if offset < 0 {
					t.Fatal("SNMPv3 fixture lacks engine clock")
				}
				offset += len(clockMarker)
				clock := time.Unix(int64(binary.BigEndian.Uint32(got[offset:offset+4])), 0)
				if delta := time.Since(clock); delta < -time.Second || delta > 10*time.Second {
					t.Fatalf("SNMPv3 engine clock differs from test host: %s", clock)
				}
				clear(got[offset : offset+4])
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("SNMP response = %x, want %x", got, want)
			}
		})
	}
}

func normalizeSNMPTimeTicks(packet []byte) ([]byte, error) {
	var root asn1.RawValue
	rest, err := asn1.Unmarshal(packet, &root)
	if err != nil || len(rest) != 0 {
		return nil, fmt.Errorf("invalid SNMP response structure: %x", packet)
	}
	return normalizeSNMPElement(root)
}

func normalizeSNMPElement(value asn1.RawValue) ([]byte, error) {
	if !value.IsCompound {
		return value.FullBytes, nil
	}
	var children []asn1.RawValue
	for rest := value.Bytes; len(rest) > 0; {
		var child asn1.RawValue
		next, err := asn1.Unmarshal(rest, &child)
		if err != nil {
			return nil, err
		}
		children = append(children, child)
		rest = next
	}
	var body []byte
	if value.Class == 0 && value.Tag == asn1.TagSequence && len(children) == 2 &&
		bytes.Equal(children[0].FullBytes, []byte{0x06, 8, 0x2b, 6, 1, 2, 1, 1, 3, 0}) &&
		children[1].FullBytes[0] == 0x43 {
		ticks := children[1].Bytes
		if len(ticks) == 0 || len(ticks) > 4 || ticks[0]&0x80 != 0 ||
			(len(ticks) > 1 && ticks[0] == 0 && ticks[1]&0x80 == 0) {
			return nil, fmt.Errorf("invalid SNMP TimeTicks: %x", ticks)
		}
		body = append(body, children[0].FullBytes...)
		body = append(body, 0x43, 4, 0, 0, 0, 0)
	} else {
		for _, child := range children {
			wire, err := normalizeSNMPElement(child)
			if err != nil {
				return nil, err
			}
			body = append(body, wire...)
		}
	}
	value.FullBytes, value.Bytes = nil, body
	return asn1.Marshal(value)
}
