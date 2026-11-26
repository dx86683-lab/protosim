package protocols

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"
)

//go:embed fixtures/reference-snmpv3.json
var snmpV3Fixtures []byte

func TestReferenceSNMPv3DiscoveryAndRead(t *testing.T) {
	var cases []struct {
		Name, Clock       string
		Custom            bool
		EchoClock         bool `json:"echo_clock"`
		Request, Response string
	}
	if err := json.Unmarshal(snmpV3Fixtures, &cases); err != nil {
		t.Fatal(err)
	}
	decode := func(t *testing.T, s string) []byte {
		t.Helper()
		wire, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return wire
	}
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			params := map[string]any{}
			if tc.Custom {
				params = map[string]any{"engineid": "lab-engine", "enterpriseid": 321, "sys_desc": "Lab SNMP", "accounts": []any{"fixture:lab-only"}}
			}
			if tc.Response == "" {
				runRound6Case(t, round6Case{Handler: "snmp", UDP: true, Params: params,
					Steps: []round6Step{{Send: tc.Request, Silence: true}}})
				return
			}
			request := decode(t, tc.Request)
			const bootAndTimePrefix = "\x02\x01\x01\x02\x04"
			requestClock := bytes.Index(request, []byte(bootAndTimePrefix))
			if requestClock >= 0 && tc.Clock == "" {
				requestClock += len(bootAndTimePrefix)
				binary.BigEndian.PutUint32(request[requestClock:requestClock+4], 0x6b000000)
			}
			got := roundTripDatagram(t, "snmp", params, request)
			want := decode(t, tc.Response)
			if tc.Clock != "literal" {
				offset := bytes.Index(want, []byte(bootAndTimePrefix))
				if offset < 0 || len(got) != len(want) {
					t.Fatalf("SNMP reply length = %d, want %d", len(got), len(want))
				}
				offset += len(bootAndTimePrefix)
				clock := int64(binary.BigEndian.Uint32(got[offset:]))
				if tc.EchoClock {
					if requestClock < 0 || !bytes.Equal(got[offset:offset+4], request[requestClock:requestClock+4]) {
						t.Fatal("SNMP response did not echo the submitted clock")
					}
				} else if now := time.Now().Unix(); clock < now-5 || clock > now+5 {
					t.Fatalf("SNMP response clock = %d, want wall-clock time near %d", clock, now)
				}
				clear(got[offset : offset+4])
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("SNMP reply = %x, want %x", got, want)
			}
		})
	}
}

func TestReferenceSNMPv3EchoesZeroClock(t *testing.T) {
	request, _ := hex.DecodeString("306f020103300e020165020300ffe304010402010304283026041080004fb805736e6d705f536572766572020101020400000000040561646d696e040004003030041080004fb805736e6d705f5365727665720400a01a020200c9020100020100300e300c06082b060102010101000500")
	want, _ := hex.DecodeString("30710201033011020400000065020300ffe304010402010304253023041080004fb805736e6d705f536572766572020101020100040561646d696e040004003032041080004fb805736e6d705f5365727665720400a21c0204000000c9020110020100300e300c06082b060102010101000500")
	requireReferenceDatagram(t, "snmp", request, want)
}
