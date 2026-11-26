package protocols

import (
	_ "embed"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"testing"
)

//go:embed fixtures/reference-tns.json
var tnsFixtures []byte

func TestReferenceTNSListener(t *testing.T) {
	var cases []round6Case
	if err := json.Unmarshal(tnsFixtures, &cases); err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) { runRound6Case(t, tc) })
	}
}

func TestTNSResendUsesConnectionState(t *testing.T) {
	var cases []round6Case
	if err := json.Unmarshal(tnsFixtures, &cases); err != nil {
		t.Fatal(err)
	}
	raw, err := hex.DecodeString(cases[2].Steps[0].Send)
	if err != nil {
		t.Fatal(err)
	}
	offset := int(binary.BigEndian.Uint16(raw[26:28]))
	request := func(selectors string) string {
		descriptor := "(DESCRIPTION=(CONNECT_DATA=" + selectors + "))"
		wire := append(append([]byte(nil), raw[:offset]...), descriptor...)
		binary.BigEndian.PutUint16(wire, uint16(len(wire)))
		binary.BigEndian.PutUint16(wire[24:], uint16(len(descriptor)))
		return string(wire)
	}
	accepted, err := hex.DecodeString(cases[2].Steps[1].Recv)
	if err != nil {
		t.Fatal(err)
	}
	requireReferenceTCP(t, "tns", nil, []referenceExchange{
		{request("(SERVICE_NAME=XE)"), "\x00\x08\x00\x00\x0b\x00\x00\x00"},
		{request("(SID=absent)(SERVICE_NAME=ORCL)"), string(accepted)},
	})
}

func TestTNSModernListenerAcceptsLongHeader(t *testing.T) {
	var cases []round6Case
	if err := json.Unmarshal(tnsFixtures, &cases); err != nil {
		t.Fatal(err)
	}
	for _, fixture := range cases {
		if fixture.Name != "custom-version" {
			continue
		}
		request, err := hex.DecodeString(fixture.Steps[0].Send)
		if err != nil {
			t.Fatal(err)
		}
		response, err := hex.DecodeString(fixture.Steps[0].Recv)
		if err != nil {
			t.Fatal(err)
		}
		binary.BigEndian.PutUint32(request, uint32(len(request)))
		requireReferenceTCP(t, "tns", fixture.Params, []referenceExchange{{string(request), string(response)}})
		return
	}
	t.Fatal("missing custom-version fixture")
}
