package protocols

import "testing"

func TestReferenceDCERPCNegotiation(t *testing.T) {
	tests := []struct {
		name, request, response string
		mask                    [][2]int
	}{
		{
			"endpoint-mapper",
			"05000b03100000004800000020000000b810b8100000000001000000000001000883afe11f5dc91191a408002b14a0fa03000000045d888aeb1cc9119fe808002b10486002000000",
			"05000c03100000003c00000020000000b810b8108159598004003133350000000100000000000000045d888aeb1cc9119fe808002b10486002000000",
			[][2]int{{20, 24}},
		},
		{
			"unknown-interface",
			"05000b03100000004800000020000000b810b810000000000100000000000100" +
				"0000000000000040800000000000000103000000" +
				"045d888aeb1cc9119fe808002b10486002000000",
			"05000c03100000003c00000020000000b810b81081d7e2d204003133350000000100000000000000045d888aeb1cc9119fe808002b10486002000000",
			[][2]int{{20, 24}},
		},
		{
			"reject-unbound-request",
			"05000103100000001000000020000000",
			"05000d03100000001600000020000000040001050000",
			nil,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			runRound6Case(t, round6Case{
				Name: tc.name, Handler: "dcerpc",
				Steps: []round6Step{{Send: tc.request, Recv: tc.response, Mask: tc.mask}},
			})
		})
	}
}

func TestDCERPCRejectsTruncatedContext(t *testing.T) {
	request := "05000b03100000001c00000020000000b810b8100000000001000000"
	runRound6Case(t, round6Case{
		Name: "truncated-context", Handler: "dcerpc",
		Steps: []round6Step{{Send: request, Recv: "05000d03100000001600000020000000040001050000"}},
	})
}
