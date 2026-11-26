package protocols

import (
	"strings"
	"testing"
)

func TestRedLionSplitHeaderAndIdentityLength(t *testing.T) {
	const model = "\x00\x04\x01\x2a\x1a\x00"
	const modelReply = "\x00\x0a\x01\x2a\x03\x00G306m\x00"
	manufacturer := strings.Repeat("m", 250)
	requireReferenceTCP(t, "redlion-crimson3", map[string]any{
		"manufacturer": manufacturer + "extra",
	}, []referenceExchange{
		{send: "\x00\x04"},
		{
			send:    "\x01\x2b\x1b\x00" + model,
			receive: "\x00\xff\x01\x2b\x03\x00" + manufacturer + "\x00" + modelReply,
		},
	})
}
