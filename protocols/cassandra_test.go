package protocols

import (
	"encoding/binary"
	"encoding/hex"
	"testing"
)

func TestReferenceCassandraNativeSession(t *testing.T) {
	decode := func(wire string) string {
		t.Helper()
		b, err := hex.DecodeString(wire)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	params := map[string]any{"version": 3, "accounts": []any{"fixture:sample-placeholder"}}
	const query = "SELECT release_version FROM system.local"
	request := []byte{4, 0, 0, 8, 7}
	request = binary.BigEndian.AppendUint32(request, uint32(len(query)+7))
	request = binary.BigEndian.AppendUint32(request, uint32(len(query)))
	request = append(request, query...)
	request = append(request, 0, 1, 0)
	queryBody := request[9:]
	compressed := binary.BigEndian.AppendUint32([]byte{4, 1, 0, 18, 7}, uint32(len(queryBody)+6))
	compressed = binary.BigEndian.AppendUint32(compressed, uint32(len(queryBody)))
	// This LZ4 block encodes the query as one literal run.
	compressed = append(compressed, 0xf0, byte(len(queryBody)-15))
	compressed = append(compressed, queryBody...)
	requireReferenceTCP(t, "cassandra", params, []referenceExchange{
		{decode("0400000701000000020000"), decode("840000070200000000")},
		{decode("040000150b000000110001000d5354415455535f4348414e4745040000160500000000"), decode("840000150200000000")},
		{string(request), decode("84000008080000000400000000")},
		{string(compressed), decode("84010012080000000400000000")},
		{decode("060000090500000000"), decode("8300000000000000670000000a0061496e76616c6964206f7220756e737570706f727465642070726f746f636f6c2076657273696f6e202836293b20737570706f727465642076657273696f6e73206172652028332f76332c20342f76342c20352f76352c20362f76362d6265746129")},
	})
}

func TestReferenceCassandraThriftPreservesHeader(t *testing.T) {
	requireReferenceTCP(t, "cassandra", nil, []referenceExchange{{
		"\x00\x00\x00\x1d\x80\x01\x01\x04\x00\x00\x00\x10describe_version\x00\x00\x00\x34\x00",
		"\x00\x00\x00\x2b\x80\x01\x01\x02\x00\x00\x00\x10describe_version\x00\x00\x00\x34\x0b\x00\x00\x00\x00\x00\x0719.39.0\x00",
	}})
}
