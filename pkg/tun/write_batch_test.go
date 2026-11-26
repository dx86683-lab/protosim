package tun

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

func TestBatchWriteAdapterReportsBytes(t *testing.T) {
	packet := []byte{0x45, 1, 2, 3, 4}
	writeErr := errors.New("closed after write")
	for _, tt := range []struct {
		name      string
		packets   int
		err       error
		wantBytes int
		wantErr   error
	}{
		{"success", 1, nil, len(packet), nil},
		{"packet and error", 1, writeErr, len(packet), writeErr},
		{"short write", 0, nil, 0, io.ErrShortWrite},
		{"failed", 0, writeErr, 0, writeErr},
	} {
		t.Run(tt.name, func(t *testing.T) {
			writer := func(bufs [][]byte, offset int) (int, error) {
				if len(bufs) != 1 || offset != 0 || !bytes.Equal(bufs[0], packet) {
					t.Fatalf("wrong batch write bufs=%x offset=%d", bufs, offset)
				}
				return tt.packets, tt.err
			}
			n, err := writeSinglePacket(writer, packet)
			if n != tt.wantBytes || !errors.Is(err, tt.wantErr) {
				t.Fatalf("Write = (%d,%v), want (%d,%v)", n, err, tt.wantBytes, tt.wantErr)
			}
		})
	}
}
