package protocols

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"
)

//go:embed fixtures/reference-ntp.json
var ntpFixture []byte

func TestReferenceNTPVariants(t *testing.T) {
	var cases []struct {
		Name                 string
		Request, Poll, Reply byte
		Size                 int
		Transmit             string
		Extensions           []int
	}
	if err := json.Unmarshal(ntpFixture, &cases); err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			conn, stop := startRound6Server(t, round6Case{Handler: "ntp", UDP: true})
			defer stop()
			request := make([]byte, c.Size)
			copy(request, []byte{c.Request, 2, c.Poll, 246})
			if c.Transmit == "" {
				c.Transmit = "e93c001001020304"
			}
			transmit, err := hex.DecodeString(c.Transmit)
			if err != nil || len(transmit) != 8 {
				t.Fatalf("invalid fixture timestamp %q", c.Transmit)
			}
			copy(request[40:48], transmit)
			offset := 48
			for _, length := range c.Extensions {
				if length < 4 || offset+length > len(request) {
					t.Fatalf("invalid fixture extension length %d", length)
				}
				binary.BigEndian.PutUint16(request[offset:], 0x2244)
				binary.BigEndian.PutUint16(request[offset+2:], uint16(length))
				offset += length
			}
			started := time.Now()
			if err := conn.SetDeadline(started.Add(250 * time.Millisecond)); err != nil {
				t.Fatal(err)
			}
			if _, err := conn.Write(request); err != nil {
				t.Fatal(err)
			}
			var response [128]byte
			n, err := conn.Read(response[:])
			if c.Reply == 0 {
				if !errors.Is(err, os.ErrDeadlineExceeded) {
					t.Fatalf("expected no response, got %x (%v)", response[:n], err)
				}
				return
			}
			if n != 48 || err != nil {
				t.Fatalf("expected 48-byte response, got %x (%v)", response[:n], err)
			}
			header := []byte{c.Reply, 1, c.Poll, 0xec, 0, 0, 0, 0, 0, 0, 0, 0, 'N', 'I', 'C', 'T'}
			if !bytes.Equal(response[:16], header) || !bytes.Equal(response[24:32], request[40:48]) ||
				!bytes.Equal(response[32:40], response[40:48]) || binary.BigEndian.Uint32(response[20:24]) != 0 {
				t.Fatalf("unexpected response format: %x", response[:n])
			}
			if !bytes.Equal(response[16:20], response[32:36]) {
				t.Fatalf("reference and receive seconds differ: %x", response[:n])
			}
			seconds := int64(binary.BigEndian.Uint32(response[32:36])) - ntpEpochOffset
			fraction := uint64(binary.BigEndian.Uint32(response[36:40]))
			nanoseconds := int64((fraction * 1_000_000_000) >> 32)
			timestamp := time.Unix(seconds, nanoseconds)
			if nanoseconds < 0 || nanoseconds >= int64(time.Second) ||
				timestamp.Before(started.Add(-50*time.Millisecond)) || timestamp.After(time.Now().Add(50*time.Millisecond)) {
				t.Fatalf("unexpected timestamp from %x: %s", response[32:40], timestamp)
			}
		})
	}
}

// Check that an incomplete time header does not produce a datagram.
func TestNTPShortDatagram(t *testing.T) {
	conn, stop := startRound6Server(t, round6Case{Handler: "ntp", UDP: true})
	defer stop()
	if err := conn.SetDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte{0x23}); err != nil {
		t.Fatal(err)
	}
	var response [1]byte
	if _, err := conn.Read(response[:]); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("expected no datagram for incomplete header, got %v", err)
	}
}
