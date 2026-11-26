package protocols

import (
	"crypto/sha256"
	_ "embed"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"testing"
	"time"
)

//go:embed fixtures/reference-winbox.json
var winboxFixtures []byte

func TestReferenceWinboxFileMetadata(t *testing.T) {
	var fixtures []struct {
		Name   string
		Params map[string]any
		Steps  []struct {
			File      string
			ReplySize uint16 `json:"reply_size"`
			SkipSize  uint16 `json:"skip_size"`
			Length    int
			SHA256    string
		}
	}
	if err := json.Unmarshal(winboxFixtures, &fixtures); err != nil {
		t.Fatal(err)
	}
	handler := GetProtocol("winbox").HandleFunc.(func(*SessionConnection) error)
	for _, fixture := range fixtures {
		t.Run(fixture.Name, func(t *testing.T) {
			server, client := net.Pipe()
			defer server.Close()
			defer client.Close()
			if err := client.SetDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			go handler(&SessionConnection{Conn: server, ConfigInfo: &ConfigInfo{BindInfo: &BindInfo{Params: fixture.Params}}})
			for _, step := range fixture.Steps {
				var request [20]byte
				request[0], request[1] = 18, WINBOX_FILE_MODE
				copy(request[2:14], step.File)
				binary.BigEndian.PutUint16(request[14:16], step.ReplySize)
				binary.BigEndian.PutUint16(request[18:20], step.SkipSize)
				if _, err := client.Write(request[:]); err != nil {
					t.Fatal(err)
				}
				reply := make([]byte, step.Length)
				if _, err := io.ReadFull(client, reply); err != nil {
					t.Fatal(err)
				}
				checksum := sha256.Sum256(reply)
				if hex.EncodeToString(checksum[:]) != step.SHA256 {
					t.Fatalf("%s response SHA-256 = %x, want %s", step.File, checksum, step.SHA256)
				}
			}
		})
	}
}
