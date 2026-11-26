package protocols

import (
	_ "embed"
	"encoding/json"
	"testing"
)

//go:embed fixtures/reference-ftp.json
var ftpFixtures []byte

//go:embed fixtures/reference-ftp-rename.json
var ftpRenameFixtures []byte

func TestReferenceFTPRenameDestinations(t *testing.T) {
	var steps [][2]string
	if err := json.Unmarshal(ftpRenameFixtures, &steps); err != nil {
		t.Fatal(err)
	}
	requireFTPControlSteps(t, newFTPHandler(), steps)
}

func TestReferenceFTPControlSessions(t *testing.T) {
	var fixtures []struct {
		Name  string
		Steps [][2]string
	}
	if err := json.Unmarshal(ftpFixtures, &fixtures); err != nil {
		t.Fatal(err)
	}
	factory := GetProtocol("ftp").HandleFunc.(func() func(*SessionConnection) error)
	plain, implicitTLS := factory(), factory()
	for _, f := range fixtures {
		t.Log(f.Name)
		// The production listener handles implicit TLS. Here both sessions
		// exercise the FTP controls over an in-memory connection.
		handle := plain
		if f.Name == "implicit-tls" {
			handle = implicitTLS
		}
		requireFTPControlSteps(t, handle, f.Steps)
	}
}

func requireFTPControlSteps(t *testing.T, handle func(*SessionConnection) error, steps [][2]string) {
	t.Helper()
	exchanges := make([]referenceExchange, 0, len(steps))
	for _, step := range steps {
		request := step[0]
		if request != "" {
			request += "\r\n"
		}
		exchanges = append(exchanges, referenceExchange{request, step[1] + "\r\n"})
	}
	params := map[string]interface{}{"accounts": []interface{}{"fixture:lab-only"}}
	requireReferenceTCPHandler(t, handle, params, exchanges)
}

func TestFTPSocketlessUploadPreservesParentFile(t *testing.T) {
	requireReferenceTCPHandler(t, newFTPHandler(), nil, []referenceExchange{
		{"", "220 Welcome to the FTP Server\r\n"},
		{"USER fixture\r\n", "331 User name ok, password required\r\n"},
		{"PASS lab-only\r\n", "230 Password ok, continue\r\n"},
		{"STOR text.txt/child.txt\r\n", "150 Data transfer starting\r\n450 error during transfer: parent /text.txt is not a directory\r\n"},
		{"SIZE text.txt\r\n", "213 4\r\n"},
		{"SIZE text.txt/child.txt\r\n", "450 path text.txt/child.txt not found\r\n"},
		{"QUIT\r\n", "221 Goodbye\r\n"},
	})
}
