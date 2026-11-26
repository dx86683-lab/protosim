package protocols

import (
	"bufio"
	"bytes"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

//go:embed fixtures/reference-blockchain-http.json
var blockchainHTTPFixtures []byte

func TestReferenceBlockchainHTTP(t *testing.T) {
	t.Chdir(t.TempDir())
	var fixtures []struct {
		Name, Request, Response string
		SimResponse           string `json:"sim_response"`
	}
	if err := json.Unmarshal(blockchainHTTPFixtures, &fixtures); err != nil {
		t.Fatal(err)
	}
	for _, fixture := range fixtures {
		t.Run(fixture.Name, func(t *testing.T) {
			name := "ethereum"
			if strings.HasPrefix(fixture.Name, "eos") {
				name = "eos"
			}
			entry, ok := registor.Load(name)
			if !ok {
				t.Fatalf("%s is not registered", name)
			}
			requestBytes, err := hex.DecodeString(fixture.Request)
			if err != nil {
				t.Fatal(err)
			}
			req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(requestBytes)))
			if err != nil {
				t.Fatal(err)
			}
			replyHex := fixture.Response
			if fixture.SimResponse != "" {
				replyHex = fixture.SimResponse
			}
			replyBytes, err := hex.DecodeString(replyHex)
			if err != nil {
				t.Fatal(err)
			}
			want, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(replyBytes)), req)
			if err != nil {
				t.Fatal(err)
			}
			defer want.Body.Close()
			rec := httptest.NewRecorder()
			handler := entry.(*ProtocolInfo).HandleFunc.(func(*ConfigInfo) http.Handler)
			handler(&ConfigInfo{BindInfo: &BindInfo{Handler: name}}).ServeHTTP(rec, req)
			got := rec.Result()
			defer got.Body.Close()
			if got.StatusCode != want.StatusCode {
				t.Fatalf("status %d, want %d", got.StatusCode, want.StatusCode)
			}
			for _, key := range []string{"Content-Type", "Content-Length", "Server"} {
				if got.Header.Get(key) != want.Header.Get(key) {
					t.Errorf("%s = %q, want %q", key, got.Header.Get(key), want.Header.Get(key))
				}
			}
			body, err := io.ReadAll(got.Body)
			if err != nil {
				t.Fatal(err)
			}
			expected, err := io.ReadAll(want.Body)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(body, expected) {
				t.Errorf("body %q, want %q", body, expected)
			}
		})
	}
}

func TestBlockchainConfiguredResponses(t *testing.T) {
	for _, tc := range []struct {
		name, path, versionKey, version, payload, want string
		factory                                        func(*ConfigInfo) http.Handler
	}{
		{"eos", "/v1/chain/get_info", "", "", "", `{"block":9007199254740993}`, serveEOS},
		{"ethereum", "/", "ethereum_version", "Fixture/v1", `{"id":45,"method":"web3_clientVersion"}`, `{"id":45,"jsonrpc":"2.0","result":"Fixture/v1"}`, serveEthereum},
		{"ethereum", "/", "", "", `{"id":46,"method":"net_version"}`, `{"id":46,"jsonrpc":"2.0","result":"test"}`, serveEthereum},
	} {
		t.Run(tc.name+tc.payload, func(t *testing.T) {
			config := map[string]any{"server_version": "Fixture HTTP"}
			path := writeBlockchainResponseConfig(t, tc.name)
			config["config_file"] = path
			if tc.versionKey != "" {
				config[tc.versionKey] = tc.version
			}
			req := httptest.NewRequest(http.MethodPost, tc.path, strings.NewReader(tc.payload))
			rec := httptest.NewRecorder()
			tc.factory(&ConfigInfo{BindInfo: &BindInfo{Params: config}}).ServeHTTP(rec, req)
			if rec.Code != http.StatusOK || rec.Header().Get("Server") != "Fixture HTTP" || rec.Body.String() != tc.want {
				t.Fatalf("status=%d server=%q body=%s", rec.Code, rec.Header().Get("Server"), rec.Body.String())
			}
		})
	}
}

func writeBlockchainResponseConfig(t *testing.T, name string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name+".json")
	data := `{"/v1/chain/get_info":{"block":9007199254740993},"net_version":"test"}`
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
