package protocols

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/sirupsen/logrus"
)

func TestBindInfoJSONMarshalAndHostInfoRace(t *testing.T) {
	bi := &BindInfo{
		Handler: "http",
		Port:    8080,
		IP:      "127.0.0.1",
		Log:     logrus.New(),
		ActivityFn: func(addr net.Addr, bi *BindInfo, isClose bool) {
		},
	}
	data, err := json.Marshal(bi)
	if err != nil {
		t.Fatalf("json.Marshal(BindInfo) failed: %v", err)
	}
	if strings.Contains(string(data), `"_"`) {
		t.Fatalf("BindInfo marshaled internal fields under \"_\": %s", data)
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 100 {
				if got := bi.GetHostInfo(); got != "127.0.0.1:8080" {
					t.Errorf("GetHostInfo() = %q", got)
				}
			}
		}()
	}
	wg.Wait()
}

func TestBindInfoAccountAndParamSafety(t *testing.T) {
	bi := &BindInfo{
		Params: map[string]interface{}{
			"accounts": []interface{}{"malformed_no_colon", "alice:p@ss:word"},
			"flag":     "not_a_bool",
			"name":     12345,
			"list":     []string{"a", "b"},
		},
	}
	if ok, configured := bi.IsAccountValid("alice", "p@ss:word"); !ok || !configured {
		t.Fatalf("expected colon password to validate: ok=%v configured=%v", ok, configured)
	}
	if ok, configured := bi.IsAccountValid("malformed_no_colon", ""); ok || !configured {
		t.Fatalf("malformed account entry should not match: ok=%v configured=%v", ok, configured)
	}
	if bi.GetBoolParams("flag") {
		t.Fatal("non-bool param should return false")
	}
	if got := bi.GetStringParams("name", "fallback"); got != "fallback" {
		t.Fatalf("non-string param = %q, want fallback", got)
	}
	if got := bi.GetStringsParams("list", nil); len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("[]string param = %v", got)
	}
}

func TestReadRPCRecordRejectsEmptyNonFinalFragment(t *testing.T) {
	// RFC 5531 §11: repeated zero-length non-final fragments must not spin indefinitely.
	data := bytes.Repeat([]byte{0, 0, 0, 0}, 8)
	if _, err := readRPCRecord(bytes.NewReader(data), 1024); err == nil {
		t.Fatal("expected error for empty non-final RPC fragment")
	}
}

func TestSMBNTLMMICRequiredFlagDetection(t *testing.T) {
	// 16-byte NTProofStr + 28-byte NTLMv2 client blob header + AV_PAIR(MsvAvFlags=0x0002) + MsvAvEOL.
	nt := make([]byte, 44)
	nt = binary.LittleEndian.AppendUint16(nt, 6) // MsvAvFlags
	nt = binary.LittleEndian.AppendUint16(nt, 4)
	nt = binary.LittleEndian.AppendUint32(nt, 0x00000002)
	nt = binary.LittleEndian.AppendUint16(nt, 0) // MsvAvEOL
	nt = binary.LittleEndian.AppendUint16(nt, 0)
	if !smbNTLMMICRequired(nt) {
		t.Fatal("expected smbNTLMMICRequired to return true when MsvAvFlags bit 0x02 is set")
	}
	if smbNTLMMICRequired(make([]byte, 44)) {
		t.Fatal("expected smbNTLMMICRequired to return false without MsvAvFlags")
	}
}

func TestHTTPWrapNoDirEmptyPathNoPanic(t *testing.T) {
	handler := WrapNoDirFileHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.URL.Path = ""
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}
