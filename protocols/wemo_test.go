package protocols

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
)

func TestReferenceWemoAssets(t *testing.T) {
	t.Chdir(t.TempDir())
	entry, ok := registor.Load("wemo")
	if !ok {
		t.Fatal("wemo is not registered")
	}
	factory := entry.(*ProtocolInfo).HandleFunc.(func(*ConfigInfo) http.Handler)
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	config := func(params map[string]any) *ConfigInfo {
		return &ConfigInfo{BindInfo: &BindInfo{Handler: "wemo", Params: params}, Log: logrus.NewEntry(logger)}
	}
	t.Run("no assets closes connection", func(t *testing.T) {
		srv := httptest.NewServer(factory(config(nil)))
		defer srv.Close()
		resp, err := srv.Client().Get(srv.URL + "/setup.xml")
		if err == nil {
			resp.Body.Close()
			t.Fatalf("expected connection close, got status %d", resp.StatusCode)
		}
	})
	const setup = "<root><device><friendlyName>Lab Fixture</friendlyName></device></root>"
	const manifest = `{"url_handlers":[{"value":"/setup.xml","operation":"equal","filepath":"/setup.xml","status":200,"headers":{"Content-Type":"text/xml"}}]}`
	if err := os.Mkdir("wemo-fixture", 0700); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string]string{"setup.xml": setup, "_app_config.json": manifest} {
		if err := os.WriteFile(filepath.Join("wemo-fixture", name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	absolute, err := filepath.Abs("wemo-fixture")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, path, body string
		status           int
	}{
		{"absolute asset directory", absolute, setup, http.StatusOK},
		{"missing absolute asset directory", filepath.Join(absolute, "missing"), "404 page not found\n", http.StatusNotFound},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(factory(config(map[string]any{"fs_path": test.path})))
			defer server.Close()
			response, err := server.Client().Get(server.URL + "/setup.xml")
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			body, err := io.ReadAll(response.Body)
			if err != nil || response.StatusCode != test.status || string(body) != test.body {
				t.Fatalf("got status %d and body %q (%v)", response.StatusCode, body, err)
			}
		})
	}
	srv := httptest.NewServer(factory(config(map[string]any{"fs_path": "wemo-fixture"})))
	defer srv.Close()
	for _, tc := range []struct {
		path, body, contentType string
		status                  int
	}{
		{"/setup.xml", setup, "text/xml", http.StatusOK},
		{"/", "404 page not found\n", "text/plain; charset=utf-8", http.StatusNotFound},
		{"/missing", "404 page not found\n", "text/plain; charset=utf-8", http.StatusNotFound},
	} {
		t.Run(tc.path, func(t *testing.T) {
			resp, err := srv.Client().Get(srv.URL + tc.path)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != tc.status || string(body) != tc.body || resp.Header.Get("Content-Type") != tc.contentType ||
				resp.Header.Get("Server") != "Apache" || resp.Header.Get("Accept-Ranges") != "" {
				t.Fatalf("status=%d headers=%v body=%q", resp.StatusCode, resp.Header, body)
			}
		})
	}
	t.Run("range requests", func(t *testing.T) {
		for _, method := range []string{http.MethodGet, http.MethodHead} {
			req, err := http.NewRequest(method, srv.URL+"/setup.xml", nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Range", "bytes=0-3")
			resp, err := srv.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			wantBody := setup[:4]
			if method == http.MethodHead {
				wantBody = ""
			}
			if err != nil || resp.StatusCode != http.StatusPartialContent || string(body) != wantBody ||
				resp.Header.Get("Content-Range") != "bytes 0-3/"+strconv.Itoa(len(setup)) || resp.Header.Get("Accept-Ranges") != "" {
				t.Fatalf("%s range response = %d, %v, %q, %v", method, resp.StatusCode, resp.Header, body, err)
			}
		}
	})
	t.Run("SOAP action precedes manifest", func(t *testing.T) {
		const action = `"urn:Belkin:service:basicevent:1#GetBinaryState"`
		for _, tc := range []struct {
			method, path, media, soapAction string
			status                          int
		}{
			{http.MethodPost, "/upnp/control/basicevent1", "text/xml; charset=utf-8", action, http.StatusInternalServerError},
			{http.MethodPost, "/setup.xml", "TEXT/XML", action, http.StatusInternalServerError},
			{http.MethodPost, "/setup.xml", "application/soap+xml", action, http.StatusOK},
			{http.MethodPost, "/setup.xml", "text/xml", "", http.StatusOK},
			{http.MethodGet, "/setup.xml", "text/xml", action, http.StatusOK},
		} {
			req, err := http.NewRequest(tc.method, srv.URL+tc.path, nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Type", tc.media)
			req.Header.Set("SOAPAction", tc.soapAction)
			resp, err := srv.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil || resp.StatusCode != tc.status || resp.Header.Get("Server") != "Apache" {
				t.Fatalf("%s %s (%s): status=%d, body=%q, err=%v", tc.method, tc.path, tc.media, resp.StatusCode, body, err)
			}
			if tc.status == http.StatusInternalServerError &&
				(resp.Header.Get("Content-Type") != "text/plain; charset=utf-8" ||
					!strings.Contains(string(body), "<errorCode>401</errorCode><errorDescription>Invalid Action</errorDescription>")) {
				t.Fatalf("unexpected SOAP fault response: %v, %q", resp.Header, body)
			}
		}
	})
	t.Run("explicit server version", func(t *testing.T) {
		srv := httptest.NewServer(factory(config(map[string]any{
			"fs_path": "wemo-fixture", "server_version": wemoServerVersion,
			"headers": []interface{}{"Accept-Ranges: provisioned"},
		})))
		defer srv.Close()
		resp, err := srv.Client().Get(srv.URL + "/setup.xml")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if got := resp.Header.Get("Server"); got != wemoServerVersion {
			t.Fatalf("Server = %q, want %q", got, wemoServerVersion)
		}
		if got := resp.Header.Get("Accept-Ranges"); got != "" {
			t.Fatalf("unexpected configured Accept-Ranges header %q", got)
		}
	})
}
