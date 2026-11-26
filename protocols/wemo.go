package protocols

import (
	"io"
	"net/http"
)

const wemoServerVersion = "OS 1.0 UPnP/1.0 Realtek/V1.0"

const wemoInvalidAction = `<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">` +
	`<s:Body><s:Fault><faultcode>s:Client</faultcode><faultstring>UPnPError</faultstring><detail>` +
	`<UPnPError xmlns="urn:schemas-upnp-org:control-1-0"><errorCode>401</errorCode><errorDescription>Invalid Action</errorDescription></UPnPError>` +
	`</detail></s:Fault></s:Body></s:Envelope>`

func init() {
	AddProtocol(NewProtocolInfo("wemo", serveWemo, 49152),
		ProtocolParams{Name: "server_version", DefaultValue: wemoServerVersion})
}

func serveWemo(config *ConfigInfo) http.Handler {
	path := config.GetStringParams("fs_path", "")
	if path == "" {
		return http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			panic(http.ErrAbortHandler)
		})
	}
	handler := NewDefaultHTTPHandler(config, "wemo", path)
	manifest := handler.URLHandler
	handler.URLHandler = func(w http.ResponseWriter, r *http.Request) (string, bool) {
		if r.Method == http.MethodPost && r.Header.Get("SOAPAction") != "" && HasContentType(r, "text/xml") {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = io.WriteString(w, wemoInvalidAction)
			return "", true
		}
		if manifest != nil {
			return manifest(w, r)
		}
		return r.URL.Path, false
	}
	headers := handler.HeaderHandler
	handler.HeaderHandler = func(w http.ResponseWriter) {
		if headers != nil {
			headers(w)
		}
		// Device assets still honor Range requests without advertising them.
		w.Header().Del("Accept-Ranges")
	}
	return handler
}
