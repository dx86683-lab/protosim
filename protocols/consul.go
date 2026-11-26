package protocols

import (
	"encoding/json"
	"net"
	"net/http"

	"github.com/sirupsen/logrus"
)

func init() {
	AddProtocol(NewProtocolInfo("consul", ConsulAPI, 8500))
}

// ConsulAPI implements the HashiCorp Consul HTTP API (TCP 8500).
func ConsulAPI(ci *ConfigInfo) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		addr, _ := net.ResolveTCPAddr("tcp", r.RemoteAddr)
		ci.LogWithRemote("consul_api_request", addr, logrus.Fields{
			"method": r.Method,
			"uri":    r.RequestURI,
		})

		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/status/leader":
			_, _ = w.Write([]byte(`"127.0.0.1:8300"`))
		case "/v1/agent/self":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"Config": map[string]any{
					"Datacenter": "dc1",
					"NodeName":   "consul-server-01",
					"Server":     true,
					"Version":    "1.18.1",
				},
			})
		case "/v1/catalog/services":
			_ = json.NewEncoder(w).Encode(map[string][]string{
				"consul": {},
				"web":    {"prod"},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
}
