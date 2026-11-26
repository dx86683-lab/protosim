package protocols

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"

	"github.com/sirupsen/logrus"
)

func init() {
	AddProtocol(NewProtocolInfo("etcd", EtcdAPI, 2379),
		ProtocolParams{
			Name:         "server_version",
			DefaultValue: "3.5.14",
		},
		ProtocolParams{
			Name:         "cluster_version",
			DefaultValue: "3.5",
		},
	)
}

// EtcdAPI implements the etcd HTTP/JSON client API (TCP 2379) for /version, /health, /v2/keys.
func EtcdAPI(ci *ConfigInfo) http.Handler {
	srvVer := ci.GetStringParams("server_version", "3.5.14")
	clsVer := ci.GetStringParams("cluster_version", "3.5")

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		addr, _ := net.ResolveTCPAddr("tcp", r.RemoteAddr)
		ci.LogWithRemote("etcd_api_request", addr, logrus.Fields{
			"method":     r.Method,
			"uri":        r.RequestURI,
			"user_agent": r.UserAgent(),
		})

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Etcd-Cluster-Id", "cdf818194e3a8c32")
		w.Header().Set("X-Etcd-Index", "14")
		w.Header().Set("X-Raft-Index", "28")
		w.Header().Set("X-Raft-Term", "2")

		switch {
		case r.URL.Path == "/version":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"etcdserver":  srvVer,
				"etcdcluster": clsVer,
			})
		case r.URL.Path == "/health":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"health": "true",
			})
		case strings.HasPrefix(r.URL.Path, "/v2/keys"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"action": "get",
				"node": map[string]any{
					"dir": true,
					"nodes": []map[string]any{
						{"key": "/config", "dir": true, "modifiedIndex": 4, "createdIndex": 4},
						{"key": "/registry", "dir": true, "modifiedIndex": 5, "createdIndex": 5},
					},
				},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"errorCode": 100,
				"message":   "Key not found",
				"cause":     r.URL.Path,
			})
		}
	})
}
