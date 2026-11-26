package protocols

import (
	"encoding/json"
	"net"
	"net/http"

	"github.com/sirupsen/logrus"
)

func init() {
	AddProtocol(NewProtocolInfo("kubelet", KubeletAPI, 10250),
		ProtocolParams{
			Name:         "ssl",
			DefaultValue: true,
		},
	)
}

// KubeletAPI implements the Kubernetes Kubelet HTTPS API (TCP 10250) scanned by nuclei/fscan.
func KubeletAPI(ci *ConfigInfo) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		addr, _ := net.ResolveTCPAddr("tcp", r.RemoteAddr)
		ci.LogWithRemote("kubelet_request", addr, logrus.Fields{
			"method":     r.Method,
			"uri":        r.RequestURI,
			"user_agent": r.UserAgent(),
		})

		switch r.URL.Path {
		case "/healthz":
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = w.Write([]byte("ok"))
		case "/pods", "/runningpods/":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"kind":       "PodList",
				"apiVersion": "v1",
				"items": []map[string]any{
					{
						"metadata": map[string]any{"name": "coredns-5dd5756b68-k9x2p", "namespace": "kube-system"},
						"status":   map[string]any{"phase": "Running"},
					},
				},
			})
		case "/metrics":
			w.Header().Set("Content-Type", "text/plain; version=0.0.4")
			_, _ = w.Write([]byte("# HELP kubelet_running_pods Number of pods currently running\n# TYPE kubelet_running_pods gauge\nkubelet_running_pods 6\n"))
		default:
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("404 page not found\n"))
		}
	})
}
