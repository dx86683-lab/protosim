package protocols

import (
	"encoding/json"
	"net"
	"net/http"

	"github.com/sirupsen/logrus"
)

func init() {
	AddProtocol(NewProtocolInfo("docker", DockerAPI, 2375),
		ProtocolParams{
			Name:         "version",
			DefaultValue: "26.1.4",
		},
		ProtocolParams{
			Name:         "api_version",
			DefaultValue: "1.45",
		},
	)
}

// DockerAPI implements the Docker Engine Remote HTTP API (TCP 2375) commonly scanned by fscan/nuclei/nmap.
func DockerAPI(ci *ConfigInfo) http.Handler {
	ver := ci.GetStringParams("version", "26.1.4")
	apiVer := ci.GetStringParams("api_version", "1.45")

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		addr, _ := net.ResolveTCPAddr("tcp", r.RemoteAddr)
		ci.LogWithRemote("docker_api_request", addr, logrus.Fields{
			"method":     r.Method,
			"uri":        r.RequestURI,
			"user_agent": r.UserAgent(),
		})

		w.Header().Set("Api-Version", apiVer)
		w.Header().Set("Docker-Experimental", "false")
		w.Header().Set("Ostype", "linux")
		w.Header().Set("Server", "Docker/"+ver+" (linux)")

		switch r.URL.Path {
		case "/_ping":
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("OK"))
		case "/version", "/v1.45/version", "/v1.41/version":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"Platform":   map[string]string{"Name": "Docker Engine - Community"},
				"Version":    ver,
				"ApiVersion": apiVer,
				"MinAPIVersion": "1.24",
				"GoVersion":  "go1.22.4",
				"Os":         "linux",
				"Arch":       "amd64",
				"KernelVersion": "6.8.0-45-generic",
			})
		case "/info", "/v1.45/info":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ID":                "PROTOSIM:DOCKER:0001",
				"Containers":        2,
				"ContainersRunning": 2,
				"Images":            5,
				"Driver":            "overlay2",
				"ServerVersion":     ver,
				"OperatingSystem":   "Ubuntu 24.04 LTS",
				"OSType":            "linux",
				"Architecture":      "x86_64",
				"NCPU":              4,
				"MemTotal":          8589934592,
				"Name":              "docker-node-01",
			})
		case "/containers/json", "/v1.45/containers/json":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{
					"Id":     "a1b2c3d4e5f60001a1b2c3d4e5f60001a1b2c3d4e5f60001a1b2c3d4e5f60001",
					"Names":  []string{"/web-frontend"},
					"Image":  "nginx:1.25-alpine",
					"State":  "running",
					"Status": "Up 12 days",
				},
			})
		case "/images/json", "/v1.45/images/json":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{
					"Id":       "sha256:0000000000000000000000000000000000000000000000000000000000000001",
					"RepoTags": []string{"nginx:1.25-alpine"},
					"Size":     43120000,
				},
			})
		default:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]string{"message": "page not found"})
		}
	})
}
