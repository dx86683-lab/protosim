package protocols

import (
	"encoding/json"
	"net"
	"net/http"

	"github.com/sirupsen/logrus"
)

func init() {
	AddProtocol(NewProtocolInfo("k8s-apiserver", K8sAPIServer, 6443), ProtocolParams{Name: "ssl", DefaultValue: true})
	AddProtocol(NewProtocolInfo("docker-registry", DockerRegistry, 5000))
	AddProtocol(NewProtocolInfo("vault", HashiCorpVault, 8200))
	AddProtocol(NewProtocolInfo("prometheus", PrometheusHTTP, 9090))
	AddProtocol(NewProtocolInfo("minio", MinIOS3, 9001))
	AddProtocol(NewProtocolInfo("grafana", GrafanaHTTP, 3000))
	AddProtocol(NewProtocolInfo("kibana", KibanaHTTP, 5601))
	AddProtocol(NewProtocolInfo("jenkins", JenkinsHTTP, 8080))
}

func K8sAPIServer(ci *ConfigInfo) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		addr, _ := net.ResolveTCPAddr("tcp", r.RemoteAddr)
		ci.LogWithRemote("k8s_api_request", addr, logrus.Fields{"method": r.Method, "uri": r.RequestURI})
		w.Header().Set("Audit-Id", "protosim-k8s-001")
		switch r.URL.Path {
		case "/healthz", "/livez", "/readyz":
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = w.Write([]byte("ok"))
		case "/version":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"major": "1", "minor": "30", "gitVersion": "v1.30.2", "platform": "linux/amd64",
			})
		case "/api":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"kind": "APIVersions", "versions": []string{"v1"}})
		default:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"kind": "Status", "apiVersion": "v1", "status": "Failure",
				"message": "forbidden: User \"system:anonymous\" cannot get path \"" + r.URL.Path + "\"",
				"reason":  "Forbidden", "code": 403,
			})
		}
	})
}

func DockerRegistry(ci *ConfigInfo) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		addr, _ := net.ResolveTCPAddr("tcp", r.RemoteAddr)
		ci.LogWithRemote("docker_registry_request", addr, logrus.Fields{"method": r.Method, "uri": r.RequestURI})
		w.Header().Set("Docker-Distribution-Api-Version", "registry/2.0")
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		switch r.URL.Path {
		case "/v2/":
			_, _ = w.Write([]byte("{}"))
		case "/v2/_catalog":
			_, _ = w.Write([]byte(`{"repositories":["library/nginx","internal/app"]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"errors":[{"code":"NAME_UNKNOWN","message":"repository name not known to registry"}]}`))
		}
	})
}

func HashiCorpVault(ci *ConfigInfo) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		addr, _ := net.ResolveTCPAddr("tcp", r.RemoteAddr)
		ci.LogWithRemote("vault_request", addr, logrus.Fields{"method": r.Method, "uri": r.RequestURI})
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		switch r.URL.Path {
		case "/v1/sys/health", "/v1/sys/seal-status":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"initialized": true, "sealed": false, "standby": false,
				"version": "1.16.2", "cluster_name": "vault-cluster-protosim",
			})
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"errors":[]}`))
		}
	})
}

func PrometheusHTTP(ci *ConfigInfo) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		addr, _ := net.ResolveTCPAddr("tcp", r.RemoteAddr)
		ci.LogWithRemote("prometheus_request", addr, logrus.Fields{"method": r.Method, "uri": r.RequestURI})
		switch r.URL.Path {
		case "/-/healthy", "/-/ready":
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = w.Write([]byte("Prometheus Server is Healthy.\n"))
		case "/api/v1/status/buildinfo":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"status":"success","data":{"version":"2.52.0","goVersion":"go1.22.3"}}`))
		case "/metrics":
			w.Header().Set("Content-Type", "text/plain; version=0.0.4")
			_, _ = w.Write([]byte("# HELP prometheus_build_info Build info\n# TYPE prometheus_build_info gauge\nprometheus_build_info{version=\"2.52.0\"} 1\n"))
		default:
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte("<html><head><title>Prometheus Time Series Collection and Processing Server</title></head><body>Prometheus 2.52.0</body></html>"))
		}
	})
}

func MinIOS3(ci *ConfigInfo) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		addr, _ := net.ResolveTCPAddr("tcp", r.RemoteAddr)
		ci.LogWithRemote("minio_request", addr, logrus.Fields{"method": r.Method, "uri": r.RequestURI})
		w.Header().Set("Server", "MinIO")
		w.Header().Set("X-Amz-Request-Id", "17C0PROTOSIM0001")
		if r.URL.Path == "/minio/health/live" || r.URL.Path == "/minio/health/ready" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><Error><Code>AccessDenied</Code><Message>Access Denied.</Message><Resource>/</Resource><RequestId>17C0PROTOSIM0001</RequestId></Error>`))
	})
}

func GrafanaHTTP(ci *ConfigInfo) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		addr, _ := net.ResolveTCPAddr("tcp", r.RemoteAddr)
		ci.LogWithRemote("grafana_request", addr, logrus.Fields{"method": r.Method, "uri": r.RequestURI})
		if r.URL.Path == "/api/health" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"commit":"a7c9b12","database":"ok","version":"10.4.2"}`))
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<!DOCTYPE html><html><head><title>Grafana</title></head><body>Grafana v10.4.2</body></html>"))
	})
}

func KibanaHTTP(ci *ConfigInfo) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		addr, _ := net.ResolveTCPAddr("tcp", r.RemoteAddr)
		ci.LogWithRemote("kibana_request", addr, logrus.Fields{"method": r.Method, "uri": r.RequestURI})
		w.Header().Set("kbn-name", "kibana")
		w.Header().Set("kbn-version", "8.13.4")
		w.Header().Set("kbn-license-sig", "protosim")
		if r.URL.Path == "/api/status" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"name":"kibana","version":{"number":"8.13.4"},"status":{"overall":{"level":"available"}}}`))
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<!DOCTYPE html><html><head><title>Elastic</title></head><body>Kibana 8.13.4</body></html>"))
	})
}

func JenkinsHTTP(ci *ConfigInfo) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		addr, _ := net.ResolveTCPAddr("tcp", r.RemoteAddr)
		ci.LogWithRemote("jenkins_request", addr, logrus.Fields{"method": r.Method, "uri": r.RequestURI})
		w.Header().Set("Server", "Jetty(10.0.20)")
		w.Header().Set("X-Jenkins", "2.452.1")
		w.Header().Set("X-Hudson", "1.395")
		w.Header().Set("X-Jenkins-Session", "protosim01")
		if r.URL.Path == "/api/json" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"mode":"NORMAL","nodeDescription":"the Jenkins controller","jobs":[]}`))
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("<html><head><title>Sign in [Jenkins]</title></head><body>Authentication required</body></html>"))
	})
}
