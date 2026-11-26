package protocols

import (
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/sirupsen/logrus"
)

func init() {
	AddProtocol(NewProtocolInfo("hadoop-yarn", HadoopYARN, 8088))
	AddProtocol(NewProtocolInfo("hdfs", HDFSNameNode, 9870))
	AddProtocol(NewProtocolInfo("solr", ApacheSolr, 8983))
	AddProtocol(NewProtocolInfo("influxdb", InfluxDB, 8086))
	AddProtocol(NewProtocolInfo("couchdb", CouchDB, 5984))
	AddProtocol(NewProtocolInfo("neo4j", Neo4jHTTP, 7474))
	AddProtocol(NewProtocolInfo("neo4j-bolt", Neo4jBolt, 7687))
	AddProtocol(NewProtocolInfo("firebird", Firebird, 3050))
	AddProtocol(NewProtocolInfo("db2", DB2DRDA, 50000))
}

func HadoopYARN(ci *ConfigInfo) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		addr, _ := net.ResolveTCPAddr("tcp", r.RemoteAddr)
		ci.LogWithRemote("hadoop_yarn_request", addr, logrus.Fields{"method": r.Method, "uri": r.RequestURI})
		w.Header().Set("Server", "Jetty(9.4.51.v20230217)")
		switch {
		case strings.HasPrefix(r.URL.Path, "/ws/v1/cluster/info"):
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"clusterInfo": map[string]any{
					"id":                    1710000000000,
					"state":                 "STARTED",
					"haState":               "ACTIVE",
					"resourceManagerVersion": "3.3.6",
					"hadoopVersion":         "3.3.6",
				},
			})
		case strings.HasPrefix(r.URL.Path, "/ws/v1/cluster/apps"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"apps":{"app":[]}}`))
		default:
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte("<html><head><title>All Applications - Hadoop YARN ResourceManager</title></head><body><h1>ResourceManager</h1></body></html>"))
		}
	})
}

func HDFSNameNode(ci *ConfigInfo) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		addr, _ := net.ResolveTCPAddr("tcp", r.RemoteAddr)
		ci.LogWithRemote("hdfs_request", addr, logrus.Fields{"method": r.Method, "uri": r.RequestURI})
		w.Header().Set("Server", "Jetty(9.4.51.v20230217)")
		switch {
		case r.URL.Path == "/jmx":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"beans": []map[string]any{
					{"name": "Hadoop:service=NameNode,name=NameNodeInfo", "Version": "3.3.6", "ClusterId": "CID-protosim-01"},
				},
			})
		case strings.HasPrefix(r.URL.Path, "/webhdfs/v1"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"FileStatuses":{"FileStatus":[{"pathSuffix":"user","type":"DIRECTORY"}]}}`))
		default:
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte("<html><head><title>Namenode information</title></head><body><h1>Hadoop HDFS NameNode 3.3.6</h1></body></html>"))
		}
	})
}

func ApacheSolr(ci *ConfigInfo) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		addr, _ := net.ResolveTCPAddr("tcp", r.RemoteAddr)
		ci.LogWithRemote("solr_request", addr, logrus.Fields{"method": r.Method, "uri": r.RequestURI})
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(r.URL.Path, "/admin/info/system"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"responseHeader": map[string]int{"status": 0, "QTime": 1},
				"mode":           "std",
				"lucene":         map[string]string{"solr-spec-version": "9.6.1", "lucene-spec-version": "9.10.0"},
			})
		case strings.Contains(r.URL.Path, "/admin/cores"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"responseHeader": map[string]int{"status": 0, "QTime": 1},
				"status":         map[string]any{"demo": map[string]string{"name": "demo"}},
			})
		default:
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte("<html><head><title>Solr Admin</title></head><body>Apache Solr 9.6.1</body></html>"))
		}
	})
}

func InfluxDB(ci *ConfigInfo) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		addr, _ := net.ResolveTCPAddr("tcp", r.RemoteAddr)
		ci.LogWithRemote("influxdb_request", addr, logrus.Fields{"method": r.Method, "uri": r.RequestURI})
		w.Header().Set("X-Influxdb-Build", "OSS")
		w.Header().Set("X-Influxdb-Version", "1.8.10")
		switch r.URL.Path {
		case "/ping":
			w.WriteHeader(http.StatusNoContent)
		case "/query":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"results":[{"statement_id":0,"series":[{"name":"databases","columns":["name"],"values":[["_internal"],["metrics"]]}]}]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"404 page not found"}`))
		}
	})
}

func CouchDB(ci *ConfigInfo) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		addr, _ := net.ResolveTCPAddr("tcp", r.RemoteAddr)
		ci.LogWithRemote("couchdb_request", addr, logrus.Fields{"method": r.Method, "uri": r.RequestURI})
		w.Header().Set("Server", "CouchDB/3.3.3 (Erlang OTP/25)")
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"couchdb": "Welcome",
				"version": "3.3.3",
				"vendor":  map[string]string{"name": "The Apache Software Foundation"},
			})
		case "/_all_dbs":
			_, _ = w.Write([]byte(`["_users","_replicator","app_data"]`))
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"not_found","reason":"Database does not exist."}`))
		}
	})
}

func Neo4jHTTP(ci *ConfigInfo) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		addr, _ := net.ResolveTCPAddr("tcp", r.RemoteAddr)
		ci.LogWithRemote("neo4j_http_request", addr, logrus.Fields{"method": r.Method, "uri": r.RequestURI})
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"bolt_direct":    "bolt://localhost:7687",
			"neo4j_version":  "5.20.0",
			"neo4j_edition":  "community",
		})
	})
}

// Neo4jBolt implements Neo4j Bolt binary handshake (magic 0x6060b017 + 4 proposed versions).
func Neo4jBolt(sc *SessionConnection) error {
	defer sc.DeleteActivity()

	hs := make([]byte, 20)
	if _, err := io.ReadFull(sc.Conn, hs); err != nil {
		return err
	}
	if hs[0] != 0x60 || hs[1] != 0x60 || hs[2] != 0xb0 || hs[3] != 0x17 {
		return nil
	}
	sc.LogWithRemote("neo4j_bolt_handshake", sc.Conn.RemoteAddr(), logrus.Fields{
		"proposed_v1": binary.BigEndian.Uint32(hs[4:8]),
	})
	// Echo back the first proposed protocol version
	_, err := sc.Conn.Write(hs[4:8])
	return err
}

// Firebird implements Firebird SQL wire protocol op_connect (1) -> op_accept (3).
func Firebird(sc *SessionConnection) error {
	defer sc.DeleteActivity()

	buf := make([]byte, 1024)
	n, err := sc.Conn.Read(buf)
	if err != nil || n < 4 {
		return err
	}
	op := binary.BigEndian.Uint32(buf[0:4])
	sc.LogWithRemote("firebird_connect", sc.Conn.RemoteAddr(), logrus.Fields{"opcode": op, "bytes": n})
	if op == 1 { // op_connect -> op_accept (3), version=10, arch=1, ptype=2
		resp := make([]byte, 16)
		binary.BigEndian.PutUint32(resp[0:4], 3)  // op_accept
		binary.BigEndian.PutUint32(resp[4:8], 10) // PROTOCOL_VERSION10
		binary.BigEndian.PutUint32(resp[8:12], 1) // arch_generic
		binary.BigEndian.PutUint32(resp[12:16], 2)
		_, err = sc.Conn.Write(resp)
		return err
	}
	return nil
}

// DB2DRDA implements IBM DB2 DRDA DSS EXCSAT -> EXCSATRD handshake (TCP 50000).
func DB2DRDA(sc *SessionConnection) error {
	defer sc.DeleteActivity()

	hdr := make([]byte, 6)
	if _, err := io.ReadFull(sc.Conn, hdr); err != nil {
		return err
	}
	if hdr[2] != 0xd0 { // DRDA DDM magic
		return nil
	}
	dssLen := int(binary.BigEndian.Uint16(hdr[0:2]))
	if dssLen > 6 && dssLen < 16384 {
		_, _ = io.CopyN(io.Discard, sc.Conn, int64(dssLen-6))
	}
	sc.LogWithRemote("db2_drda_excsat", sc.Conn.RemoteAddr(), logrus.Fields{"dss_len": dssLen})

	// Minimal EXCSATRD (0x1443) DSS Reply
	resp := []byte{
		0x00, 0x16, 0xd0, 0x02, 0x00, 0x01, // DSS header (len=22, RPYDSS, corr=1)
		0x00, 0x10, 0x14, 0x43, // EXCSATRD (len=16)
		0x00, 0x0c, 0x11, 0x5e, // SRVCLSNM = "QDB2/LINUXX8664" (truncated EBCDIC-like)
		0xd8, 0xc4, 0xc2, 0xf2, 0x61, 0xd3, 0xc9, 0xd5,
	}
	_, err := sc.Conn.Write(resp)
	return err
}
