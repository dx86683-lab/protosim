package protocols

import (
	"net"
	"net/http"
	"strings"

	"github.com/sirupsen/logrus"
)

func init() {
	AddProtocol(NewProtocolInfo("clickhouse", ClickHouseHTTP, 8123),
		ProtocolParams{
			Name:         "version",
			DefaultValue: "24.3.2.23",
		},
	)
}

// ClickHouseHTTP implements the ClickHouse HTTP interface (TCP 8123).
func ClickHouseHTTP(ci *ConfigInfo) http.Handler {
	ver := ci.GetStringParams("version", "24.3.2.23")

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("query")
		addr, _ := net.ResolveTCPAddr("tcp", r.RemoteAddr)
		ci.LogWithRemote("clickhouse_http", addr, logrus.Fields{
			"method": r.Method,
			"uri":    r.RequestURI,
			"query":  q,
		})

		w.Header().Set("X-ClickHouse-Server-Display-Name", "clickhouse-01")
		w.Header().Set("X-ClickHouse-Summary", `{"read_rows":"1","read_bytes":"1","written_rows":"0","written_bytes":"0","total_rows_to_read":"1"}`)
		w.Header().Set("Content-Type", "text/plain; charset=UTF-8")

		ql := strings.ToLower(strings.TrimSpace(q))
		switch {
		case strings.Contains(ql, "version()"):
			_, _ = w.Write([]byte(ver + "\n"))
		case strings.Contains(ql, "show databases"):
			_, _ = w.Write([]byte("default\ninformation_schema\nsystem\n"))
		case r.URL.Path == "/ping" || q == "":
			_, _ = w.Write([]byte("Ok.\n"))
		default:
			_, _ = w.Write([]byte("1\n"))
		}
	})
}
