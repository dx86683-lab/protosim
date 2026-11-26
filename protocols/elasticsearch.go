package protocols

import (
	"net/http"
	"strings"
)

func init() {
	AddProtocol(NewProtocolInfo("elasticsearch", ElasticSearch, 9200))
}

func ElasticSearch(ci *ConfigInfo) http.Handler {
	h := NewDefaultHTTPHandler(ci, "ElasticSearch", "elasticsearch")
	h.URLHandler = func(w http.ResponseWriter, r *http.Request) (string, bool) {
		uri := r.URL.Path
		switch {
		case uri == "/":
			return "/index.json", false
		case strings.Contains(uri, "_nodes"):
			return "/nodes.json", false
		case strings.Contains(uri, "_search"):
			return "/search.json", false
		default:
			return uri, false
		}
	}
	h.HeaderHandler = func(w http.ResponseWriter) {
		// 去掉一些字段
		w.Header()["Date"] = nil
		// 这个为什么去不了？作为文件读取的时候的问题：net/http/fs.go：w.Header().Set("Accept-Ranges", "bytes") 写死了
		w.Header()["Accept-Ranges"] = nil
	}
	return h
}
