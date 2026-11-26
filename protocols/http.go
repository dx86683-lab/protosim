package protocols

import (
	"bytes"
	"embed"
	"encoding/gob"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/sirupsen/logrus"
)

const staticAppConfigFile = "_app_config.json"

//go:embed staticfs
var staticF embed.FS

var DEFAULT_HTTP_BODY = "It works."
var DEFAULT_HTTP_HEADERS = []string{}

func init() {
	gob.Register(http.Header{})
	gob.Register(map[string]interface{}{})
	AddProtocol(NewProtocolInfo("http", HTTP, 80),
		ProtocolParams{
			Name:         "fs_path",
			DefaultValue: "apachefs",
		},
		ProtocolParams{
			Name:         "server_version",
			DefaultValue: "Apache",
		},
		ProtocolParams{
			Name:         "headers",
			DefaultValue: DEFAULT_HTTP_HEADERS,
		},
		ProtocolParams{
			Name:         "body",
			DefaultValue: DEFAULT_HTTP_BODY,
		},
		ProtocolParams{
			Name:         "ssl",
			DefaultValue: false,
		})
}

// 第二个参数表明是否完成了处理
type URLHandler func(w http.ResponseWriter, r *http.Request) (string, bool)

type DefaultHTTPHandler struct {
	info                 *ConfigInfo
	path                 string
	fsHandler            http.Handler
	name                 string // 名称，用于日志
	localdir             bool   // 是否本地文件系统，不用embed
	Log                  *logrus.Entry
	URLHandler           URLHandler                  //url重定向处理，一些文件名区分，比如elasticsearch的json
	HeaderHandler        func(w http.ResponseWriter) //header处理
	defaultServerVersion string
}

func WrapNoDirFileHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rawW http.ResponseWriter, r *http.Request) {
		uri := r.URL.Path
		if strings.TrimPrefix(uri, "/") == staticAppConfigFile ||
			strings.HasSuffix(uri, "/") {
			http.NotFound(rawW, r)
			return
		}

		wb := NewResponseBuffer(rawW)
		next.ServeHTTP(wb, r)
		// 去掉301目录跳转
		if wb.Status == http.StatusMovedPermanently {
			loc := wb.Header().Get("Location")
			if strings.HasSuffix(loc, "/") {
				wb.Header().Del("Location")
				wb.Body.Reset()
				http.NotFound(wb, r)
			}
		}

		// 设置php文件header
		if strings.HasSuffix(uri, ".php") || strings.HasSuffix(uri, ".jsp") ||
			strings.HasSuffix(uri, ".asp") || strings.HasSuffix(uri, ".aspx") {
			wb.Header().Set("Content-Type", "text/html")
		}

		// logrus.Info("no dir headers :", wb.Header())
		wb.Flush()
	})
}
func NewDefaultHTTPHandler(info *ConfigInfo, name string, fsPath string) *DefaultHTTPHandler {
	var handler http.Handler
	var urlhandler URLHandler
	var headerhandler func(w http.ResponseWriter)
	localdir := false
	if fsPath != "" {
		fullpath, err := filepath.Abs(fsPath)
		if err != nil {
			panic(err)
		}
		entry, err := os.Stat(fullpath)
		switch {
		case os.IsNotExist(err) && !filepath.IsAbs(fsPath):
			// 内嵌文件系统
			fsPath = "/staticfs/" + fsPath
			handler = WrapNoDirFileHandler(http.FileServer(http.FS(staticF)))
		case err != nil || !entry.IsDir():
			handler = http.NotFoundHandler()
		default:
			// Local static directory hosting (with optional _app_config.json)
			fsPath = fullpath
			handler = WrapNoDirFileHandler(http.FileServer(http.Dir(fsPath)))
			if ac, err := loadStaticAppConfig(filepath.Join(fsPath, staticAppConfigFile)); err == nil {
				urlhandler = newStaticURLHandler(ac)
				headerhandler = newStaticHeaderHandler(ac)
			}
			localdir = true
		}
	}
	info.Log = info.Log.WithFields(logrus.Fields{
		"protocol": name,
		"base":     "http",
		"local":    info.ServerInfo,
	})
	return &DefaultHTTPHandler{
		info:                 info,
		path:                 fsPath,
		fsHandler:            handler,
		localdir:             localdir,
		Log:                  info.Log,
		URLHandler:           urlhandler,
		HeaderHandler:        headerhandler,
		defaultServerVersion: "Apache",
	}
}

func (h DefaultHTTPHandler) ServeHTTP(rawW http.ResponseWriter, r *http.Request) {
	reqBody, _ := io.ReadAll(io.LimitReader(r.Body, 10<<20))
	r.Body.Close()
	r.Body = io.NopCloser(bytes.NewBuffer(reqBody))
	addr, _ := net.ResolveTCPAddr("tcp", r.RemoteAddr)
	h.info.LogWithRemote("request", addr, logrus.Fields{
		"method":  r.Method,
		"uri":     r.RequestURI,
		"headers": r.Header,
		"body":    string(reqBody),
	})

	wb := NewResponseBuffer(rawW)
	if h.path == "" {
		wb.Write([]byte(h.info.GetStringParams("body", DEFAULT_HTTP_BODY)))
	} else {
		// 映射embed fs
		var a http.Request = *r
		var url url.URL = *r.URL
		var processed bool
		fixedPath := r.URL.Path
		if h.URLHandler != nil {
			fixedPath, processed = h.URLHandler(wb, r)
			if processed {
				goto HEADER_PROC
			}
		}

		if !h.localdir {
			url.Path = h.path + fixedPath
		} else {
			url.Path = fixedPath
		}
		a.URL = &url

		h.fsHandler.ServeHTTP(wb, &a)
	}

HEADER_PROC:
	// 处理header
	hdrs := h.info.GetStringsParams("headers", DEFAULT_HTTP_HEADERS)
	for _, hdr := range hdrs {
		line := strings.SplitN(hdr, ": ", 2)
		if len(line) > 1 {
			wb.Header().Set(line[0], line[1])
		}
	}
	if server := h.info.GetStringParams("server_version", h.defaultServerVersion); len(server) > 0 {
		if server != "NONE" {
			wb.Header().Set("Server", server)
		}
	}

	if h.HeaderHandler != nil {
		h.HeaderHandler(wb)
	}
	// logrus.Info("http result headers:", wb.Header(), " status:", wb.Status)
	wb.Flush()
}

func ApacheHTTP(ci *ConfigInfo) http.Handler {
	fsPath := ci.GetStringParams("fs_path", "apachefs")
	return NewDefaultHTTPHandler(ci, "ApacheHTTP", fsPath)
}

func HTTP(ci *ConfigInfo) http.Handler {
	fsPath := ci.GetStringParams("fs_path", "")
	return NewDefaultHTTPHandler(ci, "HTTP", fsPath)
}

type staticURLRule struct {
	Value       string                 `json:"value"`
	Operation   string                 `json:"operation"`
	URL         string                 `json:"url"`
	RedirectURL string                 `json:"redirect_url"`
	Filepath    string                 `json:"filepath"`
	Status      uint16                 `json:"status"`
	StatusText  string                 `json:"status_text"`
	Headers     map[string]interface{} `json:"headers"`
}

func (u staticURLRule) matches(uri string) bool {
	pat := u.Value
	if pat == "" {
		pat = u.URL
	}
	if pat == "" {
		return false
	}
	switch strings.ToLower(u.Operation) {
	case "equal", "":
		if pat == uri {
			return true
		}
		if u.Operation == "equal" {
			return false
		}
	case "prefix":
		return strings.HasPrefix(uri, pat)
	case "contains":
		return strings.Contains(uri, pat)
	}
	re, err := regexp.Compile(pat)
	return err == nil && re.MatchString(uri)
}

type staticAppConfig struct {
	Headers       map[string]interface{} `json:"headers"`
	DeleteHeaders []string               `json:"delete_headers"`
	URLHandlers   []staticURLRule        `json:"url_handlers"`
}

func loadStaticAppConfig(filename string) (*staticAppConfig, error) {
	d, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	var ac staticAppConfig
	if err := json.Unmarshal(d, &ac); err != nil {
		return nil, err
	}
	return &ac, nil
}

func newStaticURLHandler(ac *staticAppConfig) URLHandler {
	return func(w http.ResponseWriter, r *http.Request) (string, bool) {
		uri := r.URL.Path
		for _, uh := range ac.URLHandlers {
			if uh.matches(uri) {
				if len(uh.RedirectURL) > 0 {
					http.Redirect(w, r, uh.RedirectURL, http.StatusFound)
					return "", true
				}
				if len(uh.Filepath) > 0 {
					for k, v := range uh.Headers {
						if s, ok := v.(string); ok {
							w.Header().Set(k, s)
						}
					}
					return uh.Filepath, false
				}
				if uh.Status > 0 {
					for k, v := range uh.Headers {
						if s, ok := v.(string); ok {
							w.Header().Set(k, s)
						}
					}
					http.Error(w, uh.StatusText, int(uh.Status))
					return "", true
				}
			}
		}
		return uri, false
	}
}

func newStaticHeaderHandler(ac *staticAppConfig) func(w http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		for _, k := range ac.DeleteHeaders {
			w.Header()[k] = nil
			w.Header().Del(k)
		}
		for k, v := range ac.Headers {
			if s, ok := v.(string); ok {
				w.Header()[k] = []string{s}
			}
		}
	}
}

type responseBuffer struct {
	Response http.ResponseWriter // the actual ResponseWriter to flush to
	Status   int                 // the HTTP response code from WriteHeader
	Body     *bytes.Buffer       // the response content body
	Flushed  bool
}

func NewResponseBuffer(w http.ResponseWriter) *responseBuffer {
	return &responseBuffer{
		Response: w,
		Status:   200,
		Body:     &bytes.Buffer{},
	}
}

func (w *responseBuffer) Header() http.Header {
	return w.Response.Header() // use the actual response header
}

func (w *responseBuffer) Write(buf []byte) (int, error) {
	w.Body.Write(buf)
	return len(buf), nil
}

func (w *responseBuffer) WriteHeader(status int) {
	w.Status = status
}

func (w *responseBuffer) Flush() {
	if w.Flushed {
		return
	}
	w.Response.WriteHeader(w.Status)
	if w.Body.Len() > 0 {
		_, err := w.Response.Write(w.Body.Bytes())
		if err != nil {
			logrus.Error("http write response error: ", err)
		}
		w.Body.Reset()
	}
	w.Flushed = true
}
