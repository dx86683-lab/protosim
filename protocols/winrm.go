package protocols

import (
	"net"
	"net/http"
	"strings"

	"github.com/sirupsen/logrus"
)

func init() {
	AddProtocol(NewProtocolInfo("winrm", WinRM, 5985))
}

// WinRM implements the Windows Remote Management WS-Management HTTP endpoint (TCP 5985).
func WinRM(ci *ConfigInfo) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		addr, _ := net.ResolveTCPAddr("tcp", r.RemoteAddr)
		authHdr := r.Header.Get("Authorization")
		ci.LogWithRemote("winrm_request", addr, logrus.Fields{
			"method":     r.Method,
			"uri":        r.RequestURI,
			"has_auth":   authHdr != "",
			"user_agent": r.UserAgent(),
		})

		w.Header().Set("Server", "Microsoft-HTTPAPI/2.0")
		if r.URL.Path != "/wsman" {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		if authHdr == "" || strings.HasPrefix(authHdr, "Negotiate ") || strings.HasPrefix(authHdr, "NTLM ") {
			w.Header().Set("WWW-Authenticate", "Negotiate")
			w.Header().Add("WWW-Authenticate", "Kerberos")
			w.Header().Add("WWW-Authenticate", "Basic realm=\"WSMAN\"")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		if u, p, ok := r.BasicAuth(); ok {
			ci.LogWithRemote("winrm_auth", addr, logrus.Fields{
				"username":  u,
				"password":  p,
				"mechanism": "basic",
				"accepted":  false,
			})
		}
		w.Header().Set("Content-Type", "application/soap+xml;charset=UTF-8")
		w.WriteHeader(http.StatusUnauthorized)
	})
}
