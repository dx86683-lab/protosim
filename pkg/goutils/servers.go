package goutils

import (
	"github.com/bradleypeabody/godap"
	"net"
	"net/http"
	"path/filepath"
	"time"
)

func StartHTTPStaticServer(port string, staticDir string, onReq http.HandlerFunc) *http.Server {
	fileDir, _ := filepath.Abs(staticDir)
	server := &http.Server{
		Addr: ":" + port,
		Handler: func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if onReq != nil {
					onReq(w, r)
				}
				next.ServeHTTP(w, r)
			})
		}(http.FileServer(http.Dir(fileDir))),
	}
	go server.ListenAndServe()
	return server
}

func StartJMILDAPServer(port string, redirectUrl string, objName string) (ln net.Listener) {
	hs := make([]godap.LDAPRequestHandler, 0)

	// use a LDAPBindFuncHandler to provide a callback function to respond
	// to bind requests
	hs = append(hs, &godap.LDAPBindFuncHandler{LDAPBindFunc: func(binddn string, bindpw []byte) bool {
		return true
	}})

	// use a LDAPSimpleSearchFuncHandler to reply to search queries
	hs = append(hs, &godap.LDAPSimpleSearchFuncHandler{
		LDAPSimpleSearchFunc: func(req *godap.LDAPSimpleSearchRequest) []*godap.LDAPSimpleSearchResultEntry {
			ret := make([]*godap.LDAPSimpleSearchResultEntry, 0, 1)

			// here we produce a single search result that matches whatever
			// they are searching for
			ret = append(ret, &godap.LDAPSimpleSearchResultEntry{
				DN: objName,
				Attrs: map[string]interface{}{
					"javaClassName": []string{"foo"},
					"javaCodeBase":  []string{redirectUrl},
					"objectClass":   []string{"javaNamingReference"},
					"javaFactory":   []string{objName},
				},
			})

			return ret

		},
	})

	s := &godap.LDAPServer{
		Handlers: hs,
	}

	go s.ListenAndServe(":" + port)
	time.Sleep(time.Second)
	return s.Listener
}
