package protocols

import (
	"crypto/hmac"
	"crypto/md5"
	"encoding/hex"
	"net"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/dx86683-lab/protosim/pkg/smtpd"
)

const (
	SMTP_APPNAME  = "ESMTP"
	SMTP_HOSTNAME = "smtp.protosim.local"
	SMTP_BANNER   = "Postfix (Ubuntu)"
	SMTP_TIMEOUT  = 3
)

func init() {
	AddProtocol(NewProtocolInfo("smtp", SMTP, 25), ProtocolParams{
		Name:         "accounts",
		DefaultValue: []string{"admin:123456"},
	}, ProtocolParams{
		Name:         "appname",
		DefaultValue: SMTP_APPNAME,
	}, ProtocolParams{
		Name:         "timeout",
		DefaultValue: SMTP_TIMEOUT,
	}, ProtocolParams{
		Name:         "banner",
		DefaultValue: SMTP_BANNER,
	}, ProtocolParams{
		Name:         "hostname",
		DefaultValue: SMTP_HOSTNAME,
	}, ProtocolParams{
		Name:         "auth",
		DefaultValue: false,
	}, ProtocolParams{
		Name:         "ssl",
		DefaultValue: false,
	})
}

func SMTP(lc *ListenConnection) error {
	accts := lc.GetStringsParams("accounts", nil)
	authHandler := func(remoteAddr net.Addr, mechanism string, username []byte, password []byte, shared []byte) (bool, error) {
		if len(accts) == 0 {
			return true, nil
		}
		logrus.Println("remote:", remoteAddr, "auth method:", mechanism, "user:", string(username), "pass:", string(password), "shared:", string(shared))

		// 标签 CHECKPASS 是用于在用户名和密码不匹配时跳出外部循环。
		// 密码不匹配时，break CHECKPASS 会终止整个循环，而不是继续检查剩余的账户。
	CHECKPASS:
		for _, auth := range accts {
			cfgUser, cfgPass, ok := strings.Cut(auth, ":")
			if !ok {
				continue
			}
			if cfgUser == string(username) {
				switch mechanism {
				case "CRAM-MD5":
					hash := hmac.New(md5.New, []byte(cfgPass))
					hash.Write(shared)
					encPass := hex.EncodeToString(hash.Sum(nil))
					logrus.Println("enc Pass:", encPass, "--", string(encPass), "password:", password, "--", string(password))
					if encPass == string(password) {
						lc.LogWithRemote("login successfully", remoteAddr, logrus.Fields{
							"mechanism": mechanism,
							"user":      cfgUser,
							"password":  cfgPass,
						})
						return true, nil
					} else {
						break CHECKPASS
					}
				case "PLAIN":
					if cfgPass == string(password) {
						lc.LogWithRemote("login successfully", remoteAddr, logrus.Fields{
							"mechanism": mechanism,
							"user":      cfgUser,
							"password":  cfgPass,
						})
						return true, nil
					} else {
						break CHECKPASS
					}
				default:
					lc.LogWithRemote("unsupported login method", remoteAddr, logrus.Fields{
						"mechanism": mechanism,
						"user":      string(username),
						"password":  string(password),
						"shared":    string(shared),
					})
					return false, nil
				}
			}
		}
		lc.LogWithRemote("login failed", remoteAddr, logrus.Fields{
			"mechanism": mechanism,
			"user":      string(username),
			"password":  string(password),
			"shared":    string(shared),
		})
		return false, nil
	}

	mailHandler := func(remoteAddr net.Addr, from string, to []string, data []byte) error {
		lc.LogWithRemote("new mail", remoteAddr, logrus.Fields{
			"from": from,
			"to":   to,
			"data": data,
		})
		return nil
	}

	addr := lc.Listener.Addr().String()
	timeout := lc.GetIntParams("timeout", SMTP_TIMEOUT)
	mechs := map[string]bool{
		"PLAIN":    true,
		"CRAM-MD5": true,
	}
	srv := &smtpd.Server{
		Addr:         addr,
		Handler:      mailHandler,
		Appname:      lc.GetStringParams("appname", SMTP_APPNAME),
		Hostname:     lc.GetStringParams("hostname", SMTP_HOSTNAME),
		Banner:       lc.GetStringParams("banner", SMTP_BANNER),
		AuthMechs:    mechs,
		AuthHandler:  authHandler,
		AuthRequired: lc.GetBoolParams("auth"),
		MaxSize:      1024,
		Timeout:      time.Second * (time.Duration)(timeout),
	}
	defer func() {
		if err := recover(); err != nil {
			lc.Log.Error("[smtp] handler panic. error:", err)
		}
	}()

	return srv.Serve(lc.Listener)
}
