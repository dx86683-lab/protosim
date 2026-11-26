package api

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const sessionCookieName = "protosim_session"
const sessionTTL = 24 * time.Hour

func newSessionSecret() []byte {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return b
}

func (s *Server) signSession(exp time.Time) string {
	payload := strconv.FormatInt(exp.Unix(), 10)
	mac := hmac.New(sha256.New, s.sessionKey)
	mac.Write([]byte(payload))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return payload + "." + sig
}

func (s *Server) verifySessionCookie(r *http.Request) bool {
	c, err := r.Cookie(sessionCookieName)
	if err != nil || c.Value == "" {
		return false
	}
	payload, sig, ok := strings.Cut(c.Value, ".")
	if !ok || payload == "" || sig == "" {
		return false
	}
	expUnix, err := strconv.ParseInt(payload, 10, 64)
	if err != nil || time.Now().UTC().Unix() > expUnix {
		return false
	}
	mac := hmac.New(sha256.New, s.sessionKey)
	mac.Write([]byte(payload))
	expected := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return subtle.ConstantTimeCompare([]byte(sig), []byte(expected)) == 1
}

// isAuthenticated checks whether the incoming request has valid credentials
// via HttpOnly session cookie, Bearer/X-API-Token header, query token, or HTTP Basic Auth.
func (s *Server) isAuthenticated(r *http.Request) bool {
	auth := s.cfg.API.Auth
	if !auth.Enabled {
		return true
	}
	if s.verifySessionCookie(r) {
		return true
	}
	if auth.Token != "" {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if tok == "" {
			tok = r.Header.Get("X-API-Token")
		}
		if tok == "" {
			tok = r.URL.Query().Get("token")
		}
		if subtle.ConstantTimeCompare([]byte(tok), []byte(auth.Token)) == 1 {
			return true
		}
	}
	if auth.Username != "" {
		u, p, ok := r.BasicAuth()
		if ok &&
			subtle.ConstantTimeCompare([]byte(u), []byte(auth.Username)) == 1 &&
			subtle.ConstantTimeCompare([]byte(p), []byte(auth.Password)) == 1 {
			return true
		}
	}
	return false
}

func (s *Server) handleAuthLogin(w http.ResponseWriter, r *http.Request) {
	auth := s.cfg.API.Auth
	if !auth.Enabled {
		writeJSON(w, http.StatusOK, map[string]any{"authenticated": true})
		return
	}
	var body struct {
		Token    string `json:"token"`
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	ok := false
	if auth.Token != "" && body.Token != "" {
		if subtle.ConstantTimeCompare([]byte(body.Token), []byte(auth.Token)) == 1 {
			ok = true
		}
	}
	if !ok && auth.Username != "" && body.Username != "" {
		if subtle.ConstantTimeCompare([]byte(body.Username), []byte(auth.Username)) == 1 &&
			subtle.ConstantTimeCompare([]byte(body.Password), []byte(auth.Password)) == 1 {
			ok = true
		}
	}
	if !ok {
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	exp := time.Now().UTC().Add(sessionTTL)
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    s.signSession(exp),
		Path:     "/",
		Expires:  exp,
		MaxAge:   int(sessionTTL.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   r.TLS != nil,
	})
	writeJSON(w, http.StatusOK, map[string]any{"authenticated": true})
}

func (s *Server) handleAuthLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   r.TLS != nil,
	})
	writeJSON(w, http.StatusOK, map[string]any{"authenticated": false})
}

func (s *Server) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.API.Auth.Enabled || s.isAuthenticated(r) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	hasToken := s.cfg.API.Auth.Token != ""
	hasBasic := s.cfg.API.Auth.Username != ""

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintf(w, loginPageHTML, hasToken, hasBasic)
}

const loginPageHTML = `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Sign In</title>
  <style>
    * { box-sizing: border-box; }
    body {
      margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center;
      background: #0f172a; color: #e2e8f0;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "PingFang SC", sans-serif;
    }
    .card {
      width: 100%%; max-width: 380px; background: #1e293b; border: 1px solid #334155;
      border-radius: 12px; padding: 28px 26px; box-shadow: 0 20px 40px rgba(0,0,0,0.4);
    }
    h1 { margin: 0 0 6px; font-size: 20px; color: #f8fafc; }
    .sub { margin: 0 0 20px; font-size: 13px; color: #94a3b8; }
    label { display: block; font-size: 12px; color: #cbd5e1; margin-bottom: 6px; }
    input {
      width: 100%%; padding: 10px 12px; border-radius: 8px; border: 1px solid #475569;
      background: #0f172a; color: #f8fafc; font-size: 14px; margin-bottom: 14px; outline: none;
    }
    input:focus { border-color: #38bdf8; }
    button {
      width: 100%%; padding: 10px; border: none; border-radius: 8px; background: #0284c7;
      color: #fff; font-size: 14px; font-weight: 600; cursor: pointer;
    }
    button:hover { background: #0369a1; }
    button:disabled { opacity: 0.6; cursor: not-allowed; }
    .err { color: #f87171; font-size: 12px; min-height: 18px; margin-bottom: 10px; }
    .hidden { display: none; }
  </style>
</head>
<body>
  <div class="card">
    <h1>Authentication Required</h1>
    <p class="sub">请先完成身份验证后再访问控制台</p>
    <form id="loginForm">
      <div id="tokenBlock">
        <label for="token">API Token</label>
        <input id="token" type="password" autocomplete="current-password" placeholder="请输入 API Token" />
      </div>
      <div id="basicBlock">
        <label for="username">用户名</label>
        <input id="username" type="text" autocomplete="username" placeholder="Username" />
        <label for="password">密码</label>
        <input id="password" type="password" autocomplete="current-password" placeholder="Password" />
      </div>
      <div id="err" class="err"></div>
      <button id="btn" type="submit">登 录</button>
    </form>
  </div>
  <script>
    const hasToken = %t;
    const hasBasic = %t;
    if (!hasToken) document.getElementById('tokenBlock').classList.add('hidden');
    if (!hasBasic) document.getElementById('basicBlock').classList.add('hidden');
    document.getElementById('loginForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      const errEl = document.getElementById('err');
      const btn = document.getElementById('btn');
      errEl.textContent = '';
      btn.disabled = true;
      try {
        const body = {};
        if (hasToken) body.token = document.getElementById('token').value.trim();
        if (hasBasic) {
          body.username = document.getElementById('username').value.trim();
          body.password = document.getElementById('password').value;
        }
        const res = await fetch('/api/v2/auth/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body),
          credentials: 'same-origin'
        });
        if (!res.ok) {
          errEl.textContent = '认证失败，请检查凭证后重试';
          return;
        }
        window.location.replace('/');
      } catch (ex) {
        errEl.textContent = '网络请求失败';
      } finally {
        btn.disabled = false;
      }
    });
  </script>
</body>
</html>
`
