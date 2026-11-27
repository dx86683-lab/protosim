#!/usr/bin/env python3
"""Cross-platform E2E functional test suite for ProtoSim (Linux / Windows / macOS)."""

import http.cookiejar
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request


TOKEN = "ci_test_token_12345"
HOST = "127.0.0.1"
API_PORT = 15555
BASE = f"http://{HOST}:{API_PORT}"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
opener_noredir = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())


def raw_req(method, path, body=None, headers=None, follow=True):
    data = json.dumps(body).encode("utf-8") if body is not None else None
    hdrs = dict(headers or {})
    if data is not None and "Content-Type" not in hdrs:
        hdrs["Content-Type"] = "application/json"
    req = urllib.request.Request(BASE + path, data=data, headers=hdrs, method=method)
    op = opener if follow else opener_noredir
    try:
        with op.open(req, timeout=10) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


def main():
    if len(sys.argv) < 2:
        print("Usage: e2e_cross_platform.py <path-to-protosim-binary>")
        sys.exit(2)

    binary = os.path.abspath(sys.argv[1])
    tmpdir = tempfile.mkdtemp(prefix="protosim-e2e-")
    cfg_path = os.path.join(tmpdir, "protosim.json")
    db_path = os.path.join(tmpdir, "protosim.db")
    log_path = os.path.join(tmpdir, "protosim.log")

    cfg = {
        "scenario": "ci-cross-platform",
        "network": {"mode": "localhost", "cidr": "10.99.0.1/24", "mtu": 1500, "max_conns": 1024},
        "api": {"listen": f"{HOST}:{API_PORT}"},
        "storage": {"db_path": db_path, "payload_enabled": True, "max_payload_bytes": 65536},
        "hosts": [
            {
                "ip": HOST,
                "services": [
                    {"protocol": "http", "port": 18080},
                    {"protocol": "mysql", "port": 13306},
                    {"protocol": "ldap", "port": 10389},
                    {"protocol": "redis", "port": 16379},
                    {"protocol": "tftp", "port": 10069},
                    {"protocol": "netbios", "port": 10137},
                ],
            }
        ],
    }
    with open(cfg_path, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)

    log_f = open(log_path, "wb")
    proc = subprocess.Popen(
        [
            binary,
            "run",
            "-c",
            cfg_path,
            "--auth-token",
            TOKEN,
            "--catch-all-tcp",
            "19999",
        ],
        stdout=log_f,
        stderr=subprocess.STDOUT,
    )

    passed = 0
    failed = 0

    def check(name, cond, detail=""):
        nonlocal passed, failed
        if cond:
            passed += 1
            print(f"  [PASS] {name}" + (f" ({detail})" if detail else ""))
        else:
            failed += 1
            print(f"  [FAIL] {name}" + (f" ({detail})" if detail else ""))

    try:
        # Wait for health endpoint
        ready = False
        for _ in range(60):
            try:
                st, _, _ = raw_req("GET", "/api/v2/health")
                if st == 200:
                    ready = True
                    break
            except Exception:
                pass
            time.sleep(0.2)
        if not ready:
            raise RuntimeError("ProtoSim failed to start within 12s")

        auth = {"X-API-Token": TOKEN}

        # 1. Auth & security gate
        st, hdrs, _ = raw_req("GET", "/", follow=False)
        check("Unauth / -> 302 /login", st == 302 and "/login" in hdrs.get("Location", ""), f"st={st}")

        st, _, body = raw_req("GET", "/login")
        check("GET /login -> 200 HTML", st == 200 and b"<form" in body.lower())

        st, _, _ = raw_req("GET", "/assets/index.js")
        check("Unauth /assets/* -> 401", st == 401, f"st={st}")

        st, _, body = raw_req("GET", "/api/v2/health")
        h_unauth = json.loads(body)
        check("Unauth /api/v2/health minimal", st == 200 and h_unauth.get("auth_enabled") is True and "version" not in h_unauth)

        st, _, _ = raw_req("GET", "/api/v2/sessions")
        check("Unauth /api/v2/sessions -> 401", st == 401)

        cj = http.cookiejar.CookieJar()
        op_cookie = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(cj))
        login_req = urllib.request.Request(
            BASE + "/api/v2/auth/login",
            data=json.dumps({"token": TOKEN}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with op_cookie.open(login_req, timeout=10) as r:
            sc = r.headers.get("Set-Cookie", "")
            check("Cookie login sets HttpOnly", r.status == 200 and "protosim_session=" in sc and "HttpOnly" in sc)
        with op_cookie.open(BASE + "/", timeout=10) as r:
            check("Cookie GET / -> 200 SPA", r.status == 200 and b"<!doctype html>" in r.read()[:256].lower())

        st, _, _ = raw_req("POST", "/api/v2/services", {"ip": HOST, "protocol": "tcp_forward", "port": 28889}, headers=auth)
        check("Dynamic tcp_forward blocked", st == 400, f"st={st}")

        st, _, _ = raw_req(
            "PUT",
            "/api/v2/config/runtime",
            {"webhook": {"enabled": True, "url": "http://169.254.169.254/latest/meta-data"}},
            headers=auth,
        )
        check("SSRF metadata webhook blocked", st == 400, f"st={st}")

        # 2. Core API & hot-add/delete
        st, _, body = raw_req("GET", "/api/v2/health", headers=auth)
        h_auth = json.loads(body)
        check("Auth /api/v2/health", st == 200 and h_auth.get("services") == 6, str(h_auth))

        st, _, body = raw_req("GET", "/api/v2/protocols", headers=auth)
        pdata = json.loads(body)
        pitems = pdata.get("items", pdata) if isinstance(pdata, dict) else pdata
        check("Registered protocols >= 159", st == 200 and len(pitems) >= 159, f"count={len(pitems)}")

        st, _, _ = raw_req("POST", "/api/v2/services", {"ip": HOST, "protocol": "redis", "port": 28888}, headers=auth)
        check("Hot-add redis:28888", st in (200, 201), f"st={st}")
        s = socket.create_connection((HOST, 28888), timeout=3)
        s.settimeout(3)
        s.sendall(b"*1\r\n$4\r\nPING\r\n")
        check("Probe hot-added redis -> PONG", b"PONG" in s.recv(64))
        s.close()
        st, _, _ = raw_req("DELETE", f"/api/v2/services/{HOST}:28888:tcp:redis", headers=auth)
        check("Hot-delete redis:28888", st == 200)

        # Wait for prior flush so TestRun window is clean
        time.sleep(0.5)

        # 3. 5-state TestRun + multi-protocol probes + UDP + Catch-All + PCAP
        st, _, body = raw_req("POST", "/api/v2/test-runs", {"name": "CI Cross-Platform E2E"}, headers=auth)
        run_id = json.loads(body)["id"]
        check("Create TestRun", st in (200, 201), run_id)

        # hit: HTTP
        s = socket.create_connection((HOST, 18080), timeout=3)
        s.settimeout(3)
        s.sendall(b"GET /ci-e2e HTTP/1.1\r\nHost: localhost\r\nUser-Agent: Nmap Scripting Engine\r\nConnection: close\r\n\r\n")
        resp = s.recv(512)
        s.close()
        check("TCP HTTP 200 OK", b"200 OK" in resp)

        # banner_only: MySQL
        s = socket.create_connection((HOST, 13306), timeout=3)
        s.settimeout(3)
        banner = s.recv(256)
        s.close()
        check("TCP MySQL banner", len(banner) >= 40, f"len={len(banner)}")

        # connect_only: LDAP
        s = socket.create_connection((HOST, 10389), timeout=3)
        s.close()

        # UDP TFTP
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        u.settimeout(3)
        u.sendto(b"\x00\x01test.txt\x00octet\x00", (HOST, 10069))
        d, _ = u.recvfrom(256)
        u.close()
        check("UDP TFTP response", len(d) >= 10, f"len={len(d)}")

        # UDP NetBIOS
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        u.settimeout(3)
        nb = bytes.fromhex(
            "12340000000100000000000020434b4141414141414141414141414141414141"
            "414141414141414141414141410000210001"
        )
        u.sendto(nb, (HOST, 10137))
        d, _ = u.recvfrom(512)
        u.close()
        check("UDP NetBIOS response", len(d) >= 50, f"len={len(d)}")

        # Catch-All TCP
        s = socket.create_connection((HOST, 19999), timeout=3)
        s.sendall(b"CI-CATCHALL-PROBE-1")
        time.sleep(0.1)
        s.close()

        time.sleep(1.0)
        raw_req("POST", f"/api/v2/test-runs/{run_id}/stop", {}, headers=auth)
        time.sleep(0.5)

        st, _, body = raw_req("GET", f"/api/v2/test-runs/{run_id}/coverage", headers=auth)
        cov = json.loads(body)
        pmap = {p["protocol"]: p["status"] for p in cov["protocols"]}
        check("5-State: http=hit", pmap.get("http") == "hit", pmap.get("http"))
        check("5-State: mysql=banner_only", pmap.get("mysql") == "banner_only", pmap.get("mysql"))
        check("5-State: ldap=connect_only", pmap.get("ldap") == "connect_only", pmap.get("ldap"))
        check("5-State: tftp=hit", pmap.get("tftp") == "hit", pmap.get("tftp"))
        check("5-State: netbios=hit", pmap.get("netbios") == "hit", pmap.get("netbios"))

        st, _, body = raw_req("GET", "/api/v2/sessions?protocol=http&limit=5", headers=auth)
        items = json.loads(body).get("items", [])
        check("Sessions recorded", st == 200 and len(items) > 0)
        sid = items[0]["id"]
        st, _, pcap = raw_req("GET", f"/api/v2/sessions/{sid}/pcap", headers=auth)
        check("PCAP export valid magic", st == 200 and len(pcap) > 40 and pcap[:4] == b"\xd4\xc3\xb2\xa1", f"len={len(pcap)}")

        st, _, body = raw_req("GET", "/api/v2/probes?limit=10", headers=auth)
        check("Probe library populated", st == 200 and len(json.loads(body).get("items", [])) > 0)

        print(f"\nCROSS_PLATFORM_E2E_SUMMARY: passed={passed} failed={failed}")
        if failed > 0:
            sys.exit(1)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        log_f.close()
        if failed > 0:
            print("=== PROTOSIM LOG ===")
            with open(log_path, "r", encoding="utf-8", errors="replace") as f:
                print(f.read())


if __name__ == "__main__":
    main()
