#!/usr/bin/env python3
"""Offline verification for the admin page (ADMIN.md VER-1/VER-3/VER-5).
No root, no live dnsmasq, no Telegram, no real network: fixtures in a temp
dir, the reload hook is a counting wrapper, and Telegram sends are stubbed.
The admin HTTP server runs in-process on an ephemeral loopback port.

Run:  python3 tests/test_admin.py
"""

import importlib.util
import hmac as hmac_mod
import json
import os
import shutil
import socket
import sys
import tempfile
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
MODULE = os.path.join(HERE, "..", "scripts", "doorbell-dhcp.py")
sys.path.insert(0, os.path.join(HERE, "..", "scripts"))
import admin_web as aw          # stdlib-only at import — the HTTP stack is lazy

FIXTURE_CONF = """\
port=53
interface=wlxlab0
dhcp-range=192.168.213.0,static
dhcp-authoritative
dhcp-leasefile={leasefile}
dhcp-range=set:pending,192.168.214.100,192.168.214.149,2m
dhcp-option=option:router,192.168.213.1

dhcp-host=98:3b:8f:aa:7d:37,192.168.213.20,ar-lmsi,24h
dhcp-host=1a:91:6c:4c:02:89,ignore
"""

FIXTURE_LEASES = """\
1700000000 98:3b:8f:aa:7d:37 192.168.213.20 ar-lmsi *
1700000002 aa:bb:cc:dd:ee:ff 192.168.214.100 labphone *
"""

NEW_MAC = "aa:bb:cc:dd:ee:ff"
NEXT_IP = "192.168.213.21"
TOKEN = "test-token-4242"


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def boot(env_dir):
    """Write fixtures, set env (incl. the admin knobs), import fresh."""
    counter = os.path.join(env_dir, "pokes")
    wrapper = os.path.join(env_dir, "poke.sh")
    with open(wrapper, "w") as f:
        f.write(f"#!/bin/sh\necho x >> {counter}\nexit 0\n")
    os.chmod(wrapper, 0o755)
    conf = os.path.join(env_dir, "gatekeeper.conf")
    with open(conf, "w") as f:
        f.write(FIXTURE_CONF.format(leasefile=os.path.join(env_dir, "dnsmasq.leases")))
    with open(os.path.join(env_dir, "dnsmasq.leases"), "w") as f:
        f.write(FIXTURE_LEASES)
    with open(os.path.join(env_dir, "dnsmasq.log"), "w") as f:
        f.write("lab dnsmasq log line\n")
    port = free_port()
    os.environ.update(
        CONFIG=conf,
        LEASEFILE=os.path.join(env_dir, "dnsmasq.leases"),
        DB=os.path.join(env_dir, "test.db"),
        TEMPLATE=os.path.join(env_dir, "gatekeeper.template"),
        LOG_FILE=os.path.join(env_dir, "dnsmasq.log"),
        DNMSQ_RELOAD=f"/bin/sh {wrapper}",
        DNMSQ_RESTART=f"/bin/sh {wrapper}",
        ADMIN_BIND="127.0.0.1,127.0.0.2",   # multi-bind: one listener per address
        ADMIN_PORT=str(port),
        ADMIN_TOKEN=TOKEN,
        ADMIN_HOSTS="apis.adolfrey.com,apps.adolfrey.com",
    )
    spec = importlib.util.spec_from_file_location("doorbell", MODULE)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod, port


def poke_count(env_dir):
    try:
        with open(os.path.join(env_dir, "pokes")) as f:
            return len(f.read().split())
    except OSError:
        return 0


def http(port, method, path, body=None, headers=None, host="127.0.0.1"):
    """Returns (status, headers, body-text). Follows no redirects.
    Headers are lower-cased: uvicorn emits 'set-cookie', the stdlib
    handler used to emit 'Set-Cookie' — tests must not care."""
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(f"http://{host}:{port}{path}",
                                 data=data, method=method,
                                 headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, {k.lower(): v for k, v in r.headers.items()}, \
                r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in e.headers.items()}, \
            e.read().decode()


def wait_port(port, timeout=3.0):
    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                return True
        except OSError:
            time.sleep(0.05)
    return False


def wait_admin(port, timeout=20.0):
    """The socket binds before uvicorn finishes building the app (fastapi
    import takes a beat) — poll until a request actually gets answered."""
    end = time.time() + timeout
    while time.time() < end:
        try:
            st, _, _ = http(port, "GET", "/api/summary")
            return st == 401
        except (urllib.error.URLError, OSError):
            time.sleep(0.1)
    return False


def main():
    tmp = tempfile.mkdtemp(prefix="gatekeeper-admin-")
    ok = True

    def check(name, cond, extra=""):
        nonlocal ok
        print(f"  {'✅' if cond else '❌'} {name}{(' — ' + extra) if extra else ''}")
        ok = ok and cond

    try:
        mod, port = boot(tmp)
        mod.db_init()
        mod.migrate_bindings()
        mod.ensure_template()
        mod.render_and_apply()
        conf = os.environ["CONFIG"]

        # Telegram is stubbed: offline, and card ids become observable.
        sent = []
        mod.send_message = lambda text, buttons=None: (
            sent.append((text, buttons)) or 4242)
        mod.tg = lambda method, **params: {"result": {"message_id": 777}}

        # ---- pure helpers (VER-1) ------------------------------------------
        check("SEC-6 bind self-check refuses 0.0.0.0",
              not aw.admin_bind_ok("0.0.0.0"))
        check("SEC-6 bind self-check refuses the portal IP",
              not aw.admin_bind_ok("192.168.214.2"))
        check("SEC-6 bind self-check accepts loopback / 213.x",
              aw.admin_bind_ok("127.0.0.1") and aw.admin_bind_ok("192.168.213.2"))
        check("VER-5 claim relay pinned loopback-only",
              mod.CLAIM_BIND == "127.0.0.1")
        check("MAC regex accepts colon form only",
              bool(aw._MAC_RE.fullmatch("aa:bb:cc:dd:ee:ff"))
              and not aw._MAC_RE.fullmatch("aabbcc.ddee.ff")
              and not aw._MAC_RE.fullmatch("AA:BB:CC:dd:ee:ff"))

        # ---- session cookie (SEC-7) ----------------------------------------
        s = aw.make_session(mod)
        check("session verifies", aw.check_session(mod, s))
        tampered = s[:-1] + ("0" if s[-1] != "0" else "1")
        check("tampered session rejected", not aw.check_session(mod, tampered))
        exp = str(int(time.time()) - 10)
        check("expired session rejected",
              not aw.check_session(mod, f"{exp}.{aw._sign(mod, exp)}"))
        wrong = hmac_mod.new(b"other", exp.encode(), "sha256").hexdigest()
        check("signature from another token rejected",
              not aw.check_session(mod, f"{exp}.{wrong}"))

        # ---- server up ------------------------------------------------------
        import threading
        threading.Thread(target=mod.admin_server, daemon=True).start()
        check("admin server listens", wait_port(port))
        check("admin server serving requests", wait_admin(port))

        # ---- oauth off (no ADMIN_BFF_SECRET in this boot) -------------------
        st, _, body = http(port, "GET", "/api/authmode")
        j = json.loads(body)
        check("authmode advertises token-only when the BFF is off",
              st == 200 and j["ok"] and j["oauth"] is False)
        st, _, _ = http(port, "GET", "/auth/login")
        check("SDK routes absent when the BFF is off", st == 404)

        # ---- multi-bind: one listener per ADMIN_BINDS entry -------------------
        check("bind list parsed from comma-separated env",
              mod.ADMIN_BINDS == ["127.0.0.1", "127.0.0.2"])
        st, _, _ = http(port, "GET", "/api/summary", host="127.0.0.2")
        check("second bind also listens", st == 401)
        st, h2, _ = http(port, "POST", "/api/login", {"token": TOKEN},
                         host="127.0.0.2")
        cookie2 = (h2.get("set-cookie") or "").split(";")[0]
        origin2 = {"Cookie": cookie2, "Content-Type": "application/json",
                   "Origin": f"http://127.0.0.2:{port}"}
        st, _, _ = http(port, "POST", "/api/action",
                         {"action": "skip", "mac": "11:22:33:44:55:66"},
                         origin2, host="127.0.0.2")
        check("Origin matching any bind address is accepted", st == 200)

        auth = {"Authorization": f"Bearer {TOKEN}",
                "Content-Type": "application/json"}

        # ---- page + auth (SEC-1) -------------------------------------------
        st, _, body = http(port, "GET", "/")
        check("static page served without auth (no secrets in it)",
              st == 200 and "Gatekeeper admin" in body)
        st, _, body = http(port, "GET", "/api/summary")
        check("API without auth -> 401", st == 401)
        st, _, body = http(port, "GET", "/api/summary",
                           headers={"Authorization": "Bearer wrong"})
        check("wrong bearer -> 401", st == 401)
        st, _, body = http(port, "GET", "/api/summary", headers=auth)
        j = json.loads(body)
        check("bearer auth -> summary 200",
              st == 200 and j["ok"] and "free_ips" in j and "counts" in j)

        # ---- views before any decision --------------------------------------
        mod.db_event("knock", NEW_MAC, "labphone")   # what the sniffer records
        st, _, body = http(port, "GET", "/api/pending", headers=auth)
        j = json.loads(body)
        check("waiting room shows the pending lease",
              any(p["mac"] == NEW_MAC and p["ip"] == "192.168.214.100"
                  for p in j["pending"]))
        st, _, body = http(port, "GET", "/api/devices", headers=auth)
        j = json.loads(body)
        check("roster lists pending device", any(
            d["mac"] == NEW_MAC and d["kind"] == "pending" for d in j["devices"]))

        # ---- input validation (SEC-3) ---------------------------------------
        st, _, body = http(port, "POST", "/api/action",
                           {"action": "approve", "mac": "zz:zz"}, auth)
        check("bad mac -> 400", st == 400)
        st, _, body = http(port, "POST", "/api/action",
                           {"action": "allow", "mac": NEW_MAC, "hours": 3}, auth)
        check("bad hours (not 4/12/24) -> 400", st == 400)
        st, _, body = http(port, "POST", "/api/action",
                           {"action": "rm -rf", "mac": NEW_MAC}, auth)
        check("unknown action -> 400", st == 400)

        # ---- login + cookie + Origin (SEC-2/SEC-7) ---------------------------
        st, hdrs, _ = http(port, "POST", "/api/login", {"token": TOKEN})
        cookie = (hdrs.get("set-cookie") or "").split(";")[0]
        check("login with right token sets session cookie",
              st == 200 and cookie.startswith("gkadmin="))
        cookie_hdr = {"Cookie": cookie, "Content-Type": "application/json"}
        st, _, _ = http(port, "GET", "/api/summary", headers=cookie_hdr)
        check("cookie auth works for GET", st == 200)
        st, _, _ = http(port, "POST", "/api/action",
                         {"action": "approve", "mac": NEW_MAC}, cookie_hdr)
        check("cookie POST without Origin -> 403 (CSRF guard)", st == 403)
        origin = {"Cookie": cookie, "Content-Type": "application/json",
                  "Origin": f"http://127.0.0.1:{port}"}
        st, _, _ = http(port, "POST", "/api/action",
                         {"action": "approve", "mac": NEW_MAC}, origin)
        check("cookie POST with matching Origin -> 200", st == 200)

        # ---- approve via web: full effect chain (ACT-1, ACT-9) --------------
        with open(conf) as f:
            conf_text = f.read()
        check("approve rendered its dhcp-host line",
              f"dhcp-host={NEW_MAC},{NEXT_IP},labphone,24h" in conf_text)
        evs = aw._admin_events(mod, kind="approve", mac=NEW_MAC)
        check("approve event recorded with via-web provenance",
              evs and "via web" in evs[0]["detail"] and NEXT_IP in evs[0]["detail"],
              evs[0]["detail"] if evs else "no event")
        check("dnsmasq poked (reload + lease purge)",
              poke_count(tmp) >= 2, f"pokes: {poke_count(tmp)}")
        st, _, body = http(port, "GET", "/api/pending", headers=auth)
        check("waiting-room lease purged after approve",
              not any(p["mac"] == NEW_MAC for p in json.loads(body)["pending"]))
        check("Telegram card still sent (phone stays the pager)",
              any("approved" in t for t, _ in sent))

        # ---- stale guard (ACT-12) -------------------------------------------
        st, _, body = http(port, "POST", "/api/action",
                           {"action": "approve", "mac": NEW_MAC}, origin)
        j = json.loads(body)
        check("web re-approve is a no-op error",
              st == 409 and j["error"] == "already-approved")
        mod.CURRENT_CBQ = {}   # stale Telegram card, tapped after the web decision
        mod.handle_callback(f"approve:{NEW_MAC}")
        check("stale Telegram ✅ is a harmless no-op",
              any("already approved" in t for t, _ in sent))
        with open(conf) as f:
            check("no second IP was allocated",
                  conf_text.count(f"dhcp-host={NEW_MAC},") == 1)

        # ---- rename via web (ACT-7) ------------------------------------------
        st, _, body = http(port, "POST", "/api/note",
                           {"mac": NEW_MAC, "name": "Bob"}, origin)
        check("rename via web -> ok", st == 200 and json.loads(body)["ok"])
        with open(conf) as f:
            check("note marker rendered", "# doorbell note: Bob" in f.read())
        evs = aw._admin_events(mod, kind="note", mac=NEW_MAC)
        check("note event carries via-web provenance",
              evs and evs[0]["detail"] == "Bob via web")

        # ---- roster reflects state (V-1) --------------------------------------
        st, _, body = http(port, "GET", "/api/devices", headers=auth)
        row = next(d for d in json.loads(body)["devices"] if d["mac"] == NEW_MAC)
        check("roster row: approved, reserved IP, name",
              row["kind"] == "approve" and row["ip"] == NEXT_IP
              and row["name"] == "Bob")

        # ---- undo + guest pass + deny (ACT-3/ACT-4/ACT-2) ---------------------
        st, _, _ = http(port, "POST", "/api/action",
                         {"action": "undo", "mac": NEW_MAC}, auth)
        check("undo -> ok", st == 200)
        with open(conf) as f:
            check("undo removed the device line",
                  f"dhcp-host={NEW_MAC}," not in f.read())
        st, _, body = http(port, "POST", "/api/action",
                           {"action": "allow", "mac": NEW_MAC, "hours": 4}, auth)
        j = json.loads(body)
        check("guest pass 4h -> ok with until",
              st == 200 and "until" in j)
        check("temp_queue armed (expiry sweep will revoke)",
              NEW_MAC in mod.temp_queue)
        check("guest-pass countdown visible in roster",
              any(d["mac"] == NEW_MAC and d["kind"] == "temp"
                  and d["expires_in"] and d["expires_in"] > 0
                  for d in json.loads(http(port, "GET", "/api/devices",
                                           headers=auth)[2])["devices"]))
        mod.temp_queue.clear()
        mod.db_restore()   # restart simulation: parses "ip until ts via web"
        check("guest pass survives restart (provenance suffix tolerated)",
              NEW_MAC in mod.temp_queue)
        st, _, _ = http(port, "POST", "/api/action",
                        {"action": "deny", "mac": NEW_MAC}, auth)
        with open(conf) as f:
            check("deny rendered ignore line",
                  f"dhcp-host={NEW_MAC},ignore" in f.read())
        evs = aw._admin_events(mod, kind="deny", mac=NEW_MAC)
        check("deny event via web", evs and evs[0]["detail"] == "via web")

        # ---- events + logs (L-1..L-4) -----------------------------------------
        st, _, body = http(port, "GET", "/api/events?kind=deny&mac=" + NEW_MAC,
                           headers=auth)
        j = json.loads(body)
        check("events filter kind+mac", len(j["events"]) == 1
              and j["events"][0]["mac"] == NEW_MAC)
        st, _, body = http(port, "GET", "/api/logs?src=doorbell&lines=50",
                           headers=auth)
        check("doorbell log tail served",
              any("approved" in l or "denied" in l for l in json.loads(body)["lines"]))
        st, _, body = http(port, "GET", "/api/logs?src=dnsmasq", headers=auth)
        check("dnsmasq log tail served",
              "lab dnsmasq log line" in json.loads(body)["lines"])

        # ---- summary (V-5) ------------------------------------------------------
        st, _, body = http(port, "GET", "/api/summary", headers=auth)
        j = json.loads(body)
        check("summary counts + free pool",
              j["counts"].get("approve", 0) >= 1 and j["counts"].get("deny", 0) >= 2
              and j["free_ips"] == 79,
              f"counts={j['counts']} free={j['free_ips']}")

        # ---- skip + logout + rate limit (SEC-2) ---------------------------------
        st, _, _ = http(port, "POST", "/api/action",
                        {"action": "skip", "mac": NEW_MAC}, auth)
        check("skip via web ok (cooldown armed)",
              st == 200 and NEW_MAC in mod.cooldown)
        st, hdrs, _ = http(port, "POST", "/api/logout", {}, origin)
        check("logout expires the cookie",
              st == 200 and "Max-Age=0" in (hdrs.get("set-cookie") or ""))
        for _ in range(5):
            st, _, _ = http(port, "POST", "/api/login", {"token": "nope"})
        st, _, body = http(port, "POST", "/api/login", {"token": "nope"})
        check("6th failed login inside a minute rate-limited -> 403 generic",
              st == 403 and json.loads(body)["error"] == "forbidden")

        # ---- BFF mode (offline): the app builds against a fake authority --
        # The full login flow needs the real auth server (manual VER step,
        # ADMIN.md); offline we prove the stack builds, the SDK routes
        # appear, and the token legs still gate everything with OAuth on.
        try:
            import asyncio

            import httpx
        except ImportError:
            httpx = None
        if httpx is None:
            print("  ⏭ httpx unavailable — skipping the BFF-mode checks")
        else:
            os.environ.update(
                ADMIN_BFF_SECRET="unit-test-secret-" + "x" * 48,
                ADMIN_OAUTH_AUTHORITY="http://127.0.0.1:9/api")
            spec2 = importlib.util.spec_from_file_location(
                "doorbell_oauth", MODULE)
            mod2 = importlib.util.module_from_spec(spec2)
            spec2.loader.exec_module(mod2)
            app = aw.build_admin_app(mod2)
            check("BFF app builds against a fake authority (no network)",
                  app is not None)

            async def _drive():
                # ASGI transport, no lifespan -> no warmup, no network
                transport = httpx.ASGITransport(app=app)
                async with httpx.AsyncClient(transport=transport,
                                             base_url="http://testserver") \
                        as c:
                    return (
                        await c.get("/api/authmode"),
                        await c.get("/api/summary"),
                        await c.get("/api/summary", headers={
                            "Authorization": f"Bearer {TOKEN}"}),
                        await c.get("/auth/login", follow_redirects=False),
                    )

            r_mode, r_401, r_bearer, r_login = asyncio.run(_drive())
            check("authmode advertises oauth when the BFF is on",
                  r_mode.json().get("oauth") is True)
            check("API still gated with the BFF on: no creds -> 401",
                  r_401.status_code == 401 and r_401.json()["ok"] is False)
            check("ADMIN_TOKEN bearer still wins with the BFF on",
                  r_bearer.status_code == 200 and r_bearer.json()["ok"])
            check("SDK owns /auth/login when the BFF is on "
                  "(fake authority -> 5xx, not 404)",
                  r_login.status_code != 404)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print("\n" + ("ALL CHECKS PASSED" if ok else "FAILURES — see ❌ above"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
