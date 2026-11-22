#!/usr/bin/env python3
"""Network Gatekeeper — admin web layer (ADMIN.md).

Split from doorbell-dhcp.py on purpose: the gate core stays lean and
stdlib-only, and everything the admin page needs lives here. The
doorbell imports THIS module (never the other way around) and hands
itself over as `g` — so web actions still run the gate's own decision
cores (INV-1: single writer) and the page keeps running inside the
doorbell process (INV-2), exactly as before the split.

Layout (ADMIN.md is the design record; invariants cited inline):
  - session cookie + per-IP rate limiting        (SEC-2 / SEC-7)
  - read views over the shared SQLite/leasefile   (V-1 / V-2 / L-1..L-4)
  - the FastAPI app + uvicorn serve loop          (one per ADMIN_BINDS)
  - the ar-auth OAuth BFF                         (SEC-9): login/callback/
    logout, app-local session cookie, silent renewal, signed double-
    submit CSRF — gated on the api://network-gatekeeper/admin scope.

The HTTP stack (fastapi / uvicorn / ar_auth) is imported lazily: a box
without those wheels keeps a fully working gate, just no admin page
(INV-4 — the admin is never load-bearing). Env knobs (ADMIN_*, parsed
once by the gate module) are read through `g`.
"""

import hashlib
import hmac
import json
import os
import re
import socket
import threading
import time
import urllib.parse
from datetime import datetime

# ------------------------------------------------------------------ constants

_MAC_RE = re.compile(r"^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$")
_ADMIN_ACTIONS = {"approve", "deny", "allow", "undo", "skip"}
_ADMIN_HOURS = {4, 12, 24}          # parity with allow4/allow12/allow24

# SEC-2 state: per-IP failed-auth timestamps (monotonic). Module-local on
# purpose — the limiter belongs to the web layer, not the gate core.
admin_fails = {}
_admin_fail_lock = threading.Lock()


def admin_bind_ok(bind: str) -> bool:
    """SEC-6 self-check: never all-interfaces, never the waiting-room
    portal IP. Refusing to start (gate unaffected) is the safe failure."""
    return bind not in ("0.0.0.0", "192.168.214.2")


# ------------------------------------------------- session cookie + SEC-2 ----

def _sign(g, payload: str) -> str:
    return hmac.new(g.ADMIN_TOKEN.encode(), payload.encode(),
                    hashlib.sha256).hexdigest()


def make_session(g) -> str:
    """Cookie value `exp.sig` — HMAC keyed on ADMIN_TOKEN, so rotating the
    token invalidates every outstanding session (documented rotation)."""
    exp = str(int(time.time()) + g.ADMIN_SESSION_HOURS * 3600)
    return f"{exp}.{_sign(g, exp)}"


def check_session(g, value: str) -> bool:
    if not g.ADMIN_TOKEN or not value:
        return False
    exp, _, sig = value.partition(".")
    if not exp.isdigit() or not sig:
        return False
    if int(exp) < time.time():
        return False
    try:
        return hmac.compare_digest(sig.encode(), _sign(g, exp).encode())
    except (TypeError, UnicodeEncodeError):
        return False        # hostile cookie payload — not our problem


def _fail_rate_ok(ip: str) -> bool:
    """SEC-2: fewer than 5 failed logins in the trailing minute."""
    now = time.monotonic()
    with _admin_fail_lock:
        recent = [t for t in admin_fails.get(ip, []) if now - t < 60]
        admin_fails[ip] = recent
        return len(recent) < 5


def _fail_record(ip: str):
    with _admin_fail_lock:
        admin_fails.setdefault(ip, []).append(time.monotonic())


# ------------------------------------------------------------------ read views

def _lease_map(g):
    """mac -> (expires_epoch, ip, hostname) from the dnsmasq leasefile."""
    out = {}
    try:
        with open(g.LEASEFILE) as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 4:
                    out[parts[1].lower()] = (int(parts[0]), parts[2], parts[3])
    except (OSError, ValueError):
        pass
    return out


def _admin_roster(g, status: str = None, q: str = None):
    """V-1: every known device (bindings ∪ devices) with live-lease expiry.
    Reads only — the writer stays the decision cores."""
    now = time.time()
    try:
        with g._db() as con:
            devices = {r[0]: r for r in con.execute(
                "SELECT mac,first_seen,last_seen,last_name,status,note FROM devices")}
            binds = {r[0]: r for r in con.execute(
                "SELECT mac,kind,ip,lease_spec,hostname,since,expires,raw FROM bindings")}
    except Exception as e:      # sqlite3.Error, but the gate module owns it
        g.log("admin roster read failed:", e)
        return []
    leases = _lease_map(g)
    rows = []
    for mac in set(devices) | set(binds):
        d = devices.get(mac)
        b = binds.get(mac)
        kind = b[1] if b else None
        if status and (kind or "pending") != status:
            continue
        note = (d[5] if d else "") or ""
        hostname = (b[4] if b else "") or ""
        claim = g.visitor_names.get(mac, "")
        if q and q not in " ".join((mac, note, hostname, claim,
                                    (d[3] if d else "") or "")).lower():
            continue
        exp_in = None
        if b and b[6]:
            try:      # temp-pass countdown (V-1 expiry)
                exp_in = (datetime.fromisoformat(b[6]) - datetime.now()).total_seconds()
            except ValueError:
                pass
        lease = leases.get(mac)
        rows.append({
            "mac": mac, "name": note or hostname, "hostname": hostname,
            "claim": claim, "kind": kind or "pending",
            "ip": b[2] if b else None,
            "lease_spec": b[3] if b else None,
            "since": b[5] if b else None,
            "expires": b[6] if b else None,
            "expires_in": exp_in,
            "raw": b[7] if b else None,
            "first_seen": d[1] if d else None,
            "last_seen": d[2] if d else None,
            "lease_ip": lease[1] if lease else None,
            "lease_left": int(lease[0] - now) if lease else None,
        })
    order = {"approve": 0, "temp": 1, "deny": 2, "raw": 3, "pending": 4}
    rows.sort(key=lambda r: (order.get(r["kind"], 9), r["mac"]))
    return rows


def _admin_pending(g):
    """V-2: current waiting room = live 214.x leases + claimed names."""
    now = time.time()
    rows = []
    for mac, (exp, ip, host) in _lease_map(g).items():
        if not ip.startswith("192.168.214."):
            continue
        rows.append({"mac": mac, "ip": ip,
                     "hostname": "" if host == "*" else host,
                     "name": g.notes.get(mac) or g.visitor_names.get(mac) or "",
                     "expires_in": max(0, int(exp - now))})
    rows.sort(key=lambda r: r["ip"])
    return rows


def _admin_events(g, kind: str = None, mac: str = None,
                  limit: int = 50, offset: int = 0):
    """L-1: audit-trail view, newest first, parameterized filters."""
    sql = "SELECT id,ts,mac,hostname,kind,detail FROM events"
    cond, params = [], []
    if kind:
        cond.append("kind=?")
        params.append(kind)
    if mac:
        cond.append("mac=?")
        params.append(mac.lower())
    if cond:
        sql += " WHERE " + " AND ".join(cond)
    sql += " ORDER BY id DESC LIMIT ? OFFSET ?"
    params += [limit, offset]
    try:
        with g._db() as con:
            return [dict(zip(("id", "ts", "mac", "hostname", "kind", "detail"), r))
                    for r in con.execute(sql, params)]
    except Exception as e:
        g.log("admin events read failed:", e)
        return []


def _tail_lines(path: str, n: int):
    """L-2/L-4: last n lines, bounded read (seek near EOF, never whole-file)."""
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(max(0, size - n * 512))
            return f.read().decode("utf-8", "replace").splitlines()[-n:]
    except OSError:
        return []


def _dnsmasq_alive() -> bool:
    """V-5 liveness: something already holds UDP 67 → dnsmasq is up."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.bind(("", 67))
        return False
    except OSError:
        return True
    finally:
        s.close()


def _admin_summary(g):
    counts = {}
    try:
        with g._db() as con:
            for kind, n in con.execute(
                    "SELECT kind, COUNT(*) FROM bindings GROUP BY kind"):
                counts[kind] = n
    except Exception as e:
        g.log("admin summary read failed:", e)
    free = sum(1 for o in range(g.IP_MIN, g.IP_MAX + 1)
               if o not in g.used_ips())
    return {"counts": counts,
            "waiting": len(_admin_pending(g)),
            "free_ips": free,
            "dnsmasq_alive": _dnsmasq_alive(),
            "doorbell_alive": True,   # the doorbell is serving this response
            "now": datetime.now().isoformat(timespec="seconds")}


def _load_admin_page(g) -> bytes:
    try:
        with open(g.ADMIN_PAGE, "rb") as f:
            return f.read()
    except OSError as e:
        return (f"<!doctype html><title>gatekeeper</title><body>"
                f"<p>admin page missing: {g.ADMIN_PAGE} ({e})</p>").encode()


# ------------------------------------------------------------ request plumbing

async def _admin_json_body(request):
    """SEC-3 input gate, unchanged from the stdlib handler: a JSON object
    body, at most 8 KiB, else None (the caller decides the 400/401)."""
    try:
        n = int(request.headers.get("content-length", "0") or "0")
        if not 0 < n <= 8192:
            return None
        v = json.loads((await request.body()).decode("utf-8", "replace"))
        return v if isinstance(v, dict) else None
    except (ValueError, OSError):
        return None


def _admin_origin_ok(g, host: str, origin: str) -> bool:
    """SEC-7, unchanged semantics: browser (cookie) POSTs must originate
    from a host we actually serve — an ADMIN_HOSTS tunnel alias or any of
    our own bind addresses. Bearer POSTs skip this: the un-forgeable
    header is their guard."""
    host = (host or "").strip().lower()
    if not origin or not host:
        return False
    if urllib.parse.urlsplit(origin).netloc.strip().lower() != host:
        return False
    allowed = set(g.ADMIN_HOSTS) | {f"{b}:{g.ADMIN_PORT}" for b in g.ADMIN_BINDS}
    return host in allowed


# ------------------------------------------------------------- OAuth BFF (SEC-9)

def _make_oauth_bff(g):
    """The ar-auth BFF pieces. Lazy import: the gate core stays
    stdlib-only, and boxes without the wheel keep the token legs
    (INV-4 — the admin is never load-bearing for the gate)."""
    from ar_auth.bff import ArAuthBff, BffOptions, add_ar_auth_bff

    class ScopeGatedBff(ArAuthBff):
        """The SDK's on_authenticated hook only sees id_token claims — and
        ar-auth puts granted scopes on the ACCESS token (the code grant
        even narrows silently, backend TokenService), so requesting a
        scope proves nothing by itself. This subclass gates on the one
        place the grant is observable: the access token of the login
        exchange. It wraps — never replaces — the AuthLib code-exchange
        call; every security-critical step of the base BFF (state, PKCE,
        correlation, cookie issuance, CSRF, renewal) still runs untouched.
        Renewal caveat: the refreshed id_token carries no scope either,
        so a granted session keeps silently renewing for the refresh
        chain's life (30 d) even after a server-side revocation — the
        same trade-off as every ar-auth BFF consumer (ADMIN.md SEC-9)."""

        _OK_KEY = "gk_admin_scope_ok"

        def __init__(self, options, required_scope):
            super().__init__(options)
            self.required_scope = required_scope
            inner = self._client.authorize_access_token

            async def gated_exchange(request):
                token = await inner(request)
                request.scope[self._OK_KEY] = await self._scope_granted(token)
                return token

            self._client.authorize_access_token = gated_exchange

        async def _scope_granted(self, token) -> bool:
            """Signature-verified scope check on the exchange's access
            token. Unverifiable ⇒ no session (fail closed)."""
            access = (token or {}).get("access_token") \
                if isinstance(token, dict) else None
            if not access:
                return False
            try:
                from joserfc import jwt as jose_jwt
                from joserfc.jwk import KeySet as JoseKeySet
                from joserfc.jws import JWSRegistry as JoseJWSRegistry

                metadata = await self._client.load_server_metadata()
                jwks = await self._client.fetch_jwk_set()
                claims = jose_jwt.decode(
                    access,
                    key=JoseKeySet.import_key_set(jwks),
                    registry=JoseJWSRegistry(algorithms=["RS256"]),
                ).claims
                if claims.get("iss") != metadata.get("issuer"):
                    return False
                if claims.get("client_id") != self.options.client_id:
                    return False
                return self.required_scope in (claims.get("scope") or "").split()
            except Exception:
                return False

        async def on_authenticated(self, context):
            await super().on_authenticated(context)   # fire BffEvents delegate
            if not context.request.scope.get(self._OK_KEY):
                g.log(f"admin oauth login rejected (sub="
                      f"{context.claims.get('sub')!r}) — scope "
                      f"{self.required_scope!r} not granted")
                context.reject(f"missing scope {self.required_scope}")

    options = BffOptions(
        client_id=g.ADMIN_OAUTH_CLIENT,
        secret=g.ADMIN_BFF_SECRET,
        authority=g.ADMIN_OAUTH_AUTHORITY,
        # The SDK derives redirect_uri (base + /auth/callback) and the
        # cookie Path from this, VERBATIM — it must equal the
        # auth-server registration minus /auth/callback, host AND path:
        # the /gatekeeper prefix is real (Caddy handle_path strips it
        # before us). Live: redirect
        # https://apps.adolfrey.com/gatekeeper/auth/callback, cookie
        # Path=/gatekeeper/
        public_base_url=g.ADMIN_OAUTH_BASE,
        scope=f"openid profile email {g.ADMIN_OAUTH_SCOPE}",
    )
    return options, ScopeGatedBff(options, g.ADMIN_OAUTH_SCOPE), add_ar_auth_bff


# ------------------------------------------------------------------ the app

def build_admin_app(g):
    """The admin surface as one FastAPI app (INV-2: in-process, sharing
    the gate's decision cores; INV-1: writes still go through them). One
    app per bind — each uvicorn server owns its event loop, so the BFF's
    renewal-chain locks must never cross loops; the shared env secret
    keeps cookies valid on every bind. Returns None when the stack is
    unavailable (admin off, gate unaffected — INV-4)."""
    try:
        from contextlib import asynccontextmanager

        from fastapi import Depends, FastAPI, Request
        from fastapi.responses import HTMLResponse, JSONResponse
        # The envelope must catch BOTH exception lineages: fastapi's
        # HTTPException (our raises) and starlette's base class — the
        # ar-auth SDK raises the latter (bff.py imports it from
        # starlette.exceptions), and a handler keyed on fastapi's subclass
        # is invisible to it (the MRO walk starts at the raised class).
        from starlette.exceptions import HTTPException
    except ImportError as e:
        g.log(f"admin disabled — the admin stack (fastapi/uvicorn) is not "
              f"installed: {e}")
        return None

    app = FastAPI(openapi_url=None, docs_url=None, redoc_url=None)

    bff = None
    if g.ADMIN_BFF_SECRET:
        try:
            options, bff, add_ar_auth_bff = _make_oauth_bff(g)
            add_ar_auth_bff(app, options, bff=bff)
            # The SDK chains a fail-fast warmup into the lifespan. On a
            # gate box the page must survive an unreachable auth server:
            # logins fail until it resolves; the gate is never affected.
            chained = app.router.lifespan_context

            @asynccontextmanager
            async def _tolerant_warmup(app):
                try:
                    async with chained(app):
                        yield
                except Exception as e:
                    g.log(f"admin oauth warmup failed (auth server "
                          f"{g.ADMIN_OAUTH_AUTHORITY} unreachable?): {e} "
                          f"— logins will fail until it resolves")
                    yield

            app.router.lifespan_context = _tolerant_warmup

            # SDK ≥ 1.3.2 required (the Dockerfile pins the exact wheel):
            # restart redirects target the PUBLIC login path
            # (bff.py::_restart_redirect), callback failures log their
            # reason (docker logs: "ar-auth BFF: callback failed…"),
            # and post-login landings without a returnUrl resolve to
            # the app's public base path instead of the bare site root.
            # 1.3.0's prefix-blind restarts sent failed logins to a dead
            # root URL (observed 2026-11-22: callback answered
            # 302 Location /auth/login past the handle_path route); the
            # workaround middleware we carried for it was removed here.
        except ImportError as e:
            g.log(f"admin oauth DISABLED — ar-auth SDK not installed ({e}); "
                  "the ADMIN_TOKEN legs stay active")
            bff = None

    ADMIN_ERRORS = {
        "pool-full": (f"reserved pool {g.IP_PREFIX}{g.IP_MIN}–{g.IP_MAX} "
                      "is full — no free IP"),
        "db": "cannot record the decision in the DB — see logs",
        "conf-write": "cannot write the rendered config — see logs",
        "already-approved": "device is already approved — no change",
        "already-denied": "device is already denied — no change",
        "already-temp": "device already has an active guest pass — no change",
        "reload": "dnsmasq reload failed — the previous decision is still active",
        "empty": "empty name — nothing saved",
    }

    # ---- error envelopes: the page reads {"ok": false, "error": …} -----
    @app.exception_handler(HTTPException)
    async def _http_exc(request, exc):
        return JSONResponse(status_code=exc.status_code,
                            content={"ok": False, "error": exc.detail},
                            headers=getattr(exc, "headers", None))

    @app.exception_handler(Exception)
    async def _any_exc(request, exc):   # INV-4: contained, logged, generic
        g.log("admin request failed:", exc)
        return JSONResponse(status_code=500,
                            content={"ok": False, "error": "internal"})

    # ---- SEC-1 auth: bearer (constant-time) → signed cookie → oauth ----
    async def _admin_auth(request: Request) -> str:
        auth = request.headers.get("authorization", "")
        if g.ADMIN_TOKEN and auth.startswith("Bearer ") \
                and hmac.compare_digest(auth[7:].encode(),
                                        g.ADMIN_TOKEN.encode()):
            return "bearer"
        if check_session(g, request.cookies.get("gkadmin", "")):
            if request.method not in ("GET", "HEAD", "OPTIONS", "TRACE") \
                    and not _admin_origin_ok(g, request.headers.get("host", ""),
                                              request.headers.get("origin", "")):
                g.log(f"admin {request.method} rejected: bad Origin from "
                      f"{request.client.host if request.client else '?'}")
                raise HTTPException(status_code=403, detail="forbidden")
            return "session"
        if bff is not None:
            await bff.auth(request)     # 401 w/ WWW-Authenticate: Bearer
            return "oauth"
        raise HTTPException(status_code=401, detail="unauthorized")

    _A = Depends(_admin_auth)

    # ---- GET routes -------------------------------------------------------
    @app.get("/", response_class=HTMLResponse)
    async def _index():
        # the shell carries no secrets (SEC-1); the 401 on the first API
        # call makes the page show the login UI
        return HTMLResponse(_load_admin_page(g),
                            headers={"Cache-Control": "no-store"})

    @app.get("/api/authmode")
    async def _authmode():
        # login-UI hint only: which sign-in options exist. No secrets.
        return {"ok": True, "oauth": bff is not None}

    @app.get("/api/summary")
    async def _summary(how: str = _A):
        payload = {"ok": True}
        payload.update(_admin_summary(g))
        return payload

    @app.get("/api/devices")
    async def _devices(status: str = "", q: str = "", how: str = _A):
        needle = q.strip().lower()
        rows = _admin_roster(g,
            status if status in ("approve", "deny", "temp",
                                 "raw", "pending") else None,
            needle or None)
        return {"ok": True, "devices": rows}

    @app.get("/api/pending")
    async def _pending(how: str = _A):
        return {"ok": True, "pending": _admin_pending(g)}

    @app.get("/api/events")
    async def _events(kind: str = "", mac: str = "",
                      limit: str = "50", offset: str = "0", how: str = _A):
        mac = mac.strip().lower()
        try:
            lim = min(200, max(1, int(limit)))
            off = max(0, int(offset))
        except ValueError:
            lim, off = 50, 0
        rows = _admin_events(g, kind or None,
                             mac if _MAC_RE.fullmatch(mac) else None,
                             lim, off)
        return {"ok": True, "events": rows, "limit": lim, "offset": off}

    @app.get("/api/logs")
    async def _logs(src: str = "doorbell", lines: str = "200",
                    how: str = _A):
        try:
            n = min(500, max(1, int(lines)))
        except ValueError:
            n = 200
        src_file = g.LOG_FILE if src == "dnsmasq" else g.DOORBELL_LOG
        return {"ok": True, "src": src, "lines": _tail_lines(src_file, n)}

    # ---- POST routes ------------------------------------------------------
    @app.post("/api/login")
    async def _login(request: Request):
        # SEC-2: identical generic body for rate-limit and failure — no
        # oracle for attackers. Constant-time compare; cookie HttpOnly +
        # Strict (same attributes the stdlib handler set).
        ip = request.client.host if request.client else "?"
        if not _fail_rate_ok(ip):
            return JSONResponse(status_code=403,
                                content={"ok": False, "error": "forbidden"})
        token = str((await _admin_json_body(request) or {}).get("token", ""))
        if not g.ADMIN_TOKEN or not hmac.compare_digest(
                token.encode("utf-8", "replace"), g.ADMIN_TOKEN.encode()):
            _fail_record(ip)
            g.log(f"admin login failed from {ip}")
            return JSONResponse(status_code=401,
                                content={"ok": False, "error": "unauthorized"})
        resp = JSONResponse(status_code=200, content={"ok": True})
        resp.set_cookie("gkadmin", make_session(g),
                        max_age=g.ADMIN_SESSION_HOURS * 3600, path="/",
                        httponly=True, samesite="strict")
        return resp

    @app.post("/api/logout")
    async def _logout(how: str = _A):
        resp = JSONResponse(status_code=200, content={"ok": True})
        resp.delete_cookie("gkadmin", path="/")
        return resp

    @app.post("/api/action")
    async def _action(request: Request, how: str = _A):
        # writes dispatch to the decision cores (INV-1: the same functions
        # the Telegram buttons call); validation is SEC-3, ported verbatim
        req = await _admin_json_body(request) or {}
        action = str(req.get("action", ""))
        mac = str(req.get("mac", "")).lower()
        if action not in _ADMIN_ACTIONS or not _MAC_RE.fullmatch(mac):
            return JSONResponse(status_code=400,
                                content={"ok": False,
                                         "error": "bad action or mac"})
        hours = None
        if action == "allow":
            try:
                hours = int(req.get("hours"))
            except (TypeError, ValueError):
                return JSONResponse(status_code=400,
                                    content={"ok": False, "error": "bad hours"})
            if hours not in _ADMIN_HOURS:
                return JSONResponse(
                    status_code=400,
                    content={"ok": False, "error": "hours must be 4, 12 or 24"})
        g.log(f"admin action {action} {mac} from "
              f"{request.client.host if request.client else '?'}")
        if action == "approve":
            r = g.core_approve(mac, source="web")
        elif action == "deny":
            r = g.core_deny(mac, source="web")
        elif action == "allow":
            r = g.core_temp_allow(mac, hours, source="web")
        elif action == "undo":
            r = g.core_undo(mac, source="web")
        else:
            r = g.core_skip(mac, source="web")
        if not r.get("ok"):
            err = r.get("error", "unknown")
            return JSONResponse(
                status_code=409,
                content={"ok": False, "error": err,
                         "message": ADMIN_ERRORS.get(err, err)})
        payload = {"ok": True, "action": action, "mac": mac}
        if r.get("ip"):
            payload["ip"] = r["ip"]
        if r.get("until"):
            payload["until"] = r["until"]
        if not r.get("reloaded", True):
            payload["warning"] = ("applied, but dnsmasq reload FAILED — "
                                  "check logs")
        return JSONResponse(status_code=200, content=payload)

    @app.post("/api/note")
    async def _note(request: Request, how: str = _A):
        req = await _admin_json_body(request) or {}
        mac = str(req.get("mac", "")).lower()
        if not _MAC_RE.fullmatch(mac):
            return JSONResponse(status_code=400,
                                content={"ok": False, "error": "bad mac"})
        r = g.core_set_note(mac, str(req.get("name", "")), source="web")
        if not r.get("ok"):
            return JSONResponse(
                status_code=400,
                content={"ok": False, "error": "empty",
                         "message": ADMIN_ERRORS["empty"]})
        payload = {"ok": True, "name": r["name"]}
        if r.get("warning"):
            payload["warning"] = r["warning"]
        return JSONResponse(status_code=200, content=payload)

    return app


# ------------------------------------------------------------------ serve loop

def _admin_serve(g, bind: str):
    """One bind's listener (INV-2): wait for its address to exist (the
    proxy network's gateway appears only once docker creates the network;
    a secondary LAN IP may be added later), then serve the admin app
    forever. A fresh app per bind: each uvicorn server owns its event
    loop, and the BFF's renewal-chain locks must never cross loops. If
    the server dies it waits and restarts — never propagating into the
    gate's loops (INV-4)."""
    import uvicorn

    waited = False
    while not g.stop.is_set():
        sock = None
        while not g.stop.is_set():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind((bind, g.ADMIN_PORT))
                sock.listen(128)
                break
            except OSError as e:
                try:
                    sock.close()
                except OSError:
                    pass
                if not waited:
                    g.log(f"admin page waiting for {bind}:{g.ADMIN_PORT}: {e}")
                    waited = True
                time.sleep(30)
        if g.stop.is_set():
            return
        g.log(f"admin page listening on {bind}:{g.ADMIN_PORT} "
              f"(tunnel hosts: {', '.join(g.ADMIN_HOSTS) or 'none configured'}"
              + (f", oauth client {g.ADMIN_OAUTH_CLIENT}" if g.ADMIN_BFF_SECRET
                 else "") + ")")
        app = build_admin_app(g)
        if app is None:
            try:
                sock.close()         # never hold the port with no server
            except OSError:
                pass
            return                     # reason already logged above
        try:
            uvicorn.Server(uvicorn.Config(
                # ws="none": the admin is plain HTTP/1.1 — no websocket
                # protocol import (smaller surface, no ws-lib version games)
                app, log_level="warning", access_log=False, ws="none",
            )).run(sockets=[sock])
            if g.stop.is_set():
                return
            g.log(f"admin server on {bind} exited — restarting in 30s")
        except Exception as e:         # INV-4: contained
            g.log(f"admin server on {bind} failed: {e} — restarting in 30s")
        try:
            sock.close()
        except OSError:
            pass
        time.sleep(30)
        waited = False     # a re-appearance wait deserves a fresh log line


def admin_server(g):
    """INV-2 entry point, called by the gate module with itself. One
    listener thread per ADMIN_BINDS address; each bind is SEC-6-checked
    independently — a refused address never blocks the others. Both auth
    knobs unset = nothing starts (INV-5): ADMIN_TOKEN enables the
    constant-time token legs, ADMIN_BFF_SECRET the ar-auth OAuth legs —
    either alone brings the page up."""
    if not g.ADMIN_TOKEN and not g.ADMIN_BFF_SECRET:
        g.log("admin disabled — set ADMIN_TOKEN and/or ADMIN_BFF_SECRET "
              "to enable the admin page")
        return
    for bind in g.ADMIN_BINDS:
        if not admin_bind_ok(bind):
            g.log(f"admin disabled for {bind} — refusing to bind "
                  f"(never all-interfaces or the portal IP)")
            continue
        threading.Thread(target=_admin_serve, args=(g, bind),
                         daemon=True).start()
