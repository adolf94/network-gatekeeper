#!/usr/bin/env python3
"""
doorbell-dhcp.py — Network Gatekeeper doorbell (Phase 5)

Watches the LAN gate interface for DHCPDISCOVER broadcasts and rings your
Telegram:  ✅ Approve / 🚫 Deny / 😴 Skip.

Why a sniffer instead of watching the dnsmasq journal:
in static-only mode dnsmasq silently ignores DISCOVERs from unregistered
MACs — they never appear in the journal. Raw AF_PACKET capture on the gate
interface sees every knock. (Journal DHCPNAK lines are also scanned as a
secondary signal for devices trying to renew router-era leases.)

Decisions are recorded in the SQLite `bindings` table; the device lines in
the dnsmasq config are RENDERED from it (atomic write; dnsmasq is reloaded
only when the set of dhcp-host lines actually changes). The static part of
the config (interface, ranges, DHCP options) lives in a hand-edited template.
Approve  → binding `MAC → IP,24h`, rendered as `dhcp-host=MAC,IP,hostname,24h`.
Deny     → binding rendered as `dhcp-host=MAC,ignore`.
Skip     → does nothing, just silences this knock for a while.

Stdlib only. Runs as root (needs CAP_NET_RAW for sniffing + rights to edit
the dnsmasq config and reload the service).

Usage:  doorbell.py            (run as the systemd service)
        doorbell.py chatid     (helper: print chat ids after you /start the bot)
        doorbell.py sniff      (foreground test: print knocks, no Telegram)
        doorbell.py render     (migrate bindings + render config once, report diff)
"""

import json
import hashlib
import hmac
import os
import re
import shlex
import signal
import socket
import sqlite3
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# ---------------------------------------------------------------- defaults
IFACE        = os.environ.get("IFACE", "wlx40a5ef262b87")
CONFIG       = os.environ.get("CONFIG", "/etc/dnsmasq.d/gatekeeper.conf")
LEASEFILE    = os.environ.get("LEASEFILE", "/var/lib/misc/dnsmasq.leases")
TOKEN        = os.environ.get("TELEGRAM_BOT_TOKEN", "")
CHAT_ID      = os.environ.get("TELEGRAM_CHAT_ID", "")
IP_MIN       = 20    # approved band per PLAN.md: 192.168.213.20 – .99
IP_MAX       = 99
IP_PREFIX    = "192.168.213."
KNOCK_COOLDOWN      = 600   # seconds between notifications for the same MAC
SKIP_COOLDOWN       = 600   # silence after 😴 Skip (10 minutes)
LEASE_SPEC   = "24h"
TEMP_LEASE   = "15m"   # lease on temporary (guest-pass) approvals
CLAIM_PORT   = int(os.environ.get("CLAIM_PORT", "8333"))  # loopback relay for visitor names
CLAIM_BIND   = "127.0.0.1"   # pinned, NOT env-configurable: the claim relay
                             # stays loopback-only (ADMIN.md VER-5)
DB_PATH      = os.environ.get("DB", "/var/lib/gatekeeper/gatekeeper.db")
# Template holding the hand-edited static part of the dnsmasq config; the
# rendered CONFIG = template + device lines generated from the DB.
TEMPLATE      = os.environ.get("TEMPLATE",
                               os.path.join(os.path.dirname(CONFIG),
                                            "gatekeeper.template"))
# How to poke dnsmasq (defaults = the systemd world; containers override):
DNMSQ_RELOAD  = os.environ.get("DNMSQ_RELOAD",  "systemctl reload dnsmasq")
DNMSQ_RESTART = os.environ.get("DNMSQ_RESTART", "systemctl restart dnsmasq")
# Where dnsmasq's log comes from (journal = systemd unit; file = container):
LOG_SOURCE    = os.environ.get("LOG_SOURCE", "journal")   # 'journal' | 'file'
LOG_FILE      = os.environ.get("LOG_FILE", "/var/log/gatekeeper/dnsmasq.log")
# Admin page (ADMIN.md): a second HTTP thread in THIS process, same pattern
# as the claim relay. Single writer preserved — web actions run the same
# decision cores as the Telegram buttons. ADMIN_TOKEN unset = disabled.
# comma-separated bind list, one listener each: e.g.
#   172.20.0.1      — the Caddy proxy network's gateway (tunnel path)
#   192.168.213.2  — the gate's LAN address (direct approved-subnet access)
# Each address is SEC-6-checked independently; a refused or not-yet-existing
# one never blocks the others (each retries until its address appears).
ADMIN_BINDS  = [b.strip() for b in
                os.environ.get("ADMIN_BIND", "127.0.0.1").split(",") if b.strip()]
ADMIN_PORT   = int(os.environ.get("ADMIN_PORT", "8340"))
ADMIN_TOKEN  = os.environ.get("ADMIN_TOKEN", "")
# Hostname allowlist for the tunnel aliases (Origin/Host checks, SEC-7):
ADMIN_HOSTS  = [h.strip().lower() for h in
                os.environ.get("ADMIN_HOSTS", "").split(",") if h.strip()]
ADMIN_SESSION_HOURS = int(os.environ.get("ADMIN_SESSION_HOURS", "12"))
ADMIN_PAGE   = os.environ.get("ADMIN_PAGE", os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "admin-page.html"))
# Doorbell's own log sink (L-3): joins the dnsmasq log in its directory
# (./log in the container world). Best-effort — stdout always stays.
DOORBELL_LOG = os.environ.get("DOORBELL_LOG", os.path.join(
    os.path.dirname(LOG_FILE), "doorbell.log"))

ETH_P_ALL   = 0x0003
ETH_P_IPV4  = 0x0800

run_lock = threading.Lock()
stop = threading.Event()

# mac (lowercase, colon form) -> monotonic deadline until which it is silenced
cooldown = {}
# macs already handled in the config (approved or ignored) -> never notify
configured_macs = set()
pending_lock = threading.RLock()   # guards config edits (reentrant: callbacks nest helper calls)
# mac -> hostname as last seen in a DISCOVER (sniffer)
last_hostname = {}
# mac -> name the visitor typed on the portal
visitor_names = {}
claim_last = {}   # mac -> monotonic deadline for the claim rate limit (60s)
temp_queue = {}   # mac -> (expiry_monotonic, ip) for guest-pass approvals
notes = {}        # mac -> owner's note (display name), persisted in the DB
note_pending = {} # {"mac": ...} while waiting for the owner's note message
# mac -> message_id of the device's live knock/decision card (ACT-12):
# ANY surface (Telegram tap or a web action) can strip its buttons, so a
# stale ✅ can never double-approve.
knock_cards = {}
_cards_lock = threading.Lock()
# admin page: per-IP failed-auth timestamps (monotonic) for SEC-2's limiter
admin_fails = {}
_admin_fail_lock = threading.Lock()


def log(*a):
    line = f"{datetime.now().strftime('%b %d %H:%M:%S')} doorbell: " \
           + " ".join(str(x) for x in a)
    print(line, flush=True)
    try:                              # second sink: L-3 doorbell log tail
        with open(DOORBELL_LOG, "a", errors="replace") as f:
            f.write(line + "\n")
    except OSError:
        pass                          # dir missing/unwritable — stdout only


# ---------------------------------------------------------------- helpers
def norm_mac(raw6: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw6)


def is_randomized_mac(mac: str) -> bool:
    """Locally-administered (privacy) MAC: bit 1 of the first octet."""
    return bool(int(mac[0:2], 16) & 0x02)


def sanitize_hostname(name: str) -> str:
    name = name.strip().rstrip(".")
    name = re.sub(r"[^A-Za-z0-9-]", "", name)[:63]
    return name


def tg_escape(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def device_label(mac: str) -> str:
    """Telegram-facing device reference: owner note wins as the display name,
    else the auto hostname; the MAC always accompanies it."""
    name = notes.get(mac) or resolve_hostname(mac)
    if name:
        return f"<b>{tg_escape(name)}</b> (<code>{mac}</code>)"
    return f"unknown device (<code>{mac}</code>)"


def host_tag(mac: str) -> str:
    """Log/DB-facing device reference: `name (mac)`, or bare MAC if nameless."""
    host = resolve_hostname(mac)
    return f"{host} ({mac})" if host else mac


def clean_name(s: str) -> str:
    """Visitor-supplied name: printable chars only, collapsed, capped at 40."""
    s = "".join(ch for ch in s if ch.isprintable())
    return " ".join(s.split())[:40]


# ---------------------------------------------------------------- sqlite
# Append-only audit trail + per-device rollup. Single writer (the doorbell);
# per-call connections so threads never share a handle.
def _db():
    con = sqlite3.connect(DB_PATH)
    con.execute("PRAGMA journal_mode=WAL")
    return con


def db_init():
    try:
        with _db() as con:
            con.execute("""CREATE TABLE IF NOT EXISTS events(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL, mac TEXT NOT NULL, hostname TEXT,
                kind TEXT NOT NULL, detail TEXT)""")
            con.execute("""CREATE TABLE IF NOT EXISTS devices(
                mac TEXT PRIMARY KEY, first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL, last_name TEXT, status TEXT,
                note TEXT)""")
            try:
                con.execute("ALTER TABLE devices ADD COLUMN note TEXT")
            except sqlite3.OperationalError:
                pass  # column already exists
            # Authoritative device decisions (CONTAINER.md Phase 2). The
            # dnsmasq config's device lines are rendered from this table.
            con.execute("""CREATE TABLE IF NOT EXISTS bindings(
                mac TEXT PRIMARY KEY,
                kind TEXT NOT NULL,          -- approve | deny | temp | raw
                ip TEXT,                     -- NULL for deny
                lease_spec TEXT,             -- 24h / 15m; NULL for deny
                hostname TEXT,               -- static label, optional
                expires TEXT,                -- ISO, temp passes only
                raw TEXT,                    -- verbatim legacy line (kind=raw)
                since TEXT NOT NULL)""")
    except sqlite3.Error as e:
        log("db init failed:", e)


def db_event(kind: str, mac: str, hostname: str = "",
             detail: str = "", name: str = None, status: str = None,
             note: str = None):
    ts = datetime.now().isoformat(timespec="seconds")
    try:
        with _db() as con:
            con.execute("INSERT INTO events(ts,mac,hostname,kind,detail) "
                        "VALUES(?,?,?,?,?)", (ts, mac, hostname, kind, detail))
            con.execute("""INSERT INTO devices(mac,first_seen,last_seen,last_name,status,note)
                           VALUES(?,?,?,?,?,?)
                           ON CONFLICT(mac) DO UPDATE SET
                               last_seen=excluded.last_seen,
                               last_name=COALESCE(excluded.last_name, devices.last_name),
                               status=COALESCE(excluded.status, devices.status),
                               note=COALESCE(excluded.note, devices.note)""",
                        (mac, ts, ts, name, status, note))
    except sqlite3.Error as e:
        log("db write failed:", e)


def db_restore():
    """Survive restarts: remembered names + still-active knock cooldowns."""
    try:
        with _db() as con:
            for mac, name in con.execute(
                    "SELECT mac,last_name FROM devices WHERE last_name IS NOT NULL"):
                visitor_names[mac] = name
            for mac, note in con.execute(
                    "SELECT mac,note FROM devices WHERE note IS NOT NULL"):
                notes[mac] = note
            now = time.monotonic()
            for mac, ts in con.execute(
                    "SELECT mac,MAX(ts) FROM events WHERE kind='knock' GROUP BY mac"):
                age = (datetime.now() - datetime.fromisoformat(ts)).total_seconds()
                if 0 <= age < KNOCK_COOLDOWN:
                    cooldown[mac] = now + (KNOCK_COOLDOWN - age)
            # re-arm guest passes across restarts (the config lines persist;
            # only the countdown lives here)
            latest_allow = {}
            for mac, detail in con.execute(
                    "SELECT mac,detail FROM events WHERE kind='allow' ORDER BY id"):
                latest_allow[mac] = detail
            for mac, detail in latest_allow.items():
                try:
                    ip, until = detail.split(" until ", 1)
                    until = until.split(" via ", 1)[0]   # provenance suffix ok
                    remaining = (datetime.fromisoformat(until) - datetime.now()).total_seconds()
                except ValueError:
                    continue
                if remaining > 0:
                    temp_queue[mac] = (now + remaining, ip)
                    log(f"re-armed temp allow for {mac} ({ip}), "
                        f"{int(remaining // 60)} min left")
            log(f"db restored: {len(visitor_names)} name(s), "
                f"{sum(1 for v in cooldown.values() if v > now)} active cooldown(s), "
                f"{len(temp_queue)} guest pass(es)")
    except (sqlite3.Error, ValueError) as e:
        log("db restore failed:", e)


def load_configured_macs():
    try:
        with open(CONFIG) as f:
            text = f.read()
    except OSError as e:
        log(f"cannot read {CONFIG}: {e}")
        return
    macs = set(m.lower() for m in re.findall(
        r"^\s*dhcp-host\s*=\s*([0-9A-Fa-f:]{17})", text, re.M))
    configured_macs.clear()
    configured_macs.update(macs)
    log(f"config: {len(macs)} MAC(s) already have dhcp-host lines")


def used_ips():
    ips = set()
    try:
        with open(CONFIG) as f:
            for m in re.finditer(r"^\s*dhcp-host\s*=.*?(192\.168\.213\.(\d+))", f.read(), re.M):
                octet = int(m.group(2))
                if IP_MIN <= octet <= IP_MAX:
                    ips.add(octet)
    except OSError:
        pass
    try:
        with open(LEASEFILE) as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 3 and parts[2].startswith(IP_PREFIX):
                    octet = int(parts[2].rsplit(".", 1)[1])
                    if IP_MIN <= octet <= IP_MAX:
                        ips.add(octet)
    except OSError:
        pass
    return ips


def next_free_ip():
    used = used_ips()
    for octet in range(IP_MIN, IP_MAX + 1):
        if octet not in used:
            return f"{IP_PREFIX}{octet}"
    return None


def _run_poke(cmd_spec: str, what: str) -> bool:
    """Run a dnsmasq control command. Defaults are the systemd verbs; a
    container overrides them with supervisorctl (DNMSQ_RELOAD/RESTART)."""
    try:
        r = subprocess.run(shlex.split(cmd_spec), capture_output=True, text=True)
    except (OSError, ValueError) as e:
        log(f"dnsmasq {what}: cannot run {cmd_spec!r}:", e)
        return False
    if r.returncode != 0:
        log(f"dnsmasq {what} failed:", (r.stderr or r.stdout).strip())
    return r.returncode == 0


def reload_dnsmasq() -> bool:
    return _run_poke(DNMSQ_RELOAD, "reload")


# ---------------------------------------------------------------- renderer
# The dnsmasq config = hand-edited TEMPLATE (static: interface, ranges,
# options) + device lines rendered from the SQLite `bindings` table.
# The DB is the source of truth; the file is derived (CONTAINER.md Phase 2).
MANAGED_BANNER = """\
# ============================================================
# DEVICE LINES — GENERATED by the doorbell from the bindings
# table in {db} ({ts}). Hand edits here are overwritten by the
# next decision; approve or deny devices via the Telegram
# buttons (or the DB). Static settings above stay hand-edited.
# ============================================================
"""

_HOSTLINE_RE = re.compile(r"^\s*dhcp-host\s*=\s*([0-9A-Fa-f:]{17})\s*(,.*?)\s*$")
_SPEC_RE     = re.compile(r"^\d+[smhdw]$")
_IP_RE       = re.compile(r"^192\.168\.213\.\d+$")
_KIND_MARKER = {"approve": "approved by doorbell", "deny": "denied by doorbell",
                "temp": "temp allow by doorbell", "raw": "preserved legacy line"}


def _atomic_write(path: str, text: str, mode: int = 0o644):
    """Write via temp file + rename so dnsmasq never sees a partial conf.
    chmod 644: the conf is world-readable by contract (the portal's
    DynamicUser world depends on it)."""
    d = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".gatekeeper.", suffix=".tmp")
    with os.fdopen(fd, "w") as f:
        f.write(text)
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def parse_host_line(line: str):
    """Parse a legacy `dhcp-host=...` line into a binding dict, else None.
    Unrecognisable shapes become kind='raw' so no device is ever lost."""
    m = _HOSTLINE_RE.match(line)
    if not m:
        return None
    mac = m.group(1).lower()
    parts = [p.strip() for p in m.group(2).split(",") if p.strip()]
    if not parts:
        return None
    if len(parts) == 1 and parts[0].lower() == "ignore":
        return {"mac": mac, "kind": "deny"}
    spec = None
    if _SPEC_RE.fullmatch(parts[-1]):
        spec = parts.pop()
    ip = None
    if parts and _IP_RE.fullmatch(parts[0]):
        ip = parts.pop(0)
    hostname = None
    if parts:
        hostname = sanitize_hostname(parts[0]) or None
    if spec is None or ip is None:
        return {"mac": mac, "kind": "raw", "raw": line.strip()}
    return {"mac": mac, "kind": "temp" if spec == TEMP_LEASE else "approve",
            "ip": ip, "spec": spec, "hostname": hostname}


def db_set_binding(mac: str, kind: str, ip: str = None, spec: str = None,
                   hostname: str = None, expires: str = None,
                   raw: str = None) -> bool:
    """Upsert the authoritative decision for a MAC. The caller re-renders."""
    try:
        with _db() as con:
            con.execute("""INSERT INTO bindings(mac,kind,ip,lease_spec,hostname,
                           expires,raw,since) VALUES(?,?,?,?,?,?,?,?)
                           ON CONFLICT(mac) DO UPDATE SET
                               kind=excluded.kind, ip=excluded.ip,
                               lease_spec=excluded.lease_spec,
                               hostname=COALESCE(excluded.hostname,
                                                 bindings.hostname),
                               expires=excluded.expires, raw=excluded.raw,
                               since=excluded.since""",
                        (mac, kind, ip, spec, hostname, expires, raw,
                         datetime.now().isoformat(timespec="seconds")))
        return True
    except sqlite3.Error as e:
        log("binding write failed:", e)
        return False


def db_clear_binding(mac: str) -> bool:
    try:
        with _db() as con:
            con.execute("DELETE FROM bindings WHERE mac=?", (mac,))
        return True
    except sqlite3.Error as e:
        log("binding clear failed:", e)
        return False


def db_set_note(mac: str, note: str) -> bool:
    """Owner's display name — must overwrite (unlike db_event's COALESCE)."""
    try:
        with _db() as con:
            ts = datetime.now().isoformat(timespec="seconds")
            cur = con.execute("UPDATE devices SET note=?, last_seen=? WHERE mac=?",
                              (note, ts, mac))
            if cur.rowcount == 0:
                con.execute("""INSERT INTO devices(mac,first_seen,last_seen,
                               last_name,note) VALUES(?,?,?,?,?)""",
                            (mac, ts, ts, note, note))
        return True
    except sqlite3.Error as e:
        log("note write failed:", e)
        return False


def migrate_bindings():
    """Import dhcp-host lines from the live config into the bindings table.
    Idempotent: MACs that already have a binding are left untouched, so
    hand-added lines are adopted on the next restart."""
    try:
        with open(CONFIG) as f:
            text = f.read()
    except OSError as e:
        log(f"cannot read {CONFIG} for binding migration: {e}")
        return
    latest_allow = {}   # mac -> detail of the most recent guest-pass grant
    try:
        with _db() as con:
            known = {r[0] for r in con.execute("SELECT mac FROM bindings")}
            for mac, detail in con.execute(
                    "SELECT mac,detail FROM events WHERE kind='allow' ORDER BY id"):
                latest_allow[mac] = detail
    except sqlite3.Error as e:
        log("binding migration read failed:", e)
        return
    imported = preserved = 0
    for line in text.splitlines():
        if line.lstrip().startswith("#") or "dhcp-host" not in line:
            continue
        parsed = parse_host_line(line)
        if not parsed:
            continue
        mac = parsed["mac"]
        if mac in known:
            continue
        kind = parsed["kind"]
        if kind == "raw":
            db_set_binding(mac, "raw", raw=parsed["raw"])
            preserved += 1
        elif kind == "deny":
            db_set_binding(mac, "deny")
            imported += 1
        else:
            expires = None
            if kind == "temp" and " until " in latest_allow.get(mac, ""):
                expires = latest_allow[mac].split(" until ", 1)[1].split(" via ", 1)[0]
            db_set_binding(mac, kind, ip=parsed["ip"], spec=parsed["spec"],
                           hostname=parsed.get("hostname"), expires=expires)
            imported += 1
        known.add(mac)
        db_event("migrate", mac, resolve_hostname(mac), detail=line.strip())
    if imported or preserved:
        log(f"bindings migrated from config: {imported} parsed, "
            f"{preserved} preserved verbatim")


def ensure_template():
    """First run on a host: derive the static template from the live config
    by stripping every device line (plus its doorbell marker comment)."""
    if os.path.exists(TEMPLATE):
        return
    try:
        with open(CONFIG) as f:
            text = f.read()
    except OSError as e:
        log(f"cannot derive template ({CONFIG} unreadable): {e}")
        return
    out = []
    for line in text.splitlines(keepends=True):
        if not line.lstrip().startswith("#") and "dhcp-host" in line:
            if out and out[-1].lstrip().startswith("#") and "doorbell" in out[-1]:
                out.pop()          # drop its marker comment too
            continue
        out.append(line)
    body = "".join(out).rstrip("\n")
    try:
        _atomic_write(TEMPLATE, body + "\n")
        log(f"template derived from live config → {TEMPLATE}")
    except OSError as e:
        log(f"cannot write template {TEMPLATE}:", e)


def _binding_rows():
    with _db() as con:
        return con.execute("""SELECT b.mac, b.kind, b.ip, b.lease_spec,
                              b.hostname, b.raw, b.since,
                              COALESCE(d.note,'') AS note
                              FROM bindings b LEFT JOIN devices d ON d.mac=b.mac
                              ORDER BY CASE b.kind WHEN 'approve' THEN 0
                                        WHEN 'temp' THEN 1
                                        WHEN 'deny' THEN 2
                                        ELSE 3 END,
                                       CASE WHEN b.ip IS NULL THEN 999
                                            ELSE CAST(SUBSTR(b.ip,13) AS INTEGER) END,
                                       b.mac""").fetchall()


def render_device_lines() -> str:
    blocks = []
    for mac, kind, ip, spec, hostname, raw, since, note in _binding_rows():
        if kind == "deny":
            line = f"dhcp-host={mac},ignore"
        elif kind == "raw":
            line = raw or f"dhcp-host={mac},ignore"
        else:
            line = f"dhcp-host={mac},{ip}"
            if hostname:
                line += f",{hostname}"
            line += f",{spec or LEASE_SPEC}"
        marker = (f"# doorbell note: {note}" if note
                  else f"# {_KIND_MARKER.get(kind, kind)} {str(since)[:10]}")
        blocks.append(f"{marker}\n{line}\n")
    return "".join(blocks)


def render_config_text() -> str:
    try:
        with open(TEMPLATE) as f:
            template = f.read()
    except OSError as e:
        raise OSError(f"template unreadable: {TEMPLATE}: {e}")
    if not template.endswith("\n"):
        template += "\n"
    banner = MANAGED_BANNER.format(db=DB_PATH,
                                   ts=datetime.now().strftime("%Y-%m-%d %H:%M"))
    return template + "\n" + banner + render_device_lines()


def _content_sig(text: str) -> str:
    """Signature of every effective config line (comments/blank lines
    ignored, order-normalized) — decides whether dnsmasq needs a reload:
    device-line changes AND static-option edits (e.g. dns-server) both
    count; comment-only re-renders (note renames) don't."""
    lines = sorted(l.strip() for l in text.splitlines()
                   if l.strip() and not l.lstrip().startswith("#"))
    return hashlib.sha256("\n".join(lines).encode()).hexdigest()


def _text_sig(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def render_and_apply():
    """Render the config from the DB and apply it atomically.
    Returns (written, reloaded): `written` False = file could not be updated;
    `reloaded` False = dnsmasq did not receive the change (or none was needed
    — comment-only re-renders, e.g. a note rename, skip the reload; static
    template edits like dns-server DO trigger one)."""
    with pending_lock:
        try:
            text = render_config_text()
        except OSError as e:
            log("config render failed:", e)
            return False, False
        try:
            with open(CONFIG) as f:
                current = f.read()
        except OSError:
            current = None
        written = False
        if current is None or _text_sig(text) != _text_sig(current):
            try:
                _atomic_write(CONFIG, text)
                written = True
            except OSError as e:
                log(f"cannot write {CONFIG}:", e)
                return False, False
        if current is not None and _content_sig(text) == _content_sig(current):
            return written, True
        if not reload_dnsmasq():
            return written, False
        log(f"config rendered + dnsmasq reloaded "
            f"({text.count('dhcp-host=')} device lines)")
        return written, True


# ---------------------------------------------------------------- telegram
def tg(method: str, **params):
    url = f"https://api.telegram.org/bot{TOKEN}/{method}"
    data = json.dumps(params).encode()
    req = urllib.request.Request(url, data=data,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=70) as resp:
        return json.load(resp)


def send_message(text: str, buttons=None) -> int:
    payload = {"chat_id": CHAT_ID, "text": text, "parse_mode": "HTML"}
    if buttons:
        payload["reply_markup"] = {"inline_keyboard": buttons}
    return tg("sendMessage", **payload)["result"]["message_id"]


def knock_buttons(mac: str):
    return [
        [{"text": "✅", "callback_data": f"approve:{mac}"},
         {"text": "🚫", "callback_data": f"deny:{mac}"},
         {"text": "⏳", "callback_data": f"allow:{mac}"},
         {"text": "😴", "callback_data": f"skip:{mac}"}],
    ]


def resolve_hostname(mac: str) -> str:
    """Best-effort device name: DISCOVER hostname first, then the dnsmasq
    leasefile (client-announced hostname per lease). Cached once found."""
    host = last_hostname.get(mac)
    if host:
        return host
    try:
        with open(LEASEFILE) as f:
            for line in f:
                parts = line.split()
                if (len(parts) >= 4 and parts[1].lower() == mac
                        and parts[3] not in ("", "*")):
                    last_hostname[mac] = parts[3]
                    return parts[3]
    except OSError:
        pass
    return ""


def knock_card(mac: str, hostname: str = ""):
    """The knock card: text + buttons. Used for fresh knocks and ⬅️ Back."""
    if hostname:
        last_hostname[mac] = hostname
    dice = " 🎲 random MAC" if is_randomized_mac(mac) else ""
    claim = visitor_names.get(mac)
    claim_line = (f"\n🙋 says they are: <b>{tg_escape(claim)}</b>"
                  if claim else "")
    text = (f"🚪 <b>Knock</b> — {device_label(mac)}{dice}\n"
            f"iface <code>{IFACE}</code>{claim_line}")
    return text, knock_buttons(mac)


def notify_knock(mac: str, hostname: str):
    text, buttons = knock_card(mac, hostname)
    try:
        register_card(mac, send_message(text, buttons))
        log(f"knock {host_tag(mac)} — notified")
    except Exception as e:
        log("telegram send failed:", e)


def register_card(mac: str, mid: int):
    """Remember which Telegram message carries this device's decision buttons
    so ANY surface can retire them later (ADMIN.md ACT-12)."""
    if mid:
        with _cards_lock:
            knock_cards[mac] = mid


def clear_card_buttons(mac: str):
    """Strip the inline keyboard from a device's knock/decision card and
    forget it. Works whichever surface made the decision — the Telegram
    path (registry, else the tapped callback's own message) or the admin
    page (registry only). Best-effort; never raises."""
    with _cards_lock:
        mid = knock_cards.pop(mac, None)
    if mid is None:
        mid = CURRENT_CBQ.get("message", {}).get("message_id")
    if not mid:
        return
    try:
        tg("editMessageReplyMarkup", chat_id=CHAT_ID, message_id=mid,
           reply_markup={"inline_keyboard": []})
    except Exception as e:
        log("clearing card buttons failed:", e)


def _tg_raw(text: str):
    """Best-effort plain Telegram send — no card to register (warnings)."""
    try:
        send_message(text)
    except Exception as e:
        log("telegram send failed:", e)


def send_waiting_roster():
    """Owner command: who is sitting in the 192.168.214.* waiting room."""
    try:
        with open(LEASEFILE) as f:
            lines = f.readlines()
    except OSError as e:
        send_message(f"⚠️ cannot read {LEASEFILE}: {e}")
        return
    rows = []
    for line in lines:
        parts = line.split()
        if len(parts) >= 4 and parts[2].startswith("192.168.214."):
            mac, ip = parts[1].lower(), parts[2]
            host = parts[3] if parts[3] != "*" else ""
            label = notes.get(mac) or visitor_names.get(mac) \
                or host or "unknown device"
            rows.append((ip, f"• <b>{tg_escape(label)}</b> "
                             f"(<code>{mac}</code>) → <code>{ip}</code>"))
    rows.sort(key=lambda r: int(r[0].rsplit(".", 1)[1]))
    if rows:
        send_message(f"🛋️ Waiting room — {len(rows)} pending:\n"
                     + "\n".join(r[1] for r in rows))
    else:
        send_message("🛋️ Waiting room is empty — no pending devices.")


def handle_owner_message(msg: dict):
    """A plain text message from the owner: note replies and commands
    (/pending)."""
    if str(msg.get("from", {}).get("id")) != str(CHAT_ID):
        return
    text = str(msg.get("text", "")).strip()
    if text.startswith("/"):
        if text.lower() in ("/pending", "/waiting"):
            send_waiting_roster()
        else:
            send_message("Commands: /pending — list the waiting room.")
        return
    if not note_pending.get("mac"):
        return
    mac = note_pending.pop("mac")
    r = core_set_note(mac, text)
    if not r["ok"]:
        send_message("📝 Empty note — nothing saved. Tap 📝 to try again.")
        return
    send_message(f"📝 Saved — {device_label(mac)} will be shown as "
                 f"“{tg_escape(r['name'])}” from now on.")


# ------------------------------------------------------------ decision cores
# The single decision path shared by the Telegram buttons and the admin
# page (ADMIN.md INV-1): DB binding → render+reload → purge → audit event →
# Telegram card. `source` only adds the provenance suffix to the audit
# trail ("via web", ACT-9) — behavior is otherwise identical, and the
# redundant-action guards make stale cards harmless no-ops (ACT-12).

def _binding_kind(mac: str):
    try:
        with _db() as con:
            row = con.execute("SELECT kind FROM bindings WHERE mac=?",
                              (mac,)).fetchone()
        return row[0] if row else None
    except sqlite3.Error:
        return None


def core_set_note(mac: str, text: str, source: str = "telegram") -> dict:
    """📝 — owner's display name; comment-only re-render, no reload."""
    note_text = clean_name(text)
    if not note_text:
        return {"ok": False, "error": "empty"}
    via = " via web" if source == "web" else ""
    notes[mac] = note_text
    db_ok = db_set_note(mac, note_text)
    db_event("note", mac, resolve_hostname(mac), detail=note_text + via)
    render_and_apply()   # marker comment updates; device lines unchanged → no reload
    log(f"note {host_tag(mac)}: {note_text!r}{via}")
    r = {"ok": True, "name": note_text}
    if not db_ok:
        r["warning"] = "note not persisted — see logs"
    return r


def core_approve(mac: str, source: str = "telegram") -> dict:
    """✅ — reserve the next free IP. Re-approving an approved device is a
    harmless no-op error (stale-card guard, ACT-12)."""
    if _binding_kind(mac) == "approve":
        return {"ok": False, "error": "already-approved"}
    ip = next_free_ip()
    if ip is None:
        return {"ok": False, "error": "pool-full"}
    if not db_set_binding(mac, "approve", ip=ip, spec=LEASE_SPEC,
                          hostname=resolve_hostname(mac) or None):
        return {"ok": False, "error": "db"}
    written, reloaded = render_and_apply()
    if not written:
        db_clear_binding(mac)   # no binding the rendered conf contradicts
        return {"ok": False, "error": "conf-write"}
    configured_macs.add(mac)
    temp_queue.pop(mac, None)
    clear_card_buttons(mac)
    via = " via web" if source == "web" else ""
    log(f"approved {host_tag(mac)} -> {ip}{via}")
    try:
        register_card(mac, send_message(
            f"✅ {device_label(mac)} approved → <code>{ip}</code>\n"
            "It connects on its next knock (toggle Wi-Fi to hurry it).",
            [[{"text": "↩️", "callback_data": f"undo:{mac}"},
              {"text": "📝", "callback_data": f"note:{mac}"}]]))
    except Exception as e:
        log("telegram send failed:", e)
    db_event("approve", mac, resolve_hostname(mac),
             detail=ip + via, status="approved")
    if reloaded:
        purge_leases(mac, "192.168.214.")
    else:
        _tg_raw(f"⚠️ approved {mac} → {ip} but dnsmasq reload FAILED — check journal.")
    return {"ok": True, "ip": ip, "reloaded": reloaded}


def core_deny(mac: str, source: str = "telegram") -> dict:
    """🚫 — record an ignore line; evict an approved lease if reload held."""
    if _binding_kind(mac) == "deny":
        return {"ok": False, "error": "already-denied"}
    if not db_set_binding(mac, "deny"):
        return {"ok": False, "error": "db"}
    written, reloaded = render_and_apply()
    if not written:
        db_clear_binding(mac)
        return {"ok": False, "error": "conf-write"}
    configured_macs.add(mac)
    temp_queue.pop(mac, None)
    clear_card_buttons(mac)
    via = " via web" if source == "web" else ""
    via_ev = via.strip()          # standalone event details carry no leading space
    log(f"denied {host_tag(mac)}{via}")
    try:
        register_card(mac, send_message(
            f"🚫 {device_label(mac)} denied (recorded as ignore).",
            [[{"text": "↩️", "callback_data": f"undo:{mac}"}]]))
    except Exception as e:
        log("telegram send failed:", e)
    db_event("deny", mac, resolve_hostname(mac), detail=via_ev, status="denied")
    if reloaded:
        purge_leases(mac, "192.168.213.")
    else:
        _tg_raw(f"⚠️ denied {mac} but dnsmasq reload FAILED — check journal.")
    return {"ok": True, "reloaded": reloaded}


def core_temp_allow(mac: str, hours: int, source: str = "telegram") -> dict:
    """⏳ — guest pass (4/12/24 h). Event detail stays `ip until ts` with an
    optional ` via web` suffix (db_restore/migrate tolerate the suffix)."""
    if _binding_kind(mac) == "temp":
        return {"ok": False, "error": "already-temp"}
    ip = next_free_ip()
    if ip is None:
        return {"ok": False, "error": "pool-full"}
    until = (datetime.now() + timedelta(hours=hours)).isoformat(timespec="minutes")
    if not db_set_binding(mac, "temp", ip=ip, spec=TEMP_LEASE,
                          hostname=resolve_hostname(mac) or None, expires=until):
        return {"ok": False, "error": "db"}
    written, reloaded = render_and_apply()
    if not written:
        db_clear_binding(mac)
        return {"ok": False, "error": "conf-write"}
    configured_macs.add(mac)
    temp_queue[mac] = (time.monotonic() + hours * 3600, ip)
    clear_card_buttons(mac)
    via = " via web" if source == "web" else ""
    log(f"temp-allow {host_tag(mac)} -> {ip} for {hours}h{via}")
    try:
        register_card(mac, send_message(
            f"⏳ {device_label(mac)} allowed until {until} → <code>{ip}</code>\n"
            "Access auto-revokes; the device then returns to the waiting room.",
            [[{"text": "↩️", "callback_data": f"undo:{mac}"}]]))
    except Exception as e:
        log("telegram send failed:", e)
    db_event("allow", mac, resolve_hostname(mac),
             detail=f"{ip} until {until}{via}", status="temp")
    if reloaded:
        purge_leases(mac, "192.168.214.")
    else:
        _tg_raw(f"⚠️ allowed {mac} but dnsmasq reload FAILED — check journal.")
    return {"ok": True, "ip": ip, "until": until, "reloaded": reloaded}


def core_undo(mac: str, source: str = "telegram") -> dict:
    """↩️ — back to pending. Undoing an undecided device is tolerated."""
    db_clear_binding(mac)
    written, reloaded = render_and_apply()
    if not reloaded:
        return {"ok": False, "error": "reload"}
    configured_macs.discard(mac)
    temp_queue.pop(mac, None)
    clear_card_buttons(mac)
    via = " via web" if source == "web" else ""
    via_ev = via.strip()
    log(f"undo {host_tag(mac)}{via}")
    db_event("undo", mac, resolve_hostname(mac), detail=via_ev, status="pending")
    _tg_raw(f"↩️ {device_label(mac)} — decision undone. "
            f"The device is pending again and can knock "
            f"(toggle its Wi-Fi to hurry it).")
    purge_leases(mac, "192.168.213.")
    return {"ok": True}


def core_skip(mac: str, source: str = "telegram") -> dict:
    """😴 — silence this device's knocks for SKIP_COOLDOWN; no DB change."""
    cooldown[mac] = time.monotonic() + SKIP_COOLDOWN
    clear_card_buttons(mac)
    via = " via web" if source == "web" else ""
    via_ev = via.strip()
    log(f"skipped {host_tag(mac)}{via}")
    db_event("skip", mac, resolve_hostname(mac), detail=via_ev)
    _tg_raw(f"😴 {device_label(mac)} skipped for {SKIP_COOLDOWN // 60} min.")
    return {"ok": True}


def _cbq_error(action: str, mac: str, r: dict) -> str:
    """Telegram-surface failure texts (ACT-10): one distinct sentence per
    failure mode — same words as before the admin refactor."""
    err = r.get("error", "")
    if err == "pool-full":
        return f"⚠️ {IP_PREFIX}{IP_MIN}–{IP_MAX} is full — no free IP for {mac}"
    if err == "db":
        what = {"approve": "approval", "deny": "denial"}.get(action, "guest pass")
        return f"⚠️ cannot record the {what} in the DB — see journal"
    if err == "conf-write":
        return f"⚠️ cannot write {CONFIG}: see journal"
    if err == "reload":
        return ("⚠️ undo failed — dnsmasq reload failed; "
                "the previous decision is still active.")
    if err == "already-approved":
        return f"✅ {device_label(mac)} is already approved — no change."
    if err == "already-denied":
        return f"🚫 {device_label(mac)} is already denied — no change."
    if err == "already-temp":
        return f"⏳ {device_label(mac)} already has an active guest pass — no change."
    return "⚠️ something failed — see journal"


def handle_callback(data: str):
    action, _, mac = data.partition(":")
    mac = mac.lower()
    with pending_lock:
        if action == "approve":
            r = core_approve(mac)
            if not r["ok"]:
                send_message(_cbq_error("approve", mac, r))
        elif action == "deny":
            r = core_deny(mac)
            if not r["ok"]:
                send_message(_cbq_error("deny", mac, r))
        elif action in ("allow4", "allow12", "allow24"):
            r = core_temp_allow(mac, int(action.removeprefix("allow")))
            if not r["ok"]:
                send_message(_cbq_error("allow", mac, r))
        elif action == "allow":
            send_message(f"⏳ Allow {device_label(mac)} for how long?",
                         [[{"text": "4 hours", "callback_data": f"allow4:{mac}"},
                           {"text": "12 hours", "callback_data": f"allow12:{mac}"},
                           {"text": "24 hours", "callback_data": f"allow24:{mac}"}],
                          [{"text": "⬅️", "callback_data": f"back:{mac}"}]])
        elif action == "note":
            clear_card_buttons(mac)
            note_pending["mac"] = mac
            try:
                tg("sendMessage", chat_id=CHAT_ID,
                   text=f"📝 Optional note for {device_label(mac)}\n"
                        f"(device name or whose device it is) — send it as a reply:",
                   parse_mode="HTML",
                   reply_markup={"force_reply": True,
                                 "input_field_placeholder": "e.g. Alice's phone"})
            except Exception as e:
                log("note prompt failed:", e)
                note_pending.pop("mac", None)
        elif action == "back":
            text, buttons = knock_card(mac)
            try:
                mid = CURRENT_CBQ.get("message", {}).get("message_id")
                if mid:
                    tg("editMessageText", chat_id=CHAT_ID, message_id=mid,
                       text=text, parse_mode="HTML",
                       reply_markup={"inline_keyboard": buttons})
                else:
                    send_message(text, buttons)
            except Exception:
                send_message(text, buttons)
        elif action == "skip":
            core_skip(mac)          # has no failure paths
        elif action == "undo":
            r = core_undo(mac)
            if not r["ok"]:
                send_message(_cbq_error("undo", mac, r))
    try:
        tg("answerCallbackQuery", callback_query_id=CURRENT_CBQ.get("id", ""))
    except Exception:
        pass


# callback_query id of the message being handled (set by the poll loop)
CURRENT_CBQ = {}


class ClaimHandler(BaseHTTPRequestHandler):
    """Loopback-only relay: the portal POSTs visitor names here so that the
    bot token never has to live in the (unprivileged) portal service."""

    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _json(self, code: int, payload: dict):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path != "/claim":
            self._json(404, {"ok": False, "reason": "not found"})
            return
        try:
            n = int(self.headers.get("Content-Length", "0") or "0")
            if n > 2048:
                self._json(200, {"ok": False, "reason": "too large"})
                return
            req = json.loads(self.rfile.read(n).decode("utf-8", "replace"))
        except (ValueError, OSError):
            self._json(200, {"ok": False, "reason": "bad request"})
            return
        mac = str(req.get("mac", "")).lower()
        name = clean_name(str(req.get("name", "")))
        if not re.fullmatch(r"[0-9a-f:]{17}", mac) or not name:
            self._json(200, {"ok": False, "reason": "bad mac or name"})
            return
        now = time.monotonic()
        if now < claim_last.get(mac, 0):
            self._json(200, {"ok": False, "reason": "cooldown"})
            return
        claim_last[mac] = now + 60
        visitor_names[mac] = name
        host = resolve_hostname(mac)
        db_event("claim", mac, host or "", detail=name, name=name)
        text = f"🙋 {device_label(mac)} says they are: <b>{tg_escape(name)}</b>"
        try:
            register_card(mac, send_message(text, knock_buttons(mac)))
            log(f"claim {host_tag(mac)}: {name!r} — notified")
            self._json(200, {"ok": True})
        except Exception as e:
            log("claim notify failed:", e)
            self._json(200, {"ok": False, "reason": "telegram failed"})


def claim_server():
    try:
        srv = ThreadingHTTPServer((CLAIM_BIND, CLAIM_PORT), ClaimHandler)
        srv.daemon_threads = True
    except OSError as e:
        log(f"claim relay not started: {e}")
        return
    log(f"claim relay listening on {CLAIM_BIND}:{CLAIM_PORT}")
    srv.serve_forever()


# ---------------------------------------------------------------- admin page
# ADMIN.md: the status/management page — a second HTTP thread in THIS
# process (INV-2, same pattern as the claim relay), sharing the decision
# cores with the Telegram buttons (INV-1: no second writer, no second
# renderer). Bind is loopback/213.x only, never the portal IP (SEC-6);
# auth = bearer token or a signed session cookie + Origin check (SEC-7);
# failed logins are rate-limited (SEC-2). Handler exceptions are contained
# (INV-4). ADMIN_TOKEN unset → the thread never starts (INV-5).

_MAC_RE = re.compile(r"^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$")
_ADMIN_ACTIONS = {"approve", "deny", "allow", "undo", "skip"}
_ADMIN_HOURS = {4, 12, 24}          # parity with allow4/allow12/allow24
_ADMIN_ERRORS = {
    "pool-full": f"reserved pool {IP_PREFIX}{IP_MIN}–{IP_MAX} is full — no free IP",
    "db": "cannot record the decision in the DB — see logs",
    "conf-write": "cannot write the rendered config — see logs",
    "already-approved": "device is already approved — no change",
    "already-denied": "device is already denied — no change",
    "already-temp": "device already has an active guest pass — no change",
    "reload": "dnsmasq reload failed — the previous decision is still active",
    "empty": "empty name — nothing saved",
}


def admin_bind_ok(bind: str) -> bool:
    """SEC-6 self-check: never all-interfaces, never the waiting-room
    portal IP. Refusing to start (gate unaffected) is the safe failure."""
    return bind not in ("0.0.0.0", "192.168.214.2")


def _sign(payload: str) -> str:
    return hmac.new(ADMIN_TOKEN.encode(), payload.encode(),
                    hashlib.sha256).hexdigest()


def make_session() -> str:
    """Cookie value `exp.sig` — HMAC keyed on ADMIN_TOKEN, so rotating the
    token invalidates every outstanding session (documented rotation)."""
    exp = str(int(time.time()) + ADMIN_SESSION_HOURS * 3600)
    return f"{exp}.{_sign(exp)}"


def check_session(value: str) -> bool:
    if not ADMIN_TOKEN or not value:
        return False
    exp, _, sig = value.partition(".")
    if not exp.isdigit() or not sig:
        return False
    if int(exp) < time.time():
        return False
    try:
        return hmac.compare_digest(sig.encode(), _sign(exp).encode())
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


def _lease_map():
    """mac -> (expires_epoch, ip, hostname) from the dnsmasq leasefile."""
    out = {}
    try:
        with open(LEASEFILE) as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 4:
                    out[parts[1].lower()] = (int(parts[0]), parts[2], parts[3])
    except (OSError, ValueError):
        pass
    return out


def _admin_roster(status: str = None, q: str = None):
    """V-1: every known device (bindings ∪ devices) with live-lease expiry.
    Reads only — the writer stays the decision cores."""
    now = time.time()
    try:
        with _db() as con:
            devices = {r[0]: r for r in con.execute(
                "SELECT mac,first_seen,last_seen,last_name,status,note FROM devices")}
            binds = {r[0]: r for r in con.execute(
                "SELECT mac,kind,ip,lease_spec,hostname,since,expires,raw FROM bindings")}
    except sqlite3.Error as e:
        log("admin roster read failed:", e)
        return []
    leases = _lease_map()
    rows = []
    for mac in set(devices) | set(binds):
        d = devices.get(mac)
        b = binds.get(mac)
        kind = b[1] if b else None
        if status and (kind or "pending") != status:
            continue
        note = (d[5] if d else "") or ""
        hostname = (b[4] if b else "") or ""
        claim = visitor_names.get(mac, "")
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


def _admin_pending():
    """V-2: current waiting room = live 214.x leases + claimed names."""
    now = time.time()
    rows = []
    for mac, (exp, ip, host) in _lease_map().items():
        if not ip.startswith("192.168.214."):
            continue
        rows.append({"mac": mac, "ip": ip,
                     "hostname": "" if host == "*" else host,
                     "name": notes.get(mac) or visitor_names.get(mac) or "",
                     "expires_in": max(0, int(exp - now))})
    rows.sort(key=lambda r: r["ip"])
    return rows


def _admin_events(kind: str = None, mac: str = None,
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
        with _db() as con:
            return [dict(zip(("id", "ts", "mac", "hostname", "kind", "detail"), r))
                    for r in con.execute(sql, params)]
    except sqlite3.Error as e:
        log("admin events read failed:", e)
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


def _admin_summary():
    counts = {}
    try:
        with _db() as con:
            for kind, n in con.execute(
                    "SELECT kind, COUNT(*) FROM bindings GROUP BY kind"):
                counts[kind] = n
    except sqlite3.Error as e:
        log("admin summary read failed:", e)
    free = sum(1 for o in range(IP_MIN, IP_MAX + 1) if o not in used_ips())
    return {"counts": counts,
            "waiting": len(_admin_pending()),
            "free_ips": free,
            "dnsmasq_alive": _dnsmasq_alive(),
            "doorbell_alive": True,   # the doorbell is serving this response
            "now": datetime.now().isoformat(timespec="seconds")}


def _load_admin_page() -> bytes:
    try:
        with open(ADMIN_PAGE, "rb") as f:
            return f.read()
    except OSError as e:
        return (f"<!doctype html><title>gatekeeper</title><body>"
                f"<p>admin page missing: {ADMIN_PAGE} ({e})</p>").encode()


class AdminHandler(BaseHTTPRequestHandler):
    """Token/session-authed admin JSON API + static page (SEC-1..SEC-8).
    Writes dispatch to the decision cores; reads are bounded and read-only."""

    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass                       # 200s stay quiet; failures log() below

    # ---- plumbing ----
    def _json(self, code: int, payload: dict, set_cookie: str = None):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        if set_cookie:
            self.send_header("Set-Cookie", set_cookie)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _forbidden(self):
        # generic identical body for 403/429 — no oracle for attackers (SEC-2)
        self._json(403, {"ok": False, "error": "forbidden"})

    def _body_json(self):
        try:
            n = int(self.headers.get("Content-Length", "0") or "0")
            if not 0 < n <= 8192:
                return None
            v = json.loads(self.rfile.read(n).decode("utf-8", "replace"))
            return v if isinstance(v, dict) else None
        except (ValueError, OSError):
            return None

    def _auth(self):
        """SEC-1: 'bearer' (constant-time) or 'session' (signed cookie)."""
        auth = self.headers.get("Authorization", "")
        if ADMIN_TOKEN and auth.startswith("Bearer ") \
                and hmac.compare_digest(auth[7:].encode(), ADMIN_TOKEN.encode()):
            return "bearer"
        for part in self.headers.get("Cookie", "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == "gkadmin" and check_session(v):
                return "session"
        return None

    def _origin_ok(self) -> bool:
        """SEC-7: browser (cookie) POSTs must originate from a host we
        actually serve — an ADMIN_HOSTS tunnel alias or any of our own
        bind addresses. Bearer POSTs skip this: the un-forgeable header
        is their guard."""
        origin = self.headers.get("Origin", "")
        host = (self.headers.get("Host") or "").strip().lower()
        if not origin or not host:
            return False
        if urllib.parse.urlsplit(origin).netloc.strip().lower() != host:
            return False
        allowed = set(ADMIN_HOSTS) | {f"{b}:{ADMIN_PORT}" for b in ADMIN_BINDS}
        return host in allowed

    # ---- routes ----
    def do_GET(self):
        try:
            path = urllib.parse.urlsplit(self.path).path
            if path == "/":
                body = _load_admin_page()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if not self._auth():
                self._json(401, {"ok": False, "error": "unauthorized"})
                return
            q = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
            if path == "/api/summary":
                payload = {"ok": True}
                payload.update(_admin_summary())
                self._json(200, payload)
            elif path == "/api/devices":
                status = q.get("status", [""])[0]
                needle = q.get("q", [""])[0].strip().lower()
                rows = _admin_roster(
                    status if status in ("approve", "deny", "temp",
                                         "raw", "pending") else None,
                    needle or None)
                self._json(200, {"ok": True, "devices": rows})
            elif path == "/api/pending":
                self._json(200, {"ok": True, "pending": _admin_pending()})
            elif path == "/api/events":
                kind = q.get("kind", [""])[0]
                mac = q.get("mac", [""])[0].strip().lower()
                try:
                    limit = min(200, max(1, int(q.get("limit", ["50"])[0])))
                    offset = max(0, int(q.get("offset", ["0"])[0]))
                except ValueError:
                    limit, offset = 50, 0
                rows = _admin_events(kind or None,
                                     mac if _MAC_RE.fullmatch(mac) else None,
                                     limit, offset)
                self._json(200, {"ok": True, "events": rows,
                                 "limit": limit, "offset": offset})
            elif path == "/api/logs":
                src = q.get("src", ["doorbell"])[0]
                try:
                    lines = min(500, max(1, int(q.get("lines", ["200"])[0])))
                except ValueError:
                    lines = 200
                src_file = LOG_FILE if src == "dnsmasq" else DOORBELL_LOG
                self._json(200, {"ok": True, "src": src,
                                 "lines": _tail_lines(src_file, lines)})
            else:
                self._json(404, {"ok": False, "error": "not found"})
        except Exception as e:      # INV-4: never propagate out of the thread
            log("admin GET failed:", e)
            try:
                self._json(500, {"ok": False, "error": "internal"})
            except Exception:
                pass

    def do_POST(self):
        try:
            path = urllib.parse.urlsplit(self.path).path
            if path == "/api/login":
                self._login()
                return
            how = self._auth()
            if not how:
                self._json(401, {"ok": False, "error": "unauthorized"})
                return
            if how == "session" and not self._origin_ok():
                log(f"admin POST rejected: bad Origin from "
                    f"{self.client_address[0]}")
                self._forbidden()
                return
            if path == "/api/action":
                self._action()
            elif path == "/api/note":
                self._note()
            elif path == "/api/logout":
                self._json(200, {"ok": True},
                           set_cookie="gkadmin=; Max-Age=0; Path=/; "
                                      "HttpOnly; SameSite=Strict")
            else:
                self._json(404, {"ok": False, "error": "not found"})
        except Exception as e:      # INV-4
            log("admin POST failed:", e)
            try:
                self._json(500, {"ok": False, "error": "internal"})
            except Exception:
                pass

    # ---- POST bodies ----
    def _login(self):
        ip = self.client_address[0]
        if not _fail_rate_ok(ip):
            self._forbidden()
            return
        token = str((self._body_json() or {}).get("token", ""))
        if not ADMIN_TOKEN or not hmac.compare_digest(
                token.encode("utf-8", "replace"), ADMIN_TOKEN.encode()):
            _fail_record(ip)
            log(f"admin login failed from {ip}")
            self._json(401, {"ok": False, "error": "unauthorized"})
            return
        cookie = (f"gkadmin={make_session()}; "
                  f"Max-Age={ADMIN_SESSION_HOURS * 3600}; Path=/; "
                  f"HttpOnly; SameSite=Strict")
        self._json(200, {"ok": True}, set_cookie=cookie)

    def _action(self):
        req = self._body_json() or {}
        action = str(req.get("action", ""))
        mac = str(req.get("mac", "")).lower()
        if action not in _ADMIN_ACTIONS or not _MAC_RE.fullmatch(mac):
            self._json(400, {"ok": False, "error": "bad action or mac"})
            return
        hours = None
        if action == "allow":
            try:
                hours = int(req.get("hours"))
            except (TypeError, ValueError):
                self._json(400, {"ok": False, "error": "bad hours"})
                return
            if hours not in _ADMIN_HOURS:
                self._json(400, {"ok": False,
                                 "error": "hours must be 4, 12 or 24"})
                return
        log(f"admin action {action} {mac} from {self.client_address[0]}")
        if action == "approve":
            r = core_approve(mac, source="web")
        elif action == "deny":
            r = core_deny(mac, source="web")
        elif action == "allow":
            r = core_temp_allow(mac, hours, source="web")
        elif action == "undo":
            r = core_undo(mac, source="web")
        else:
            r = core_skip(mac, source="web")
        if not r.get("ok"):
            err = r.get("error", "unknown")
            self._json(409, {"ok": False, "error": err,
                             "message": _ADMIN_ERRORS.get(err, err)})
            return
        payload = {"ok": True, "action": action, "mac": mac}
        if r.get("ip"):
            payload["ip"] = r["ip"]
        if r.get("until"):
            payload["until"] = r["until"]
        if not r.get("reloaded", True):
            payload["warning"] = ("applied, but dnsmasq reload FAILED — "
                                  "check logs")
        self._json(200, payload)

    def _note(self):
        req = self._body_json() or {}
        mac = str(req.get("mac", "")).lower()
        if not _MAC_RE.fullmatch(mac):
            self._json(400, {"ok": False, "error": "bad mac"})
            return
        r = core_set_note(mac, str(req.get("name", "")), source="web")
        if not r.get("ok"):
            self._json(400, {"ok": False, "error": "empty",
                             "message": _ADMIN_ERRORS["empty"]})
            return
        payload = {"ok": True, "name": r["name"]}
        if r.get("warning"):
            payload["warning"] = r["warning"]
        self._json(200, payload)


def _admin_serve(bind: str):
    """One bind's listener: wait for its address to exist (the proxy
    network's gateway appears only once docker creates the network; a
    secondary LAN IP may be added later), then serve forever. Never
    propagates into the gate's loops (INV-4)."""
    waited = False
    while not stop.is_set():
        try:
            srv = ThreadingHTTPServer((bind, ADMIN_PORT), AdminHandler)
            srv.daemon_threads = True
            break
        except OSError as e:
            if not waited:
                log(f"admin page waiting for {bind}:{ADMIN_PORT}: {e}")
                waited = True
            time.sleep(30)
    if stop.is_set():
        return
    log(f"admin page listening on {bind}:{ADMIN_PORT} "
        f"(tunnel hosts: {', '.join(ADMIN_HOSTS) or 'none configured'})")
    srv.serve_forever()


def admin_server():
    """INV-2 entry point: one listener thread per ADMIN_BINDS address.
    Each bind is SEC-6-checked independently — a refused address never
    blocks the others. ADMIN_TOKEN unset = nothing starts (INV-5)."""
    if not ADMIN_TOKEN:
        log("admin disabled — set ADMIN_TOKEN to enable the admin page")
        return
    for bind in ADMIN_BINDS:
        if not admin_bind_ok(bind):
            log(f"admin disabled for {bind} — refusing to bind "
                f"(never all-interfaces or the portal IP)")
            continue
        threading.Thread(target=_admin_serve, args=(bind,), daemon=True).start()


def signal_dnsmasq() -> bool:
    """Make dnsmasq drop the leases removed from the leasefile.
    SIGHUP does NOT re-read the lease database (verified on this box,
    2026-11-16) — a restart re-reads leases at startup."""
    return _run_poke(DNMSQ_RESTART, "restart")


def purge_leases(mac: str, prefix: str) -> bool:
    """Drop every lease for this MAC under `prefix` (e.g. the waiting-room
    192.168.214.x lease after an approval). Caution: dnsmasq rewrites the
    leasefile on lease changes; the read-modify-write window is tiny and
    home-scale, so we accept it."""
    try:
        with open(LEASEFILE) as f:
            lines = f.readlines()
    except OSError as e:
        log("lease purge read failed:", e)
        return False
    keep = []
    dropped = []
    for line in lines:
        parts = line.split()
        if len(parts) >= 4 and parts[1].lower() == mac.lower() \
                and parts[2].startswith(prefix):
            dropped.append(parts[2])
            continue
        keep.append(line)
    if not dropped:
        return False
    try:
        with open(LEASEFILE, "w") as f:
            f.writelines(keep)
    except OSError as e:
        log("lease purge write failed:", e)
        return False
    signal_dnsmasq()
    for ip in dropped:
        db_event("purge", mac, resolve_hostname(mac), detail=ip)
        log(f"purged lease {ip} for {host_tag(mac)} (dnsmasq re-armed)")
    return True


def reconcile_leases():
    """Startup sweep: make the leasefile agree with the config.
    - a device with a dhcp-host binding but still holding a waiting-room
      (192.168.214.x) lease  -> purge it so it re-knocks onto its reserved IP
    - a 192.168.213.x lease whose IP differs from the device's current
      binding (or with no binding at all) -> purge it (stale approvals)
    """
    try:
        with open(CONFIG) as f:
            text = f.read()
        bindings = {}
        for m in re.finditer(r"^\s*dhcp-host\s*=\s*([0-9A-Fa-f:]{17}),"
                             r"(192\.168\.213\.\d+)", text, re.M):
            bindings[m.group(1).lower()] = m.group(2)
        with open(LEASEFILE) as f:
            lines = f.readlines()
    except OSError as e:
        log("lease reconcile failed:", e)
        return
    keep, purged = [], []
    for line in lines:
        parts = line.split()
        if len(parts) >= 4:
            mac = parts[1].lower()
            ip = parts[2]
            if ip.startswith("192.168.214.") and mac in bindings:
                purged.append((mac, ip))
                continue
            if ip.startswith("192.168.213.") and bindings.get(mac) != ip:
                purged.append((mac, ip))
                continue
        keep.append(line)
    if not purged:
        return
    try:
        with open(LEASEFILE, "w") as f:
            f.writelines(keep)
    except OSError as e:
        log("lease reconcile write failed:", e)
        return
    signal_dnsmasq()
    for mac, ip in purged:
        db_event("purge", mac, resolve_hostname(mac), detail=ip)
        log(f"reconcile: purged lease {ip} for {host_tag(mac)}")


def temp_expiry_tick():
    """One sweep of the guest-pass queue: revoke any expired temp approval."""
    now = time.monotonic()
    for mac in [m for m, (exp, _) in temp_queue.items() if exp <= now]:
        _, ip = temp_queue.pop(mac)
        db_clear_binding(mac)
        written, reloaded = render_and_apply()
        if written and reloaded:
            configured_macs.discard(mac)   # pending again -> knocks notify again
            db_event("expire", mac, resolve_hostname(mac),
                     detail=ip, status="temp-expired")
            purge_leases(mac, "192.168.213.")
            send_message(f"⌛ {device_label(mac)} — the allowed window ended; "
                         f"access revoked. The device returns to the waiting "
                         f"room within ~15 min.")
            log(f"temp-expired {host_tag(mac)} ({ip} revoked)")
        else:
            temp_queue[mac] = (now - 1, ip)   # retry next tick


def temp_expiry_loop():
    while not stop.is_set():
        try:
            temp_expiry_tick()
        except Exception as e:
            log("expiry tick failed:", e)
        time.sleep(30)


def telegram_loop():
    offset = 0
    log("telegram poll loop started")
    while not stop.is_set():
        try:
            r = tg("getUpdates", timeout=50, offset=offset)
            for upd in r.get("result", []):
                offset = upd["update_id"] + 1
                cq = upd.get("callback_query")
                if cq:
                    CURRENT_CBQ.clear()
                    CURRENT_CBQ.update(cq)
                    if str(cq["from"]["id"]) == str(CHAT_ID):
                        handle_callback(cq["data"])
                    else:
                        log(f"callback from unauthorized user {cq['from']['id']} ignored")
                    continue
                msg = upd.get("message")
                if msg:
                    handle_owner_message(msg)
        except Exception as e:
            if not stop.is_set():
                log("telegram poll error:", e)
                time.sleep(5)


# ---------------------------------------------------------------- sniffing
def parse_dhcp(frame: bytes):
    """Return (mac, hostname) for DHCPDISCOVER frames, else None."""
    if len(frame) < 42 or struct.unpack("!H", frame[12:14])[0] != ETH_P_IPV4:
        return None
    ip_off = 14
    ihl = (frame[ip_off] & 0x0F) * 4
    if frame[ip_off + 9] != 17:                       # not UDP
        return None
    udp_off = ip_off + ihl
    if len(frame) < udp_off + 8:
        return None
    dst_port = struct.unpack("!H", frame[udp_off + 2:udp_off + 4])[0]
    if dst_port != 67:                                # not to a DHCP server
        return None
    dhcp = frame[udp_off + 8:]
    if len(dhcp) < 240 or struct.unpack("!I", dhcp[236:240])[0] != 0x63825363:
        return None
    if dhcp[0] != 1 or dhcp[1] != 1:                  # BOOTREQUEST, htype ethernet
        return None
    mac = norm_mac(dhcp[28:34])
    hostname = ""
    msgtype = None
    off = 240
    while off + 2 <= len(dhcp):
        tag = dhcp[off]
        if tag == 0:                                  # PAD
            off += 1
            continue
        if tag == 255:                                # END
            break
        ln = dhcp[off + 1]
        val = dhcp[off + 2:off + 2 + ln]
        if tag == 53 and ln == 1:
            msgtype = val[0]
        elif tag == 12:
            hostname = val.decode("utf-8", "replace")
        off += 2 + ln
    if msgtype != 1:                                  # only DISCOVER = a knock
        return None
    return mac, hostname


def _tail_file_lines(path: str):
    """Yield lines appended to `path` (journalctl -n 0 semantics: start at
    EOF), surviving truncation/rotation by reopening."""
    while not stop.is_set():
        try:
            f = open(path, errors="replace")
        except OSError:
            time.sleep(1)
            continue
        try:
            f.seek(0, os.SEEK_END)
            while not stop.is_set():
                line = f.readline()
                if line:
                    yield line
                    continue
                try:
                    if os.stat(path).st_size < f.tell():
                        break            # rotated/truncated → reopen
                except OSError:
                    break
                time.sleep(0.5)
        finally:
            f.close()


def journal_nak_watcher():
    """Secondary signal + audit feed: NAKs (devices renewing unassigned
    addresses) and ACKs (approved devices landing on their reserved IP)
    appear in the dnsmasq log but not as DISCOVERs on the wire. Best-effort."""
    proc = None
    if LOG_SOURCE == "file":
        log(f"NAK watcher: tailing {LOG_FILE}")
        stream = _tail_file_lines(LOG_FILE)
    else:
        try:
            proc = subprocess.Popen(
                ["journalctl", "-u", "dnsmasq", "-f", "-n", "0", "--output=cat"],
                stdout=subprocess.PIPE, text=True)
        except OSError:
            return
        stream = proc.stdout
    pat_nak = re.compile(r"DHCPNAK\(\S+\)\s+(\S+)\s+([0-9A-Fa-f:]{17})")
    pat_ack = re.compile(r"DHCPACK\(\S+\)\s+(\S+)\s+([0-9A-Fa-f:]{17})(?:\s+(\S+))?")
    nak_last = {}   # mac -> monotonic ts of last NAK recorded (dedupe bursts)
    for line in stream:
        if stop.is_set():
            if proc:
                proc.terminate()
            return
        m = pat_ack.search(line)
        if m:
            ip, mac = m.group(1), m.group(2).lower()
            if ip.startswith("192.168.213."):
                db_event("ack", mac, m.group(3) or "", detail=ip)
            continue
        m = pat_nak.search(line)
        if not m:
            continue
        mac = m.group(2).lower()
        now = time.monotonic()
        if now - nak_last.get(mac, 0) > 600:
            nak_last[mac] = now
            db_event("nak", mac, resolve_hostname(mac), detail=f"renewed {m.group(1)}")
        if mac in configured_macs or now < cooldown.get(mac, 0):
            continue
        cooldown[mac] = now + KNOCK_COOLDOWN
        log(f"NAK-knock {host_tag(mac)} (tried to renew an unassigned address)")
        if TOKEN and CHAT_ID:
            notify_knock(mac, "")


def sniff_loop():
    while not stop.is_set():
        try:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                              socket.htons(ETH_P_ALL))
            s.bind((IFACE, 0))
            s.settimeout(1.0)
        except OSError as e:
            log(f"cannot bind {IFACE}: {e} — retrying in 5s")
            time.sleep(5)
            continue
        log(f"listening for DHCPDISCOVER on {IFACE}")
        while not stop.is_set():
            try:
                frame, _ = s.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError as e:
                log(f"recv error: {e}")
                break
            parsed = parse_dhcp(frame)
            if not parsed:
                continue
            mac, hostname = parsed
            if hostname:
                last_hostname[mac] = hostname
            now = time.monotonic()
            if mac in configured_macs or now < cooldown.get(mac, 0):
                continue
            cooldown[mac] = now + KNOCK_COOLDOWN
            db_event("knock", mac, resolve_hostname(mac))
            if TOKEN and CHAT_ID:
                notify_knock(mac, hostname)
            else:
                log(f"knock {host_tag(mac)} — no token/chat id, not notified")
        s.close()


# ---------------------------------------------------------------- modes
def mode_chatid():
    if not TOKEN:
        sys.exit("TELEGRAM_BOT_TOKEN is not set")
    r = tg("getUpdates")
    ids = set()
    for upd in r.get("result", []):
        for key in ("message", "edited_message", "callback_query"):
            item = upd.get(key)
            if not item:
                continue
            chat = item.get("chat") or item.get("message", {}).get("chat")
            if chat:
                ids.add(chat["id"])
            if key == "callback_query":
                ids.add(item["from"]["id"])
            break
    if ids:
        print("chat ids seen:", ", ".join(str(i) for i in ids))
        print("put one into /etc/doorbell.env as TELEGRAM_CHAT_ID=<id>")
    else:
        print("No messages yet. Open Telegram, send /start to your bot, then retry.")


def mode_render():
    """One-shot: migrate bindings, derive the template if missing, render the
    config once and report what changed. Safe to run while dnsmasq is up —
    an unchanged render never reloads it (line-set signature decides)."""
    db_init()
    migrate_bindings()
    ensure_template()
    written, reloaded = render_and_apply()
    log(f"render done: written={written} reloaded={reloaded}")
    sys.exit(0 if reloaded else 1)


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "chatid":
        mode_chatid()
        return
    if len(sys.argv) > 1 and sys.argv[1] == "render":
        mode_render()
        return
    if len(sys.argv) > 1 and sys.argv[1] == "sniff":
        log("foreground sniff test (Ctrl-C to stop)")
        sniff_only = True
    else:
        sniff_only = False
    if not sniff_only and (not TOKEN or not CHAT_ID):
        sys.exit("TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID not set — "
                 "see /etc/doorbell.env and systemd/doorbell.service")
    db_init()
    db_restore()
    migrate_bindings()
    ensure_template()
    try:                                   # L-3: bounded log — fresh each run
        d = os.path.dirname(DOORBELL_LOG)
        if d:
            os.makedirs(d, exist_ok=True)
        open(DOORBELL_LOG, "w").close()
    except OSError:
        pass                               # stdout sink always works
    written, reloaded = render_and_apply()
    if not reloaded:
        log("WARNING: initial config render did not reach dnsmasq")
    load_configured_macs()
    reconcile_leases()
    threading.Thread(target=sniff_loop, daemon=True).start()
    threading.Thread(target=journal_nak_watcher, daemon=True).start()
    threading.Thread(target=temp_expiry_loop, daemon=True).start()
    if not sniff_only:
        threading.Thread(target=telegram_loop, daemon=True).start()
        threading.Thread(target=claim_server, daemon=True).start()
        threading.Thread(target=admin_server, daemon=True).start()
        log(f"doorbell up — knocks will be sent to chat {CHAT_ID}")
    else:
        log("sniff-only mode active")
    stop_sig = threading.Event()

    def term(signum, frame):
        stop.set()
        stop_sig.set()

    signal.signal(signal.SIGTERM, term)
    signal.signal(signal.SIGINT, term)
    while not stop_sig.is_set():
        time.sleep(1)
    log("doorbell stopped")


if __name__ == "__main__":
    main()
