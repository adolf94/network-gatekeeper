#!/usr/bin/env python3
"""
pending-portal.py — Network Gatekeeper "waiting room" portal (Phase 5.5)

Pending (not-yet-decided) devices get a lease in 192.168.214.100–.149 with
no default route and DNS hijacked to this server. Any HTTP probe they make
lands here, which is what makes phones show their "sign in to network"
captive-portal popup.

The page is informational ONLY — approval happens via the owner's Telegram
doorbell buttons, never from the device itself. /status reports the caller's
current state (pending/approved), read live from the dnsmasq leasefile and
gatekeeper config, so the page flips to ✅ as soon as the owner approves.

Stdlib only. Reads only; needs CAP_NET_BIND_SERVICE for port 80.
"""

import html
import json
import os
import re
import urllib.parse
import urllib.request
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BIND      = os.environ.get("PORTAL_BIND", "192.168.214.2")
PORT      = int(os.environ.get("PORTAL_PORT", "80"))
LEASEFILE = os.environ.get("LEASEFILE", "/var/lib/misc/dnsmasq.leases")
CONFIG    = os.environ.get("CONFIG", "/etc/dnsmasq.d/gatekeeper.conf")
CLAIM_PORT = int(os.environ.get("CLAIM_PORT", "8333"))

PAGE = """<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>GraceMayAr Wifi Portal</title>
<meta http-equiv="refresh" content="10">
<style>
body{{font-family:system-ui,sans-serif;min-height:100vh;margin:0;display:flex;
align-items:center;justify-content:center;background:#101418;color:#e8eaed}}
.box{{max-width:32rem;padding:2rem;text-align:center;line-height:1.5}}
.big{{font-size:3.4rem;margin:0}}
h1{{margin:.6rem 0 .2rem;font-size:1.4rem}}
code{{background:#1d242b;padding:.15rem .45rem;border-radius:.35rem}}
.mut{{color:#9aa4ad;font-size:.9rem}}
.ok{{color:#4ade80}} .warn{{color:#fbbf24}}
form{{margin-top:1.2rem;display:flex;gap:.5rem;justify-content:center}}
input{{background:#1d242b;border:1px solid #39434c;color:#e8eaed;border-radius:.4rem;
padding:.5rem .7rem;font-size:1rem;width:14rem}}
button{{background:#2563eb;border:none;color:white;border-radius:.4rem;
padding:.5rem 1rem;font-size:1rem;cursor:pointer}}
.note{{margin-top:1rem;color:#4ade80}}
</style></head><body><div class="box">
<p class="big">{icon}</p>
<h1>{title}</h1>
<p>{body}</p>
<form method="post" action="/">
<input name="name" maxlength="40" placeholder="Who are you?" required>
<button type="submit">Connect</button>
</form>
<p class="note">{extra}</p>
<p class="mut">device <code>{devname}</code><br>this page refreshes automatically</p>
</div></body></html>"""

STATES = {
    "pending":  ("⏳", "Checking who's connecting",
                 "👋 Nothing is being blocked or restricted — the house Wi-Fi "
                 "just likes to know who's connecting, that's all. Like a "
                 "guest book, not a lock. AR has been notified; type your "
                 "name below so they know it's you."),
    "approved": ("✅", "Approved!",
                 "AR approved your device. Your network access is being "
                 "switched on right now — if this page persists, toggle Wi-Fi once."),
    "denied":   ("🚫", "Not approved",
                 "AR declined this device. No network access is available."),
    "unknown":  ("❔", "Waiting room",
                 "👋 Nothing is being blocked or restricted — the Wi-Fi just "
                 "checks in on who's connecting before devices go online. "
                 "AR has been notified; type your name below so they know "
                 "it's you."),
}


def ip_to_mac(ip: str):
    """Map a lease IP to (mac, hostname) via the dnsmasq leasefile."""
    try:
        with open(LEASEFILE) as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 4 and parts[2] == ip:
                    return parts[1].lower(), parts[3]
    except OSError:
        pass
    return None, ""


def mac_state(mac: str) -> str:
    """Check the config: deny lines win, then approvals, else pending."""
    if not mac:
        return "unknown"
    try:
        with open(CONFIG) as f:
            text = f.read()
    except OSError:
        return "unknown"
    if re.search(rf"^\s*dhcp-host\s*=\s*{mac}\s*,\s*ignore\b", text, re.M | re.I):
        return "denied"
    if re.search(rf"^\s*dhcp-host\s*=\s*{mac}\s*,", text, re.M | re.I):
        return "approved"
    return "pending"


class Portal(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # one line per request into the journal
        print(f"{datetime.now():%b %d %H:%M:%S} portal: {self.client_address[0]} "
              f"{self.command} {self.path}", flush=True)

    def _page(self, ip: str, mac: str, hostname: str, state: str, extra: str):
        icon, title, text = STATES.get(state, STATES["unknown"])
        devname = html.escape(hostname) if hostname else "unknown device"
        page = PAGE.format(icon=icon, title=title, body=text, extra=extra,
                           devname=devname)
        body = page.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        ip = self.client_address[0]
        mac, hostname = ip_to_mac(ip)
        state = mac_state(mac)
        if self.path.startswith("/status"):
            body = json.dumps({"state": state}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        # Connectivity probes (e.g. /generate_204) must get a proper 302 —
        # that is what reliably triggers the OS captive-portal popup.
        if self.path != "/":
            self.send_response(302)
            self.send_header("Location", f"http://{BIND}/")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self._page(ip, mac, hostname, state, "")

    def do_POST(self):
        if self.path != "/":
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        ip = self.client_address[0]
        mac, hostname = ip_to_mac(ip)
        state = mac_state(mac)
        try:
            n = int(self.headers.get("Content-Length", "0") or "0")
            if n > 4096:
                raise ValueError
            form = urllib.parse.parse_qs(
                self.rfile.read(n).decode("utf-8", "replace"))
            name = form.get("name", [""])[0].strip()[:60]
        except (ValueError, OSError):
            name = ""
        if not mac or not name:
            self._page(ip, mac, hostname, state,
                       "Type a name (who are you?) and submit again.")
            return
        # relay to the doorbell's loopback claim endpoint (token stays there)
        payload = json.dumps({"mac": mac, "name": name}).encode()
        try:
            req = urllib.request.Request(
                f"http://127.0.0.1:{CLAIM_PORT}/claim", data=payload,
                headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=6) as r:
                res = json.load(r)
            if res.get("ok"):
                extra = "✅ Noted — AR has been told you're here."
            elif res.get("reason") == "cooldown":
                extra = "Already reported a moment ago — hang tight."
            else:
                extra = "Could not deliver — try again shortly."
        except Exception:
            extra = "Could not deliver — try again shortly."
        self._page(ip, mac, hostname, state, extra)


if __name__ == "__main__":
    srv = ThreadingHTTPServer((BIND, PORT), Portal)
    srv.daemon_threads = True
    print(f"{datetime.now():%b %d %H:%M:%S} portal: waiting room up on "
          f"http://{BIND}:{PORT}", flush=True)
    srv.serve_forever()
