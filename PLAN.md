# Network Gatekeeper — Implementation Plan

**Goal:** No device gets an IP unless it's explicitly approved. New devices "knock"
(DHCP DISCOVER), a script notifies via Telegram, and the network owner taps
✅ Approve or 🚫 Deny from anywhere.

**Decisions made (final design):**

| Role | Owner | Notes |
|---|---|---|
| DHCP (gatekeeper) | Always-on Linux PC (dnsmasq, DHCP-only) | Static leases only; unknown MACs get nothing |
| DNS | Untouched — clients get 1.1.1.1 / 1.0.0.1 directly | No Pi-hole, no ad-blocking |
| Routing / gateway | Stock router (`192.168.213.1`) now; **Phase 7 inline gateway** planned | Future: TP-Link demotes to AP+switch; gate moves from "no IP offered" to "no route granted" |
| New-device notification | `doorbell-dhcp.py` + Telegram bot | Watch dnsmasq logs, approve/deny inline |
| Wi-Fi front door | Router MAC allowlist (optional, Phase 6) | Second lock; silent by design |

**Honest threat model:** stops casual/opportunistic devices completely and makes
every join attempt visible. A determined attacker can still hardcode a static IP
or clone an approved MAC — this is a strong fence, not a castle wall.

---

## Phase 0 — Inventory (before touching anything)

- [ ] List every device currently on the LAN (laptops, phones, printers, TV, IoT).
  `arp -a` from any machine + router admin page "connected devices" helps.
- [ ] Rebase the router's LAN IP to `192.168.213.1` (admin UI → LAN settings). Its still-on
      DHCP re-leases every device into the new subnet — everything keeps working, and you've
      just rehearsed the cutover.
- [ ] Confirm the rebase took: `arp -a` / router admin page now show `192.168.213.x`.
- [ ] Confirm router model supports "Wireless MAC filter / Access Control" (Phase 6).
- [ ] Pick the always-on PC's LAN interface name: `ip -br link` (e.g. `eth0`, `enp3s0`).

**Address plan**

*Deliberately uncommon subnet.* `192.168.213.0/24` dodges the ranges most likely to be
spoken elsewhere: every consumer-router default (`192.168.0/1.x`), phone hotspots
(Android `192.168.43.x`, iOS `172.20.10.x`), ISP/cable gear (`192.168.100.x`,
Technicolor `192.168.87.x`), VMware VMnet (`192.168.132.x`), Windows ICS
(`192.168.137.x`), Fritz!Box (`192.168.178.x`), devolo (`192.168.188.x`), HP Wireless
Direct (`192.168.223.x`), and the VPN-heavy `172.16.0.0/12` + low `10.x` blocks.
Networks you roam into are unlikely to speak `213` — checked against vendor default
lists on 2026-11-15; if you ever find a collision, rebase the same way (router first).

| Range | Use |
|---|---|
| `192.168.213.1` | Router (gateway) — rebased |
| `192.168.213.2` | Gatekeeper PC — static, set at OS level; also holds `192.168.214.2/24` as the pending-gate address |
| `192.168.213.20 – .99` | Approved devices (dhcp-host entries) |
| `192.168.214.100 – .149` | PENDING waiting room — 2-min leases, no gateway, DNS hijacked to the portal at `192.168.214.2` |
| `169.254.0.0/16` | Where DENIED devices end up (APIPA limbo) |

## Phase 1 — Pin the PC's IP (do this FIRST)

If the PC still gets its address from the router's DHCP, it will lose it the
moment the router's DHCP goes off. Configure statically at the OS level:

- [x] NetworkManager: `nmcli con mod "<profile>" ipv4.method manual ipv4.addresses 192.168.213.2/24 ipv4.gateway 192.168.213.1 ipv4.dns 1.1.1.1 1.0.0.1 && nmcli con up "<profile>"`
      (Done 2026-11-15 on profile UUID `7234a315…` / SSID `GraceMayAr`, interface `wlx40a5ef262b87` — this PC is on Wi-Fi, `eno1` is unplugged.)
- [ ] (netplan/systemd-networkd equivalents: same numbers, static method.) — N/A here, NetworkManager machine.
- [x] Verify: `ip -br addr` shows `192.168.213.2`; ping `192.168.213.1` and `1.1.1.1`. ✅ Route is `proto static`, DNS on the link is 1.1.1.1/1.0.0.1, resolution works.

## Phase 2 — Install dnsmasq, DHCP-only

- [x] Install: `sudo apt install dnsmasq` (or `dnf` / `pacman` equivalent).
      (dnsmasq 2.91 was already installed + enabled; failed to start on :53 vs systemd-resolved — expected, fixed by `port=0` below.)
- [x] Copy `config/gatekeeper.conf` → `/etc/dnsmasq.d/gatekeeper.conf`
      (edit: interface name, MAC/IP of your real devices).
      ⚠ **Mint quirk:** `/etc/dnsmasq.conf` ships with `conf-dir=/etc/dnsmasq.d` COMMENTED OUT — the dir is not scanned by default.
      Enable it once: `echo 'conf-dir=/etc/dnsmasq.d,*.conf' | sudo tee -a /etc/dnsmasq.conf` (done 2026-11-15)
- [x] Validate: `dnsmasq --test` — syntax OK.
- [x] Start: `sudo systemctl enable --now dnsmasq` — active since 23:37; journal shows
      `DNS disabled`, `DHCP, static leases only on 192.168.213.0`, sockets bound to `wlx40a5ef262b87`.
- [ ] Sanity checks:
  - [x] `ss -lntu` — nothing listening on :53 from dnsmasq (`port=0`), UDP :67 open on the gate interface.
  - [x] `sudo ufw allow 67/udp` — N/A: firewall verified **inactive** (`ufw status` → inactive; the ufw *service* shows "active" but its ruleset is disabled). No blocking rule needed.
  - [ ] `journalctl -u dnsmasq -f` shows live DHCP activity — listener confirmed; live DISCOVERs verified in Phase 3.

## Phase 3 — Register devices & test the bouncer

- [x] One `dhcp-host=MAC,IP,hostname,24h` line per known device (use Phase 0 list).
      (7 devices in `config/gatekeeper.conf`; new device MACs discovered since: `36:c7:1c:21:99:20` (randomized, asked for .199), `58:85:a2:90:e0:15`, `1a:91:6c:4c:02:89` (both v6-only so far).)
- [x] `sudo systemctl reload dnsmasq` after each edit.
- [x] Test APPROVED path: connect a registered device → gets its reserved IP
      (`journalctl` shows DHCPACK; lease listed in the leasefile).
      (✅ 2026-11-15 23:47: S24 `16:d1:46:3d:22:dc` DISCOVER→OFFER `.26`→REQUEST→**DHCPACK**, leasefile entry written, ARP confirms live.)
- [x] Test DENIED path: connect an unregistered device → DHCPDISCOVER logged,
      no offer, device lands on `169.254.x.x` ("connected, no internet").
      (Observed via NAK path: unknown randomized MAC `36:c7:1c:21:99:20` REQUESTed router-era `.199` → dnsmasq NAKed "address not available"; registered devices also NAKed for router-era IPs, forcing re-DHCP. Silent-drop of unknown DISCOVERs is the default.)

## Phase 4 — Cutover (the point of no return)

- [ ] Optional safety net: drop router DHCP lease time to 1h a day before. — skipped (same-evening cutover)
- [x] **Disable DHCP on the router** (admin UI → LAN/DHCP settings → off). ✅ 2026-11-15 ~23:47
- [ ] Reconnect devices; verify each gets its reserved IP. — S24 done (`.26`). Others convert at next renewal
      (router-era lease T1) or immediately on Wi-Fi toggle; expect brief NAK→DISCOVER→ACK per device.
- [x] Keep a laptop + Ethernet cable ready with a manual static config
      (e.g. `192.168.213.250/24`) so a failed cutover can't lock you out. — covered: this PC is static `.2` at OS level; Tailscale reachable too.
- [ ] **Rollback if broken:** re-enable router DHCP. Ten seconds, everything recovers. — not needed so far

## Phase 5 — The doorbell (approve/deny)

> **Design note (updated 2026-11-16):** the journal *does* log unknown-client
> DISCOVERs (as `DHCPDISCOVER … no address available`), but without the client
> hostname. The doorbell therefore sniffs DHCP frames directly on the gate
> interface (AF_PACKET, CAP_NET_RAW) — it sees every knock instantly, with the
> hostname — and additionally tails the journal for DHCPNAKs (devices trying
> to renew router-era leases). Approve/deny edit `gatekeeper.conf` + reload
> dnsmasq; 🎲 randomized-MAC flag and per-MAC cooldown are built in.

- [x] Create Telegram bot via @BotFather → token in `/etc/doorbell.env` (mode 600).
- [x] Message the bot `/start`, then get your chat id:
      `TELEGRAM_BOT_TOKEN=<token> python3 scripts/doorbell-dhcp.py chatid`
- [x] Install `scripts/doorbell-dhcp.py` → `/opt/doorbell/doorbell.py` (mode 700).
- [x] Install `systemd/doorbell.service` → `/etc/systemd/system/`.
- [x] `sudo systemctl enable --now doorbell` — live since 2026-11-16 00:07, chat `5225739111`.
- [x] Test: unregistered devices knocked → ✅ Approve / 🚫 Deny / 😴 Skip all exercised live.
      Deny recorded `,ignore` lines; journal shows `no address available` for denied
      MACs — the DENIED path is fully closed. (An approve was granted then revoked by
      its deny; the stale approve line was cleaned from the config.)
  - Lesson learned: the Galaxy-A06 rotates its randomized MAC per connection — it
    knocked under two MACs in ten minutes (`1a:91:6c:…`, `6a:89:8c:…`). Durable fix is
    Phase 6's device-side "Use device MAC" for this SSID.
  - Revoke later: delete the line from `gatekeeper.conf`, `systemctl reload dnsmasq`.

## Pending waiting room (captive portal, added 2026-11-16)

Unknown (not-yet-decided) MACs land in a gateway-less holding pool on
`192.168.214.0/24` instead of APIPA — they get "sign in to network" and a
status page. Approval still happens ONLY via the doorbell's Telegram
buttons; the page is informational.

> Tone (set 2026-11-16): the page says plainly — *"Nothing is being blocked
> or restricted — the house Wi-Fi just likes to know who's connecting, that's
> all. Like a guest book, not a lock."* The gate is a check-in, not a
> punishment, and the wording is chosen so even a teenager skimming the popup
> reads it that way.

- [x] `config/gatekeeper.conf`: DNS enabled (gate interface only, `except-interface=lo`),
      pending range `192.168.214.100–.149` (2m, `set:pending`), option 3 suppressed
      for pending, DNS → `192.168.214.2`, `address=/#/` hijack. Approved clients
      still get 1.1.1.1/1.0.0.1 directly and never touch our DNS.
- [x] PC holds secondary IP `192.168.214.2/24` on the Wi-Fi NIC (NetworkManager).
- [x] `scripts/pending-portal.py` + `systemd/pending-portal.service`
      (DynamicUser + CAP_NET_BIND_SERVICE only; reads leasefile + config per request;
      `/status` reports the caller's own pending/approved state).
- [ ] Visitor identity ("Who's connecting") — BUILT, pending deploy: the waiting-room
      page has a name field (**button: "Connect"**); submissions relay via
      127.0.0.1 to the doorbell (the bot token never leaves it) and arrive in Telegram
      as `🙋 Device: <host> (<mac>) says: <name>`; later knocks include the claim.
      Rate-limited 1/min/MAC, names sanitized + capped. Portal shows the device NAME
      to visitors but never the MAC.
- [x] SQLite audit trail — `/var/lib/gatekeeper/gatekeeper.db` (systemd
      `StateDirectory=gatekeeper`): `events` table (knock/claim/approve/deny/skip/
      allow/expire/ack/nak — append-only) + `devices` rollup (first/last seen,
      claimed name, status). Visitor names and knock cooldowns are restored on
      restart, so a service bounce no longer resets silences. Device names are
      resolved from the DISCOVER + dnsmasq leasefile and used consistently in
      Telegram, logs, and the DB (a device that never announced any name shows
      as "unknown device"). Inspect:
      `sqlite3 /var/lib/gatekeeper/gatekeeper.db "SELECT ts,mac,hostname,kind,detail FROM events ORDER BY id DESC LIMIT 20;"`
- [x] Guest pass — "⏳ Allow for…" button on knock/claim messages → 4/12/24 h
      (with ⬅️ Back, which edits the menu back into the knock card).
      Temp line uses a 15-min lease; the doorbell auto-revokes at expiry
      (device re-knocks into the waiting room). Passes survive restarts via the
      `allow` events. Approve/Deny now replace any prior line for the MAC
      (no duplicates).
- [x] Lease reconciliation — approvals evict the waiting-room lease automatically
      (`purge_leases` + a dnsmasq restart — SIGHUP does NOT re-read the lease DB,
      verified): after ✅/⏳ the device's next renewal is
      refused and it hops onto its reserved IP within ~2 min — no Forget/rejoin
      needed. Inverse on deny/undo/expiry (evicts the approved-space lease).
      A startup sweep (`reconcile_leases`) also cleans drift: devices with a
      binding still holding a 214.x lease, and stale 213.x leases not matching the
      current binding (e.g. the orphaned .27 from a revoked approval). All purges
      audited as `purge` events in SQLite.
- [x] Reversible decisions — tapping a button strips the keyboard from that
      message; the confirmation carries **↩️ Undo** (works for approve / deny /
      guest pass): removes the line, reloads dnsmasq, device returns to pending.
      Buttons are icon-only (✅ 🚫 ⏳ 😴 / ↩️ 📝 ⬅️); the confirmations + audit
      trail carry the meaning.
- [x] Optional 📝 note — after approval the confirmation offers an optional
      Note button: tapping it opens a force-reply prompt; whatever the owner
      types becomes the device's display NAME everywhere (Telegram, logs, DB
      `devices.note`, and the `# doorbell note:` marker in the config), taking
      precedence over the auto hostname. Survives restarts.
- [ ] Install: copy config → `/etc/dnsmasq.d/`, `dnsmasq --test`, restart dnsmasq;
      install portal script (mode 755) + unit, `daemon-reload`, `enable --now pending-portal`.
- [ ] Test: connect an unknown device → gets `192.168.214.x`, phone shows
      "sign in to network" → page says pending → ✅ approve in Telegram →
      device moves to its reserved IP within ~2 min (NAK of the stale 214.x lease).
- [ ] Rollback: restore pre-portal config (`port=0`, no pending range) + restart
      dnsmasq; `disable --now pending-portal`. Gate logic is config-only.
- [ ] Known gap: IPv6 — pending devices may still get v6 via router RA/SLAAC
      and bypass the waiting room entirely (portal UX is v4-only). Fix = disable
      RA/IPv6 on the router (Phase 6).

### Bugs found in the wild (recorded 2026-11-17)

1. **Doorbell blind spot — silent waiting-room entry via DHCPREQUEST (no
   knock, no card).** Every approval purges the device's pending lease and
   restarts dnsmasq; the freed IP can then be reclaimed *silently*: on its
   next connect the device sends a renewal-style DHCPREQUEST (INIT-REBOOT —
   no broadcast DISCOVER) for the IP it remembers, and dnsmasq grants it
   directly under `tag:pending`. None of the doorbell's three sensors sees
   it: the sniffer only rings on broadcast DISCOVERs (`parse_dhcp` returns
   None for anything else), the NAK watcher needs a NAK (the lease was
   *granted*, never refused), and the ACK tailer records 213.x ACKs only —
   a 214.x REQUEST-grant is invisible end to end.
   Live case: `a4:a4:90:a5:83:ee` (S24 presenting its REAL device MAC after
   "Use device MAC" was enabled) took `.122` at 13:50:25 via
   DHCPREQUEST/DHCPACK — zero doorbell events, no Telegram card; and the
   `/pending` roster is text-only (no buttons), so the device was not
   approvable from the bot either.
   → Planned fix: ACK-knock — `journal_nak_watcher` sends the knock card on
   the first DHCPACK for a non-configured MAC on 192.168.214.x (reuse
   KNOCK_COOLDOWN dedupe; seed state from the DB so restarts don't
   re-spam). Optional companion: interactive `/pending` (buttons per device).
2. **Client-side (not ours): Android 17 + Chrome 156 blocks every LAN IP —
   `ERR_TOO_MANY_RETRIES`.** Chromium issue 579403238: for apps targeting
   SDK < 37 the Nearby-devices / ACCESS_LOCAL_NETWORK permission is left in
   REVOKED_COMPAT; a kernel eBPF filter silently drops all connects to
   192.168.x.x, Chrome retries 32× and shows ERR_TOO_MANY_RETRIES — no
   permission prompt, and the portal never receives a packet (verified:
   zero requests from `.122` in the portal log). Port-agnostic — no
   portal-side change fixes it. Device fix: Settings → Apps → Chrome →
   Permissions → Nearby devices → Allow (toggle off→on if already
   allowed); Firefox unaffected. Chromium fix merged for M158/M159
   (Nov 2026). The waiting-room S24 (`android-dhcp-17`) hit exactly this.
3. **443 TLS click-through — BUILT via Caddy (2026-11-17, verified).** The
   gate's own stack needed zero changes: the public Caddy (v2.11.9,
   `/opt/caddy`) already owns `0.0.0.0:443`, so its Caddyfile now
   completes handshakes for everyone (`default_sni` + `fallback_sni`
   `192.168.214.2` — for SNI-less clients and for hijacked names like
   facebook.com, where Chrome won't fall back to HTTP), serves Caddy's
   **internal-CA** cert for `192.168.214.2` (`tls internal`; phones warn,
   which is the point), and a hostless `https://` catch-all (ranked after
   all real sites) proxies every unmatched Host to the portal at
   `192.168.214.2:80`. Result: HTTPS-stuck clients get the standard
   captive-portal certificate warning → proceed → portal page; the
   `/generate_204` probe over TLS still 302s to the HTTP portal; real
   sites (`loc-stream.adolfrey.com`) verified unchanged; graceful reload,
   no downtime. Backup: `/opt/caddy/Caddyfile.bak-2026-11-17`.
   Scope notes: does NOT drive the automatic "sign in to network" popup —
   that is the port-80 probe (already working; on Android 17 it needs the
   Chrome Nearby-devices permission per bug #2). Unmatched traffic now
   also lands on the portal from the WAN side of Caddy — harmless: the
   page is informational and the claim relay rejects callers without a
   pending lease.

## Phase 6 — Optional hardening

- [ ] Router Wi-Fi MAC allowlist in "allow only listed" mode; add every approved
      MAC. Result: unapproved Wi-Fi devices are blocked at association — silently,
      before they can even knock. Onboarding a new Wi-Fi device = add to router
      list manually (doorbell stays wired-side).
      → **SKIPPED by owner (2026-11-16).** The dnsmasq gate + doorbell visibility
      is the chosen level of hardening: unknown Wi-Fi devices still *associate*
      and knock, but get no IP. Doorbell remains the front door for ALL devices,
      wired and wireless. (Trade-off accepted: unapproved devices can join the
      radio cell and see traffic; they cannot route v4.)
- [ ] Doorbell add-on: 🎲 flag for randomized MACs (locally-administered — second
      hex digit of first byte is 2/6/A/E) + per-MAC cooldown + burst aggregation.
- [ ] Disable per-device MAC randomization for the home SSID only
      (iOS: Private Wi-Fi Address → Off; Android: Privacy → Device MAC;
      Windows: Random hardware addresses → Off). Keep it on for public networks.
- [ ] IPv6 note: the router may still advertise v6 via RA/SLAAC — a denied device
      can still get v6. Disable IPv6/RA on the router or accept the gap.

## Phase 7 — Inline gateway (planned 2026-11-17; future — no hardware yet)

> **Why (for when the box exists):** the current gate controls *who gets an
> IP*, not *who gets a route*. The threat model's static-IP splicer, IPv6
> (risk #4), wide-open wired ports (risk #2), and tethering chains behind an
> approved device (risk #6) are all invisible from a DHCP server's chair.
> The doorbell's AF_PACKET sniffer only receives broadcasts — forwarded
> traffic is unicast, frames a station NIC never gets handed. Only the
> border sees the border.

**Architecture (when built):**

```
ISP modem ──► [ inline gateway box ] ──► TP-Link (AP + switch mode) ──► LAN
```

The gateway box owns NAT/firewall (nftables); the TP-Link is demoted to
access point + switch. Every client — wired or wireless — then sits *behind*
our gate. dnsmasq/doorbell/portal keep their roles; they migrate onto the
box or stay on the PC (decide at build time).

- [ ] Acquire + pick hardware: spare PC + USB Ethernet (`eno1` → modem,
      USB → TP-Link) or a dedicated box (OpenWrt / OPNsense on an N100).
      ⚠ As the gateway, the box is the network's single point of failure —
      risk #1 gets *worse*: box down = nobody has internet. Rollback below
      stays a one-cable move.
- [ ] Demote the TP-Link: AP/switch mode (DHCP stays off, Wi-Fi unchanged).
- [ ] **NAT allowlist:** forward + NAT only for approved space
      (`192.168.213.20–.99` + `.2` infra). Unknown IPs reach the gateway and
      stop there — closes the static-IP bypass and gates the wired ports.
- [ ] **Tether-jump detection:** traffic a client forwards for something
      behind it arrives with a decremented TTL (64→63, 128→127 …).
      Learn each IP's baseline from its first flows; alert via the doorbell
      on any jump; optional `drop` toggle so tethering *stops working*,
      not just gets noticed. Sketch (hardcoded defaults before baselining):
      `nft add rule ip filter forward ct state new ip ttl { 62, 63, 125, 126 } log prefix "tether-jump: "`
- [ ] Optional **hotspot-beacon watcher** (doable even before the box): a
      second Wi-Fi NIC in monitor mode on the WLAN channel sees the
      management frames a device emits when it starts its own hotspot — no
      keys needed. Correlate BSSID → approved MACs (same OUI logic as the
      🎲 flag) → doorbell alert. Detects that tethering *started*; who
      joined stays hidden until the TTL rule exists at a gateway.
- [ ] IPv6: terminate or switch it off at the gateway (or disable RA/SLAAC
      on the TP-Link) — closes risk #4 properly.
- [ ] Migrate the stack: dnsmasq + doorbell (+ portal) onto the gateway box;
      this PC keeps `192.168.213.2` if it stays on Wi-Fi.
- [ ] Verify: denied device with a hardcoded static IP → no internet;
      approved device starts a hotspot → doorbell alert; tethering client →
      no route (with drop on).
- [ ] Rollback: one patch cable — modem → TP-Link WAN, TP-Link back to
      router mode, its DHCP re-enabled. Ten seconds, everything recovers.

## Operations runbook

| Situation | Action |
|---|---|
| Add a device | ✅ in Telegram (or edit `gatekeeper.conf` + reload) |
| Revoke a device | Delete its `dhcp-host` line, reload |
| **See who's pending** | **Send `/pending` to the bot** — lists every device currently in the 192.168.214.* waiting room (claimed names/notes included) |
| **Deploy config from repo** | **First pull live → repo** (`sudo cp /etc/dnsmasq.d/gatekeeper.conf config/gatekeeper.conf` + fix ownership) — the doorbell appends to the LIVE copy; pushing repo → live blindly wipes decisions (bit us 2026-11-16 00:33) |
| PC rebooting | Devices keep leases (24h); doorbell/DNS-independent |
| PC down > lease time | Devices drop to APIPA; **emergency:** re-enable router DHCP |
| Something's broken | Rollback: router DHCP back on; dnsmasq off; nothing else affected |
| Phase 7 gateway box down (once live) | **One cable:** modem → TP-Link WAN; TP-Link back to router mode; re-enable its DHCP |

## Risks & accepted trade-offs

1. **PC is single point of failure** for new leases only (DNS is 1.1.1.1, not the PC). → becomes a full outage under Phase 7; rollback is one cable.
2. **Wired ports have no gate** on stock routers — treat LAN ports as physical access. → Phase 7 closes (NAT allowlist behind the gateway).
3. **MACs are spoofable** — allowlist + gatekeeper raise the bar, not a guarantee.
4. **IPv6 may bypass** the IPv4 gate (see Phase 6). → Phase 7 closes (v6 off/terminated at the gateway).
5. **Two DHCP servers = chaos** — the router's DHCP must stay off permanently.
6. **Tethering chains bypass the DHCP gate** — an approved device can run its own hotspot; NAT'd clients behind it never knock and stay invisible to the doorbell. Phase 7 makes them visible (tether jumps) and optionally unroutable.

## Layout

```
network-gatekeeper/
├── PLAN.md                    ← this file
├── CONTAINER.md               ← containerization plan (dnsmasq+doorbell+portal → Docker)
├── config/gatekeeper.conf     ← live-config snapshot (device lines are rendered)
├── config/gatekeeper.template ← static part of the dnsmasq config (hand-edited)
├── scripts/doorbell-dhcp.py   ← Telegram approve/deny doorbell (+ SQLite→conf renderer)
├── scripts/pending-portal.py  ← waiting-room captive portal
├── systemd/doorbell.service   ← runs the doorbell at boot
├── tests/test_render.py       ← offline renderer verification (no root, no live paths)
├── Dockerfile · docker-compose.yml · docker/supervisord-core.conf
└── scripts/{deploy,lab-test,cutover,rollback}.sh  ← sudo run order (CONTAINER.md)
```
