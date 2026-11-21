# Network Gatekeeper — Admin Page (acceptance criteria)

> **Status (2026-11-21):** **implemented** — decision cores + card registry
> + admin server inside doorbell-dhcp.py, page at
> scripts/admin-page.html, offline verification in tests/test_admin.py
> (all green; tests/test_render.py unaffected). Guest passes are 4/12/24 h
> (full Telegram parity). **The live gate is the container world**
> (cutover ~2026-11-17), so deployment = `sudo docker compose build core
> && sudo docker compose up -d core` with the ADMIN_* knobs in
> /etc/doorbell.env (the compose `env_file:`; unset token = disabled).
> Remaining: VER-2 lab matrix on the veth rig; VER-4 go-live via the
> tunnel; record the SEC-8 bind decision when you make it.
>
> **Scope settled:** full action parity with the Telegram buttons · reachable
> on the approved subnet (`192.168.213.x`) and via the Cloudflare tunnel at
> `apis.adolfrey.com/*` (alias: `apps.adolfrey.com`) · logs = SQLite events +
> doorbell + dnsmasq.

**User stories covered** (from the original three bullets):

| Bullet | Becomes |
|---|---|
| "currently added / expiry" | Roster view: every recorded device, its decision, and expiry (§ Views) |
| "change decisions, update names" | Action parity: the page can do everything the Telegram buttons do (§ Actions) |
| "logs" | Three-source log view (§ Logs) |

---

## Design invariants (non-negotiable)

These aren't features — they're properties the existing gate already has that
this page must not break.

| ID | Invariant | Why |
|---|---|---|
| INV-1 | **Single writer.** The only process that writes SQLite or renders `gatekeeper.conf` stays the doorbell. Web actions call the *same functions* the Telegram callbacks call (`db_set_binding` → `render_and_apply` → `purge_leases` → `db_event` → Telegram card). No SQL from the page, no second renderer, no conf edits. | The renderer/conf/audit coupling is the whole point of Phase 2 (CONTAINER.md); a second writer recreates the overwrite-incident class |
| INV-2 | **Admin server is a thread in the doorbell process** — same pattern as the claim relay (`claim_server`, doorbell-dhcp.py:922). Binds `ADMIN_BIND:ADMIN_PORT` (env), default `127.0.0.1:8340`. **Must never bind `0.0.0.0` or `192.168.214.2`** — the latter is the untrusted waiting room. | Keeps one writer (INV-1) with zero new IPC; the waiting-room roster and `temp_queue` live in doorbell memory and must not be duplicated |
| INV-3 | **Portal untouched.** `pending-portal.py` and its compose service are unchanged. | The portal is the deliberately least-privileged reader (CONTAINER.md decision table) |
| INV-4 | **Crash isolation.** A dead or hung admin thread must not affect DHCP sniffing, dnsmasq signaling, rendering, or the claim relay. Handler exceptions are logged and swallowed, never propagated into core loops. | The page is the newest, most exposed code; the gate must not feel it |
| INV-5 | **Kill switch.** If `ADMIN_TOKEN` is unset, the admin thread never starts (one log line: `admin disabled — set ADMIN_TOKEN`); everything else runs normally. | Zero-cost opt-out, and a documented rollback for any admin-page incident |

---

## Access & security

The page is internet-reachable through Cloudflare → **treat every request as
hostile**, including ones that didn't come through Cloudflare.

| ID | Criterion |
|---|---|
| SEC-1 | **Auth is mandatory, not optional.** Every route (pages and JSON) requires the token — `Authorization: Bearer <ADMIN_TOKEN>` — compared in constant time. Missing/wrong → `401`. The token never appears in URLs, query strings, or log lines. Rationale: binding to `213.x` means every *approved* device (IoT included) can reach the port directly, bypassing Cloudflare. |
| SEC-2 | Failed-auth attempts rate-limited per source IP (5/min suggested) → `429` with no body difference from `403`. |
| SEC-3 | Inputs strictly validated server-side: MAC = `^[0-9a-f]{2}(:[0-9a-f]{2}){5}$` (normalized lowercase), action = fixed allowlist, guest-pass duration = fixed set {4h, 12h}, names via the existing `clean_name`. Unknown fields rejected, not ignored. |
| SEC-4 | All HTML output escaped; JSON served with correct `Content-Type`. Device-supplied strings (hostnames, claims, notes) can never inject markup into the page. |
| SEC-5 | The Cloudflare tunnel (cloudflared on the gate host) routes to the admin bind **only**. The portal (214.2), dnsmasq ports, and the claim relay are never in the tunnel config. Recommended: Cloudflare Access in front; SEC-1 stays regardless (defense in depth). |
| SEC-6 | Startup self-check: if `ADMIN_BIND` is `0.0.0.0` or `192.168.214.2`, the admin thread refuses to start and logs why (gate keeps running). |
| SEC-7 | **Browser auth is a flow, not a header.** Browsers can't send Bearer headers on navigation: the page offers a token login form → the server sets a signed, HttpOnly, `SameSite=Strict` session cookie (short TTL, 12 h suggested); every POST additionally requires an Origin check against the configured hostname allowlist (`ADMIN_HOSTS`). Constant-time compare applies at login; programmatic/automation access keeps the Bearer header. |
| SEC-8 | **Transport decision — RECORDED (2026-11-21):** the admin binds the **Caddy proxy network's gateway IP** (`ADMIN_BIND=172.20.0.1`), not the LAN. Reachability: the host itself + containers on the `proxy` network (Caddy) — and, because the host routes for them, approved-subnet clients could address the gateway IP directly too; the token + rate limit remain the guard. TLS is terminated at Cloudflare → cloudflared → Caddy, so browser-to-host traffic is encrypted the whole way; Caddy→doorbell is a plain hop across the host's own bridge. LAN clients hitting `https://apis.adolfrey.com` on 443 directly fall into the portal catch-all site, not the admin — so in practice the page is **tunnel-only**, with loopback for debugging. |

---

## Views

| ID | Criterion |
|---|---|
| V-1 | **Roster.** Table of every device in `bindings` + `devices`: MAC, label/note, status (approved / denied / temp / raw), reserved IP, `since`, lease spec, and **expiry**: for temp bindings a live countdown from `bindings.expires`; for approved devices the remaining lease time from the leasefile when a live lease exists. |
| V-2 | **Waiting room.** Current knocks with age and claimed name (what `send_waiting_roster` sends), self-refreshing. Empty state says so. |
| V-3 | **Search/filter** by MAC, name, or status; sort newest-activity first. |
| V-4 | **Device detail.** Per-device history: all `events` rows for that MAC, newest first, paginated (50/page). |
| V-5 | **Summary strip.** Counts (approved / denied / temp / waiting), free IPs in the reserved pool (`IP_MAX − highest allocated`), and liveness: dnsmasq + doorbell last-log-line age, green/red. |
| V-6 | Roster and waiting room reflect DB/memory state on every load — **no optimistic client-side state**; the page re-reads after every action. |
| V-7 | **Phone-first layout.** The admin's primary client is the same phone that gets the Telegram cards — roster, waiting room, and action buttons must be usable at ~390 px width with no horizontal scroll. |

---

## Actions (full parity with Telegram buttons)

Every action goes through the same code path as its Telegram twin
(INV-1). Semantics identical — including failure rollback.

| ID | Criterion |
|---|---|
| ACT-1 | **Approve**: allocates next free IP (`next_free_ip`), records the binding, renders + reloads, purges a 214.x lease if reload succeeded, writes the `approve` event, **and still sends the Telegram card** (the phone stays the pager). |
| ACT-2 | **Deny**: records deny binding, purges 213.x lease on reload, `deny` event, Telegram card. |
| ACT-3 | **Guest pass 4h / 12h / 24h**: same as `allow4`/`allow12`/`allow24` — `expires` stored, `temp_queue` armed so the existing expiry sweep revokes it; V-1 countdown reflects it. The event detail keeps its machine-readable `ip until ts` shape (with an optional ` via web` suffix both parsers tolerate). |
| ACT-4 | **Undo**: back to pending, re-render, purge. |
| ACT-5 | **Skip**: drop from the waiting-room roster. |
| ACT-6 | **Actions work on any known MAC, not just live knocks** — flip deny→approve or approve→deny for a device that isn't knocking right now. This is the one capability beyond the Telegram surface (buttons only exist on fresh knock cards); semantics = "pressing that device's old card again." |
| ACT-7 | **Rename/note**: `clean_name` → `db_set_note` + `note` event + marker-comment update, no reload (device lines unchanged). Same validation and persistence as the Telegram 📝 flow. |
| ACT-8 | **Web + Telegram concurrently**: both entry points serialize through the same lock the callbacks use; no lost updates; both actions appear in `events` in order. |
| ACT-9 | **Provenance**: every web-sourced event carries a `via web` marker in `detail` — the audit trail always shows *which surface* made the decision. |
| ACT-10 | **Failure UX**: pool full / DB write failed / conf write failed / reload failed each produce a distinct, human-readable error on the page — and leave state exactly as before the click (the existing pattern: clear the binding if the render fails). |
| ACT-11 | Write endpoints are POST only; GET never mutates. |
| ACT-12 | **Cross-surface invalidation.** A web decision must strip the ✅/🚫 buttons from that device's Telegram knock card and drop it from the waiting roster. Today `clear_buttons()` (doorbell-dhcp.py:649) only knows the tapped callback's own message — a web approve would leave live buttons on the phone, and tapping a stale ✅ would allocate a **second** reserved IP. Requires a mac → message_id card registry; pressing a stale card after a web decision must be a harmless no-op ("already decided via web"). |

---

## Logs

| ID | Criterion |
|---|---|
| L-1 | **Events view**: the SQLite audit trail — filter by kind and/or MAC, newest first, paginated. Read-only. |
| L-2 | **dnsmasq tail**: last N lines (200 suggested) of `LOG_DIR/dnsmasq.log`, auto-refresh. Read-only, bounded read (seek-to-end, not whole-file). |
| L-3 | **Doorbell tail**: `log()` gains a second sink — the file `LOG_DIR/doorbell.log` (the `./log` volume is already mounted, so lines are host-visible too). Bounded: truncated on doorbell start. Restart clearing it is accepted and documented. |
| L-4 | All log output escaped (L-4 same threat as SEC-4 — device-supplied names flow into logs). |
| L-5 | Timestamps displayed in local time; the source (DB ISO string vs log line) is visually distinguished, not silently mixed. |

---

## Degradation & failure modes

| ID | Criterion |
|---|---|
| F-1 | SQLite busy during a read → the view returns an error banner, not a crash (WAL readers; writer lock is brief). |
| F-2 | Conf write fails mid-action → ACT-10 rollback holds; conf file unchanged (`os.replace` atomicity already guaranteed). |
| F-3 | dnsmasq down → summary strip shows red; actions still record, with the same "reload FAILED" warning path Telegram uses. |
| F-4 | Admin thread dies or wedges → gate unaffected (INV-4); page 502s through the tunnel; recovery = doorbell restart (documented, rare). |

---

## Non-goals (v1)

- No user accounts/roles — one admin token.
- No lease editing, no template editing, **no direct conf editing** — the
  "generated, never hand-edit" runbook rule stays true; the page edits the DB
  and lets the renderer do its job.
- No changes to anything a waiting-room device sees (portal untouched, INV-3).
- No backup/restore UI.

---

## Verification plan

Same discipline as the container migration: **lab first, live last**, every
check green before the next.

| ID | Check |
|---|---|
| VER-1 | **Unit** (`tests/test_admin.py`, alongside `test_render.py`): MAC validation, action allowlist, `clean_name` round-trip, constant-time token compare, auth-enforced routes. |
| VER-2 | **Lab (Phase 5 veth rig)** — full action matrix from the page: approve → rendered-conf byte-diff + HUP + lab client ACKs at its reserved IP; deny → lease evicted; guest pass → countdown ticks → sweep revokes; undo; rename → marker comment changes, no reload; web + scripted callback concurrently (ACT-8). |
| VER-3 | **Lab security**: curl without/with-wrong token from the lab netns → 401 (proves the pending path can't reach a decision even before auth); bind self-check refuses 214.2/0.0.0.0; rate limit trips to 429. |
| VER-4 | **Go-live**: tunnel up → one real approve via each configured hostname (`apis.adolfrey.com` *and* any alias like `apps.adolfrey.com`) → verify Telegram card + `events` row + lease change + V-1 countdown; then let it idle. Rollback = unset `ADMIN_TOKEN` (INV-5) or stop cloudflared; the gate never depends on the page being up. |
| VER-5 | **Cross-surface + regression:** after a web approve, tapping the old Telegram ✅ is a harmless no-op with an explanatory message; the claim relay still binds `127.0.0.1` only — trivial to accidentally widen while touching the doorbell's HTTP code, so assert it in a unit test. |

---

## New env knobs

| Var | Default | Notes |
|---|---|---|
| `ADMIN_BIND` | `127.0.0.1` | **Comma-separated list** — one listener per address, each SEC-6-checked independently (a refused/late-appearing address never blocks the others; the per-bind retry means a secondary IP added later comes up without a restart). Live: `172.20.0.1,192.168.213.2` — never `0.0.0.0` / `214.2` |
| `ADMIN_PORT` | `8340` | No clash with CLAIM_PORT 8333 / lab 8334 |
| `ADMIN_TOKEN` | *(unset)* | Unset ⇒ admin disabled (INV-5); lives in `/etc/doorbell.env` next to the Telegram secrets; rotation = edit the file + doorbell restart |
| `ADMIN_HOSTS` | *(unset)* | Comma-separated hostname allowlist for Origin/Host checks, e.g. `apis.adolfrey.com,apps.adolfrey.com`. Unset ⇒ only direct bind-address access (loopback / 213.x forms) is accepted; any tunnel hostname must be listed explicitly |
| `DOORBELL_LOG` | `<LOG_FILE dir>/doorbell.log` | The doorbell's second log sink (L-3) — truncated on start; joins the dnsmasq log in `./log` (no separate LOG_DIR knob: the sink always lives beside LOG_FILE) |

---

## Out-of-repo dependency: cloudflared + Caddy

The tunnel is part of the **deployment**, not of the gate — it must never sit
in the critical path (tunnel down ⇒ gate fully functional, page 502s).

**Recorded routing (2026-11-21):** the admin rides the existing stack instead
of a dedicated tunnel:

```
browser ─TLS─ Cloudflare ─ cloudflared ─ 127.0.0.1:8080 (caddy)
       ─ caddy http://apis.adolfrey.com, path /gatekeeper/* ─ 172.20.0.1:8340 (doorbell)
```

- `cloudflared` already exists in the Caddy stack (native, targets
  `127.0.0.1:8080`); no new tunnel, no new DNS. `apps.adolfrey.com` works
  automatically (same Caddy site block; sessions stay per-hostname, SEC-7).
- **Why the gateway IP:** `gatekeeper-core` is `network_mode: host`, and
  Docker forbids host-mode containers from joining bridge networks — so the
  doorbell cannot appear as `gatekeeper:8340` on `proxy`. Binding the
  network's gateway address gives Caddy (and only that network) a route in.
  The bind waits and retries if the gate boots before the network exists.
- The page uses **relative** fetch paths, so `handle_path /gatekeeper/*`
  (prefix-stripping) works; it equally works at the bare root for debugging.
- **Direct LAN access (recorded 2026-11-21):** `ADMIN_BIND` also carries the
  gate's own LAN address `192.168.213.2`, so `http://192.168.213.2:8340`
  serves the page on the approved subnet without the tunnel. Trade-off
  accepted and noted: that hop is plaintext HTTP on 213.x (token/cookie
  sniffable by any approved device — home LAN, one admin); waiting-room
  devices have no route to 213.x and stay excluded; token + rate limit
  remain the guard. Same-origin (Origin = `http://192.168.213.2:8340`)
  is in the SEC-7 allowed set automatically via the bind list.
- Config lives in `/opt/caddy/Caddyfile` + `/etc/doorbell.env` (root-only,
  not in this repo). Disabling the page remotely = stop cloudflared or unset
  `ADMIN_TOKEN`; the gate never depends on either.
