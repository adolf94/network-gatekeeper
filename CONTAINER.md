# Network Gatekeeper — Containerization Plan

> **Status (2026-11-21):** Phases 1–6 are DONE — the container world is
> LIVE (cutover ~2026-11-17: `gatekeeper-core` + `gatekeeper-portal` on
> `docker ps`; systemd units disabled). Phases 5/6 scripts remain for
> lab/rollback reference. **Post-cutover code deploys go through Docker**
> (`docker compose pull && up -d` — image built by GitHub Actions and
> pushed to GHCR; deploys are MANUALLY GATED — workflow_dispatch with
> deploy=true; a push to master only builds/pushes so the DHCP front door
> never redeploys as a side effect, runbook below) —
> `deploy.sh`
> now refuses to run while the container world is live (a systemd-side
> deploy re-activates the old doorbell: two Telegram pollers = 409
> conflicts, decisions land in the dead world's conf/DB — verified the
> hard way 2026-11-21).

**Goal:** move the gate stack (dnsmasq + doorbell + pending-portal) from three
systemd units into Docker — with zero DHCP downtime and no loss of decisions.

**Governing principle:** the gate is the network's front door. Every phase ends
in a verified state; the risky step (cutover) is one short, rehearsed sequence
with a 10-minute rollback. Code changes land and soak **on systemd first** —
the container then just re-hosts already-proven code.

---

## Decisions made (final design)

| Concern | Decision | Why |
|---|---|---|
| Network mode | `network_mode: host` — mandatory | Gate NIC is Wi-Fi: macvlan/bridge needs 4addr mode consumer APs don't do; DHCP broadcast + AF_PACKET sniff + portal binding host-owned `192.168.214.2` all assume the host netns |
| Container split | **Two** containers, both host-net: `gatekeeper-core` (dnsmasq + doorbell) and `pending-portal` | dnsmasq & doorbell are surgery-coupled (same conf, same leasefile, live signal path); portal is the least-privileged reader → keep its isolation (CAP_NET_BIND_SERVICE only, read-only mounts), mirroring today's `DynamicUser` unit |
| Supervisor (inside core) | `supervisord` (apt) | Python already in image; `supervisorctl signal HUP / restart` maps 1:1 to `systemctl reload / restart`. Alternative noted: s6-overlay |
| Base image | `ubuntu:24.04` | Mint 22 host ⇒ dnsmasq version parity (2.90.x vs host's 2.91); python3 included |
| Config source of truth | **SQLite `devices` table → rendered `gatekeeper.conf`** | Kills the overwrite-incident class (2026-11-16 00:33) permanently; repo copy becomes an artifact |
| State on host | Bind-mounted **directories**, never single files | dnsmasq rewrites the leasefile; single-file mounts go stale on inode replacement |
| Leasefile trick | Mount host `./leases` dir *at* `/var/lib/misc` in the container | `dhcp-leasefile=/var/lib/misc/dnsmasq.leases` in the conf stays valid in both worlds |
| Restart policy | `restart: unless-stopped`, dockerd enabled at boot | Approved leases are 24 h — seconds of boot delay are invisible; only 2-min waiting-room guests notice |
| Coincidence guard | systemd units `disable --now` (not just stop) at cutover | Two DHCP servers = chaos (PLAN.md risk #5) |

**Already free** (verified in code): both scripts read every path/port from env —
`IFACE, CONFIG, LEASEFILE, DB, CLAIM_PORT, PORTAL_BIND, PORTAL_PORT,
TELEGRAM_*` (doorbell 43–56, portal 27–31). Only **three call sites** are
hardwired to systemd/journald.

---

## Phase 0 — Prep & freeze

- [ ] `docker --version && docker compose version && docker info` — daemon healthy.
- [ ] Backups: `cp /var/lib/misc/dnsmasq.leases`, `/etc/dnsmasq.d/gatekeeper.conf`,
      `/var/lib/gatekeeper/gatekeeper.db` into `./backup/$(date +%F)/`.
- [ ] **Pull live → repo** (runbook rule): conf currently has doorbell-written
      lines the repo copy may lack. Diff `config/gatekeeper.conf` vs live, reconcile.
- [ ] Record checksums of conf + leasefile for the cutover diff later.

## Phase 1 — Code: swap the 3 systemd couplings for env-selectable ones

Small, behavior-preserving on host (defaults = today's behavior):

- [ ] `doorbell-dhcp.py:256` `reload_dnsmasq()`: replace hardcoded
      `systemctl reload dnsmasq` with `DNMSQ_RELOAD` env
      (default `systemctl reload dnsmasq`; container: `supervisorctl signal HUP dnsmasq`).
- [ ] `doorbell-dhcp.py:671` `signal_dnsmasq()`: same pattern for the **full
      restart** used by `purge_leases` (SIGHUP does NOT re-read the lease DB —
      verified in PLAN.md; container: `supervisorctl restart dnsmasq`).
- [ ] `doorbell-dhcp.py:865` journal tail: `LOG_SOURCE` env — `journal` (default,
      unchanged `journalctl -u dnsmasq -f -n 0 --output=cat`) or `file` +
      `LOG_FILE` (container: dnsmasq `log-facility=/var/log/dnsmasq.log`).
- [ ] Verify on host: one approve + one deny round-trip behaves identically
      (conf diff, Telegram cards, SQLite events). Soak overnight before Phase 2.

## Phase 2 — SQLite as source of truth + conf renderer

The doorbell already records every decision (`approve/deny/allow/note` events,
`devices` rollup, guest-pass `allow` events survive restarts). Make the file
derived, not authoritative:

- [ ] Renderer inside the doorbell process (single writer — no cross-process
      SQLite locking): hand-edited **base template** (interface, ranges, DHCP
      options, portal DNS) + dynamic section rendered from `devices`.
- [ ] Atomic write: render → temp file → `os.replace()` — dnsmasq never reads a
      half-written conf. Reload only when content actually changed (checksum).
- [ ] `append_host_line` / `remove_host_lines` retire; approve/deny/guest-pass/
      note become DB writes + re-render. Guest-pass expiry → timer re-render.
- [ ] Keep the rendered file **grep-compatible** — portal's `mac_state()`
      (`pending-portal.py:93`) still greps the conf; zero portal changes.
- [ ] Repo `config/gatekeeper.conf` becomes an artifact (generated, committed
      for reference). The pull-first runbook rule is retired — that's the payoff.
- [ ] Verify on host (systemd still): full knock → claim → approve → guest-pass
      → deny → undo cycle; rendered conf byte-diff vs previous live conf = only
      the lines that decision cycle would have written.

## Phase 3 — Image

- [ ] `Dockerfile` on `ubuntu:24.04`: `apt-get install dnsmasq supervisor`,
      copy the two scripts, create users (`doorbell`, `dnsmasq`-style drop),
      supervisord ini for `dnsmasq` + `doorbell` programs (autorestart).
- [ ] Sanity: `dnsmasq --test` inside image; version `dnsmasq -v` vs host (2.91).
- [ ] Optional healthcheck: `pgrep dnsmasq` (liveness only; config test is not
      a liveness check).

## Phase 4 — Compose

```yaml
services:
  core:
    build: .
    network_mode: host                      # mandatory — see Decisions
    restart: unless-stopped
    cap_add: [NET_ADMIN, NET_RAW, NET_BIND_SERVICE]
    environment:
      IFACE: wlx40a5ef262b87
      DNMSQ_RELOAD:  supervisorctl signal HUP dnsmasq
      DNMSQ_RESTART: supervisorctl restart dnsmasq
      LOG_SOURCE: file
      LOG_FILE: /var/log/dnsmasq.log
    volumes:
      - ./config:/etc/dnsmasq.d            # rendered conf (doorbell writes)
      - ./leases:/var/lib/misc             # leasefile path unchanged
      - ./state:/var/lib/gatekeeper        # SQLite audit trail
      - ./log:/var/log
    logging: {driver: json-file, options: {max-size: 10m, max-file: "3"}}

  portal:
    build: .
    network_mode: host                     # shares host loopback → 127.0.0.1:8333 relay
    restart: unless-stopped
    cap_add: [NET_BIND_SERVICE]
    read_only: true
    volumes:
      - ./config:/etc/dnsmasq.d:ro
      - ./leases:/var/lib/misc:ro
    environment:
      PORTAL_BIND: 192.168.214.2
    logging: {driver: json-file, options: {max-size: 5m, max-file: "3"}}
```

- [ ] Note: `bind-dynamic` + `except-interface=lo` in the conf behave identically
      in the host netns; systemd-resolved keeps 127.0.0.53 — no clash.
- [ ] Docker's `FORWARD DROP` is irrelevant (PC isn't a router) — verify once
      with `iptables -S | grep -i docker`, move on.

## Phase 5 — Lab test on a veth pair (zero Wi-Fi risk)

A real DHCP integration test without touching the LAN. **Stop the systemd
dnsmasq for the lab window** — approved devices hold 24 h leases, hours of
slack; restart it after. Lab env keeps it fully disjoint from production:
lab conf/lease/DB dirs, `IFACE=veth-host`, `CLAIM_PORT=8334`,
`PORTAL_BIND=<lab-ip>`, `PORTAL_PORT=8080` (env support already exists).

```bash
ip netns add dhcplab
ip link add veth-host type veth peer name veth-lab
ip link set veth-lab netns dhcplab
ip addr add 192.168.213.2/24 dev veth-host && ip addr add 192.168.214.2/24 dev veth-host
ip link set veth-host up
ip netns exec dhcplab ip link set lo up && ip netns exec dhcplab ip link set veth-lab up
```

- [ ] Approved lease: lab `dhcp-host` entry → `dhclient -d veth-lab` (in netns)
      → DHCPACK, leasefile entry written, renderer idempotent.
- [ ] Pending path: unknown MAC → `192.168.214.1xx` 2-min lease, option 3
      suppressed, `dig @<lab-ip> anything` → portal IP (hijack works).
- [ ] Portal: `curl http://<lab-ip>/` → pending page; `/status` JSON correct for
      pending / approved / denied MACs.
- [ ] Doorbell end-to-end: knock card arrives (AF_PACKET on veth works in host
      netns), ✅ approve → re-render → HUP → next DISCOVER gets reserved IP;
      purge path evicts the 214.x lease + **supervisor restart** fires.
- [ ] Deny + undo: `ignore` line rendered, eviction, ↩️ undo returns to pending.
- [ ] Claim relay: portal POST name → `🙋 Device: … says: …` in Telegram
      (CLAIM_PORT 8334, no clash with the real doorbell).
- [ ] Guest pass renders its 15-min temp line; skip the 15-min wait, verify the
      event + rendered output.

## Phase 6 — Cutover (short, rehearsed)

- [ ] Preconditions: Phase 5 matrix green; fresh backups; lab containers down.
- [ ] Stop systemd dnsmasq → `cp /var/lib/misc/dnsmasq.leases ./leases/`
      (**lease migration — approved devices must keep their 24 h leases**).
- [ ] `systemctl disable --now doorbell pending-portal dnsmasq` (disable, not stop).
- [ ] `docker compose up -d` → `docker compose ps`, `docker logs core`.
- [ ] Verify: S24 renews into its reserved IP; throwaway phone knock → waiting
      room → portal page → Telegram card → approve → hops to reserved IP
      within ~2 min (no Forget/rejoin — purge+restart already proven).
- [ ] `sqlite3 state/gatekeeper.db …ORDER BY id DESC` — events flowing; deny a
      throwaway device once to prove the closed path live.
- [ ] IPv6 re-check from CONTAINER work: `ip -6 addr show wlx…` — still no
      global v6 (router v6 off, verified 2026-11-16); gap stays closed.

## Phase 7 — Soak & rollback

- [ ] 48 h soak: journal event stream == pre-cutover patterns (knocks, NAKs,
      purges); no APIPA among approved devices (`ip neigh` check).
- [ ] **Rollback** (any point): `docker compose down` → restore leasefile from
      `./leases/` if container wrote newer leases →
      `systemctl enable --now dnsmasq doorbell pending-portal` →
      verify one device renews. Conf format unchanged by Phase 2, so systemd
      world resumes without edits. Target: under 10 minutes, rehearsed once.

## Runbook additions (post-cutover)

| Situation | Action |
|---|---|
| Deploy a code change | Push to master — Actions tests → builds → pushes GHCR. Deploy via workflow_dispatch with `deploy=true` → gh_webhooks POSTs `/d` → `pull && up -d --no-deps --wait` here (manual fallback: `sudo docker compose pull && sudo docker compose up -d core`) |
| Deploy fails: "Conflict. The container name ... is already in use" | Containers from a *different* compose project hold the fixed `container_name`s (happened once, 2026-11-22: the pre-deploy checkout was its own project). One-time recreate: `docker compose down` in the old checkout (or `docker rm -f gatekeeper-core gatekeeper-portal`), then re-run the deploy. Seconds of dnsmasq-down — covered by the approved devices' 24 h leases. This deploy dir is now the canonical state home (`config/leases/state/log`) |
| Inspect DHCP logs | `docker logs -f core` (dnsmasq + doorbell) or `./log/dnsmasq.log` |
| Portal logs | `docker logs -f portal` |
| Editing device set | Via Telegram buttons only — the conf is generated; never hand-edit |
| Admin page | `ADMIN_TOKEN` and/or `ADMIN_BFF_SECRET` (OAuth, ADMIN.md SEC-9) in `/etc/doorbell.env`; the page is disabled only when BOTH are unset. Web layer: `scripts/admin_web.py` (lazy fastapi/uvicorn in the doorbell process) |
| docker broken | `systemctl restart docker`; if wedged → rollback sequence above |
| PC reboot | dockerd + `unless-stopped` bring the gate back; approved leases unaffected |

## Risks & accepted trade-offs

1. **dockerd joins the critical path** — new failure mode alongside "PC down";
   rollback (router DHCP on) unchanged and still covers it.
2. **Hardening regresses partially** — caps replace DynamicUser; portal keeps
   read-only + bind-service-only. Accepted for core.
3. **Supervisord adds an init layer** — small, boring, apt-packaged; s6 is the
   alternative if supervisord misbehaves.
4. **Renderer bugs = gate bugs** — mitigated by Phase 2's byte-diff verification
   and Phase 5's full decision-cycle test before any cutover.
5. **Two DHCP servers = chaos** — the coincidence guard (disable, not stop) is
   the single most important cutover step.
