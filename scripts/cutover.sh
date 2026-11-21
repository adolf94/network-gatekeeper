#!/usr/bin/env bash
# CONTAINER.md Phase 6 — switch the gate from systemd to Docker.
# Preconditions (check before running):
#   * Phase 5 lab matrix green (sudo ./scripts/lab-test.sh)
#   * docker + compose healthy (docker info)
#   * deploy.sh already ran (rendered doorbell soaked on systemd) — but the
#     container migrates on first boot even if it didn't, so not fatal.
#
# Ordering notes:
#   * disable, never just stop — two DHCP servers = chaos (PLAN.md risk 5)
#   * the DB is copied AFTER the doorbell stops (no WAL race)
#   * the leasefile is copied while dnsmasq is down (it rewrites the file)
#   * approved devices hold 24 h leases: the dnsmasq-down window is invisible
#     to them; only 2-min waiting-room guests would briefly slip to APIPA.
set -euo pipefail
cd "$(dirname "$0")/.."
[ "$(id -u)" -eq 0 ] || { echo "run with sudo"; exit 1; }
docker info >/dev/null 2>&1 || { echo "docker daemon not healthy"; exit 1; }

TS=$(date +%F-%H%M)
mkdir -p "backup/$TS" config leases state log

echo "== cutover to containers ($TS) =="

echo "1/7 backups + pull live conf → repo (the container will mount ./config)"
cp /etc/dnsmasq.d/gatekeeper.conf       "backup/$TS/gatekeeper.conf"
cp /etc/dnsmasq.d/gatekeeper.conf       config/gatekeeper.conf
[ -f /etc/dnsmasq.d/gatekeeper.template ] \
  && cp /etc/dnsmasq.d/gatekeeper.template "backup/$TS/" || true
cp /var/lib/misc/dnsmasq.leases         "backup/$TS/dnsmasq.leases"
[ -f /var/lib/gatekeeper/gatekeeper.db ] \
  && cp /var/lib/gatekeeper/gatekeeper.db "backup/$TS/" || true

echo "2/7 disabling the systemd doorbell + portal (writers go first)"
systemctl disable --now doorbell pending-portal

echo "3/7 checkpointing SQLite and copying the DB → ./state"
if [ -f /var/lib/gatekeeper/gatekeeper.db ]; then
  sqlite3 /var/lib/gatekeeper/gatekeeper.db "PRAGMA wal_checkpoint(TRUNCATE);" || true
  cp /var/lib/gatekeeper/gatekeeper.db state/
  [ -f /var/lib/gatekeeper/gatekeeper.db-wal ] \
    && cp /var/lib/gatekeeper/gatekeeper.db-wal state/ || true
else
  echo "   no live DB — the container will migrate bindings from the conf"
fi

echo "4/7 stopping systemd dnsmasq (brief window; 24h leases cover us)"
systemctl stop dnsmasq

echo "5/7 migrating the leasefile so approved devices keep their leases"
cp /var/lib/misc/dnsmasq.leases leases/dnsmasq.leases

echo "6/7 disabling dnsmasq unit and starting the containers"
systemctl disable dnsmasq
docker compose build
docker compose up -d
sleep 5
docker compose ps

echo "7/7 first boot of gatekeeper-core:"
docker logs --tail 25 gatekeeper-core 2>&1 || true

cat <<'EOF'

== live checks (manual) ==
  docker logs -f gatekeeper-core        # expect: template, migrate, render,
                                        # "doorbell up", sniff listening
  docker logs -f gatekeeper-portal      # portal serving on 192.168.214.2:80
  /pending in Telegram                  # waiting room still listed
  throwaway phone: knock card → ✅ → reserved IP within ~2 min
  IPv6 still closed: ip -6 addr show wlx40a5ef262b87   (no global 2xxx:)
Rollback at any point: sudo ./scripts/rollback.sh
EOF
