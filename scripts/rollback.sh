#!/usr/bin/env bash
# CONTAINER.md Phase 7 — back to the systemd world (rehearsed, <10 min).
# Works at any point after cutover.sh; the config format is unchanged by
# the renderer, so the systemd stack resumes without edits.
set -euo pipefail
cd "$(dirname "$0")/.."
[ "$(id -u)" -eq 0 ] || { echo "run with sudo"; exit 1; }

TS=$(date +%F-%H%M)
echo "== rollback to systemd ($TS) =="

echo "1/4 stopping the containers"
docker compose down

echo "2/4 adopting the container-era leasefile (it holds the newest leases)"
cp leases/dnsmasq.leases /var/lib/misc/dnsmasq.leases
if [ -f state/gatekeeper.db ]; then
  cp state/gatekeeper.db /var/lib/gatekeeper/gatekeeper.db
  echo "   (audit DB carried back too — decisions survive the round trip)"
fi

echo "3/4 re-enabling the systemd stack"
systemctl enable --now dnsmasq doorbell pending-portal
sleep 3

echo "4/4 status:"
systemctl is-active dnsmasq doorbell pending-portal
echo
echo "Verify: an approved device renews (journalctl -u dnsmasq -f shows DHCPACK)."
echo "The doorbell keeps working from /opt/doorbell/doorbell.py — the rendered"
echo "config format is identical, so nothing else needs restoring."
