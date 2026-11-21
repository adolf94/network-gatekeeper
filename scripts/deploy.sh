#!/usr/bin/env bash
# Deploy the render-capable doorbell (CONTAINER.md Phases 1–2) to the LIVE
# systemd stack. This is the soak step BEFORE any containerization — the
# container cutover is a separate, later script (cutover.sh).
#
# What it does:
#   1. pulls the live config into the repo first (the runbook rule — the
#      live copy has doorbell-written lines the repo copy may lack),
#   2. installs the new doorbell + the static config template,
#   3. restarts the doorbell service.
# The first render on the host is a no-op for dnsmasq: the migrated bindings
# re-render the same device lines, and the doorbell only reloads dnsmasq
# when the line set actually changes (verified by tests/test_render.py).
set -euo pipefail
cd "$(dirname "$0")/.."
[ "$(id -u)" -eq 0 ] || { echo "run with sudo"; exit 1; }

# Coincidence guard (CONTAINER.md risk #5): this script deploys to the
# SYSTEMD world. If the container world is live, deploying here re-activates
# the old doorbell → two Telegram pollers (409 conflicts) and decisions
# written into the dead world's conf/DB. Post-cutover deploys go via Docker.
if command -v docker >/dev/null 2>&1 \
        && [ -n "$(docker ps --filter name=gatekeeper-core \
                          --filter status=running -q 2>/dev/null)" ]; then
  echo "REFUSING: the container world is live (gatekeeper-core is running)."
  echo "Deploy the new code the cutover way instead:"
  echo "  sudo docker compose build core && sudo docker compose up -d core"
  echo "(then re-do any decision that was recorded against the systemd world)."
  exit 1
fi

TS=$(date +%F-%H%M)

echo "== doorbell deploy $TS =="
echo "1/4 pulling live state → repo (runbook rule; container cutover needs this too)"
cp /etc/dnsmasq.d/gatekeeper.conf "backup/deploy-$TS-gatekeeper.conf" 2>/dev/null || mkdir -p backup
cp /etc/dnsmasq.d/gatekeeper.conf config/gatekeeper.conf
cp /opt/doorbell/doorbell.py "backup/deploy-$TS-doorbell.py"

echo "2/4 installing doorbell + template"
install -m 700 scripts/doorbell-dhcp.py /opt/doorbell/doorbell.py
install -m 644 scripts/admin-page.html /opt/doorbell/admin-page.html
install -m 644 config/gatekeeper.template /etc/dnsmasq.d/gatekeeper.template

echo "3/4 restarting the doorbell service"
systemctl restart doorbell
sleep 2

echo "4/4 recent doorbell journal (expect a migrate/render line, no errors):"
journalctl -u doorbell -n 12 --no-pager

echo
echo "Live device lines now: $(grep -c '^dhcp-host=' /etc/dnsmasq.d/gatekeeper.conf || true)"
echo "Rollback: sudo cp backup/deploy-$TS-doorbell.py /opt/doorbell/doorbell.py && sudo systemctl restart doorbell"
