#!/usr/bin/env bash
# CONTAINER.md Phase 5 — full gate matrix on a veth pair, zero Wi-Fi risk.
#
# A network namespace + veth pair stands in for the LAN; the container stack
# serves DHCP/DNS/portal on it exactly as it would on the real NIC. The live
# stack takes a break for the window (approved devices hold 24h leases —
# they won't notice; teardown always restores whatever was running).
#
# Two test identities:
#   aa:bb:cc:dd:ee:01  pre-approved  → must get 192.168.213.20
#   aa:bb:cc:dd:ee:02  walk-in       → pending room, then Telegram-driven
#                                      ✅ / ↩️ / 🚫 round-trips (real buttons)
#
# Telegram messages during the lab are REAL but labelled `iface veth-host`.
set -euo pipefail
cd "$(dirname "$0")/.."
[ "$(id -u)" -eq 0 ] || { echo "run with sudo"; exit 1; }

for tool in docker ip dhclient curl; do
  command -v "$tool" >/dev/null || { echo "missing: $tool"; exit 1; }
done
[ -f /etc/doorbell.env ] || { echo "/etc/doorbell.env missing — no Telegram in lab"; exit 1; }

LAB=lab
M1=aa:bb:cc:dd:ee:01          # pre-approved
M2=aa:bb:cc:dd:ee:02          # the walk-in
IP1=192.168.213.20
IP2=192.168.213.21            # next free — what ✅ should hand M2

WERE=$(for u in dnsmasq doorbell pending-portal; do systemctl is-active $u; done)
IFS=$'\n' read -rd '' -a WERE_ARR <<<"$WERE" || true
UNITS=(dnsmasq doorbell pending-portal)

cleanup() {
  docker rm -f gatekeeper-lab-core gatekeeper-lab-portal 2>/dev/null || true
  ip netns del dhcplab 2>/dev/null || true
  for i in 0 1 2; do
    u=${UNITS[$i]} ; was=${WERE_ARR[$i]:-inactive}
    if [ "$was" = active ]; then systemctl start "$u"; else systemctl stop "$u"; fi
  done
  echo "— lab torn down; systemd restored (was: dnsmasq=${WERE_ARR[0]:-?} doorbell=${WERE_ARR[1]:-?} portal=${WERE_ARR[2]:-?})"
}
trap cleanup EXIT

echo "== stopping the live stack for the lab window =="
for u in "${UNITS[@]}"; do systemctl stop "$u"; done

echo "== building the lab tree =="
rm -rf "$LAB"; mkdir -p "$LAB"/{config,leases,state,log}
# the template is the production one, pointed at the lab NIC:
sed 's/^interface=.*/interface=veth-host/' config/gatekeeper.template \
  > "$LAB/config/gatekeeper.template"
{
  cat "$LAB/config/gatekeeper.template"
  cat <<EOF

# ============================================================
# DEVICE LINES — GENERATED (lab seed)
# ============================================================
# approved by doorbell (lab seed)
dhcp-host=$M1,$IP1,labphone,24h
EOF
} > "$LAB/config/gatekeeper.conf"
: > "$LAB/leases/dnsmasq.leases"

echo "== veth pair + network namespace =="
ip netns add dhcplab
ip link add veth-host type veth peer name veth-lab
ip link set veth-lab netns dhcplab
ip addr add 192.168.213.2/24 dev veth-host
ip addr add 192.168.214.2/24 dev veth-host
ip link set veth-host up
ip netns exec dhcplab ip link set lo up
ip netns exec dhcplab ip link set veth-lab address "$M1"
ip netns exec dhcplab ip link set veth-lab up

echo "== starting the lab containers =="
docker rm -f gatekeeper-lab-core gatekeeper-lab-portal 2>/dev/null || true
docker run -d --name gatekeeper-lab-core --network host \
  --cap-add NET_ADMIN --cap-add NET_RAW --cap-add NET_BIND_SERVICE \
  --env-file /etc/doorbell.env \
  -e IFACE=veth-host \
  -e DNMSQ_RELOAD="supervisorctl -c /etc/supervisor/conf.d/gatekeeper-core.conf signal HUP dnsmasq" \
  -e DNMSQ_RESTART="supervisorctl -c /etc/supervisor/conf.d/gatekeeper-core.conf restart dnsmasq" \
  -e LOG_SOURCE=file -e LOG_FILE=/var/log/gatekeeper/dnsmasq.log \
  -v "$PWD/$LAB/config:/etc/dnsmasq.d" \
  -v "$PWD/$LAB/leases:/var/lib/misc" \
  -v "$PWD/$LAB/state:/var/lib/gatekeeper" \
  -v "$PWD/$LAB/log:/var/log/gatekeeper" \
  gatekeeper-core:latest
docker run -d --name gatekeeper-lab-portal --network host \
  --cap-add NET_BIND_SERVICE --read-only --tmpfs /tmp \
  -e PORTAL_BIND=192.168.214.2 -e PORTAL_PORT=80 \
  -v "$PWD/$LAB/config:/etc/dnsmasq.d:ro" \
  -v "$PWD/$LAB/leases:/var/lib/misc:ro" \
  gatekeeper-core:latest /usr/bin/python3 /opt/doorbell/pending-portal.py
sleep 6
docker logs gatekeeper-lab-core 2>&1 | tail -8

PASS=0; FAIL=0
check() { # check <name> <command...>
  local name=$1; shift
  if "$@" >/dev/null 2>&1; then
    echo "  ✅ $name"; PASS=$((PASS+1))
  else
    echo "  ❌ $name"; FAIL=$((FAIL+1))
  fi
}

# helper: (re)lease from the netns with the CURRENT veth MAC; echoes the IP
dhcplab_ip() {
  ip netns exec dhcplab timeout 20 dhclient -4 -1 -v -timeout 8 \
      -pf "$LAB/dhclient.pid" -lf "$LAB/dhclient.leases" veth-lab \
      >/dev/null 2>&1 || true
  ip netns exec dhcplab ip -4 -o addr show veth-lab \
      | awk '{print $4}' | cut -d/ -f1
}
reset_netns() { # $1 = new MAC
  ip netns exec dhcplab dhclient -4 -r -pf "$LAB/dhclient.pid" \
      -lf "$LAB/dhclient.leases" veth-lab >/dev/null 2>&1 || true
  ip netns exec dhcplab ip link set veth-lab down
  ip netns exec dhcplab ip link set veth-lab address "$1"
  ip netns exec dhcplab ip link set veth-lab up
}

echo "== T1: approved device ($M1) gets its reserved IP =="
GOT=$(dhcplab_ip)
check "approved lease → $IP1"           [ "$GOT" = "$IP1" ]
check "leasefile recorded it"           grep -q "$M1 $IP1" "$LAB/leases/dnsmasq.leases"
check "doorbell ACK audit (lab log)"    docker logs gatekeeper-lab-core 2>&1 | grep -q "ack.*$IP1"

echo "== T2: walk-in ($M2) lands in the waiting room =="
reset_netns "$M2"
GOT=$(dhcplab_ip)
check "pending IP in 214.100–149"       bash -c "[[ '$GOT' =~ ^192\.168\.214\.1[0-4][0-9]$ ]]"
check "no default route handed out"     bash -c "! ip netns exec dhcplab ip route | grep -q '^default'"
check "waiting-room lease recorded"     grep -q "$M2 192.168.214.1" "$LAB/leases/dnsmasq.leases"

echo "== T3: portal + DNS hijack, from the visitor's seat =="
DNSQ=""
if command -v dig >/dev/null; then
  DNSQ=$(ip netns exec dhcplab dig +short +time=2 +tries=1 @192.168.214.2 example.com 2>/dev/null || true)
else
  DNSQ=$(ip netns exec dhcplab nslookup example.com 192.168.214.2 2>/dev/null | grep -i "address" || true)
fi
check "every name resolves to the portal (hijack)" \
      bash -c "[[ '$DNSQ' == *192.168.214.2* ]]"
STATUS=$(ip netns exec dhcplab curl -s --max-time 5 http://192.168.214.2/status || true)
check "/status says pending"            bash -c "[[ '$STATUS' == *pending* ]]"
PAGE=$(ip netns exec dhcplab curl -s --max-time 5 http://192.168.214.2/ || true)
check "portal shows the friendly note"  bash -c "[[ '$PAGE' == *'guest book'* ]]"

echo "== T4: visitor claims a name (portal → Telegram) =="
ip netns exec dhcplab curl -s --max-time 8 -d "name=Lab Visitor" \
   http://192.168.214.2/ >/dev/null || true
sleep 2
check "claim relayed to the doorbell"   docker logs gatekeeper-lab-core 2>&1 | grep -q "claim.*Lab Visitor"
echo "  (a 🙋 claim card should now be in Telegram)"

echo "== T5: ✅ approve in Telegram (the real path) =="
read -r -p "  Tap ✅ on the $M2 knock card, then press Enter…" _
sleep 3
GOT=$(dhcplab_ip)
check "approved device re-DHCPs → $IP2" [ "$GOT" = "$IP2" ]
check "waiting-room lease evicted (purge + supervisor restart worked)" \
      docker logs gatekeeper-lab-core 2>&1 | grep -q "purged lease 192.168.214.*re-armed"
check "config re-rendered in-container" bash -c "grep -q '$M2,$IP2' '$LAB/config/gatekeeper.conf'"
STATUS=$(ip netns exec dhcplab curl -s --max-time 5 http://192.168.214.2/status || true)
check "/status now says approved"       bash -c "[[ '$STATUS' == *approved* ]]"

echo "== T6: ↩️ undo, then 🚫 deny — the device must go dark =="
read -r -p "  Tap ↩️ on the confirmation, wait for 'pending again', press Enter…" _
sleep 2
read -r -p "  Now tap 🚫 Deny on the fresh card, press Enter…" _
sleep 3
ip netns exec dhcplab ip addr flush dev veth-lab >/dev/null 2>&1 || true
GOT=$(dhcplab_ip)
check "denied device gets NO lease (APIPA only)" \
      bash -c "[[ '$GOT' != 192.168.213.* && '$GOT' != 192.168.214.* ]]"
STATUS=$(ip netns exec dhcplab curl -s --max-time 5 http://192.168.214.2/status || true)
check "/status says denied"             bash -c "[[ '$STATUS' == *denied* ]]"
check "ignore line rendered"            bash -c "grep -q '$M2,ignore' '$LAB/config/gatekeeper.conf'"

echo
echo "== matrix: $PASS passed, $FAIL failed =="
if [ "$FAIL" -eq 0 ]; then
  echo "✅ Phase 5 matrix green — cutover.sh is cleared for takeoff."
  echo "   (Lab artifacts kept in ./$LAB for inspection; deleted next run.)"
  exit 0
else
  echo "❌ Fix the ❌ items above and re-run before any cutover."
  exit 1
fi
