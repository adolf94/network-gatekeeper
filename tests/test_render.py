#!/usr/bin/env python3
"""Offline verification for the doorbell's SQLite→config renderer
(CONTAINER.md Phase 2). No root, no live paths, no dnsmasq touched:
everything runs against fixtures in a temp dir, and the "reload" hook is
/bin/false so any attempted reload shows up as a failure.

Run:  python3 tests/test_render.py
"""

import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
MODULE = os.path.join(HERE, "..", "scripts", "doorbell-dhcp.py")

# ---------------------------------------------------------------- fixtures
# Static part mirrors the real conf (trimmed); device lines exercise every
# legacy shape: plain approve, approve+hostname, hostname-less, deny, temp.
FIXTURE_CONF = """\
# static part — what the template must preserve
port=53
except-interface=lo
interface=wlxlab0
bind-dynamic
dhcp-range=192.168.213.0,static
dhcp-authoritative
dhcp-leasefile={leasefile}
dhcp-range=set:pending,192.168.214.100,192.168.214.149,2m
dhcp-option=option:router,192.168.213.1
dhcp-option=option:dns-server,1.1.1.1,1.0.0.1
log-dhcp

# ar-lmsi (router-era IP 192.168.213.170)
dhcp-host=98:3b:8f:aa:7d:37,192.168.213.20,ar-lmsi,24h

# Samsung (router-era IP 192.168.213.228)
dhcp-host=e0:03:6b:31:e1:30,192.168.213.23,Samsung,24h

# unidentified (router-era IP 192.168.213.149)
dhcp-host=66:de:6e:57:17:b3,192.168.213.24,24h

# denied 2026-11-16
dhcp-host=1a:91:6c:4c:02:89,ignore
"""

FIXTURE_LEASES = """\
1700000000 98:3b:8f:aa:7d:37 192.168.213.20 ar-lmsi *
1700000001 e0:03:6b:31:e1:30 192.168.213.23 Samsung *
1700000002 aa:bb:cc:dd:ee:ff 192.168.214.100 labphone *
"""

NEW_MAC = "aa:bb:cc:dd:ee:ff"          # the pending device in the leasefile
NEXT_IP = "192.168.213.21"             # first free after .20/.23/.24


def boot(env_dir):
    """Write fixtures, set env, import the module fresh. Returns the module.
    The reload/restart hooks point at a counting wrapper: invocations succeed
    harmlessly AND are counted, so tests can assert when dnsmasq is poked."""
    counter = os.path.join(env_dir, "pokes")
    wrapper = os.path.join(env_dir, "poke.sh")
    with open(wrapper, "w") as f:
        f.write(f"#!/bin/sh\necho x >> {counter}\nexit 0\n")
    os.chmod(wrapper, 0o755)
    conf = os.path.join(env_dir, "gatekeeper.conf")
    with open(conf, "w") as f:
        f.write(FIXTURE_CONF.format(leasefile=os.path.join(env_dir, "dnsmasq.leases")))
    with open(os.path.join(env_dir, "dnsmasq.leases"), "w") as f:
        f.write(FIXTURE_LEASES)
    os.environ.update(
        CONFIG=conf,
        LEASEFILE=os.path.join(env_dir, "dnsmasq.leases"),
        DB=os.path.join(env_dir, "test.db"),
        TEMPLATE=os.path.join(env_dir, "gatekeeper.template"),
        DNMSQ_RELOAD=f"/bin/sh {wrapper}",
        DNMSQ_RESTART=f"/bin/sh {wrapper}",
    )
    spec = importlib.util.spec_from_file_location("doorbell", MODULE)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def poke_count(env_dir):
    p = os.path.join(env_dir, "pokes")
    try:
        with open(p) as f:
            return len(f.read().split())
    except OSError:
        return 0


def lines_of(path):
    with open(path) as f:
        return sorted(l.strip().lower()
                      for l in f if l.strip().startswith("dhcp-host="))


def main():
    tmp = tempfile.mkdtemp(prefix="gatekeeper-render-")
    ok = True

    def check(name, cond, extra=""):
        nonlocal ok
        print(f"  {'✅' if cond else '❌'} {name}{(' — ' + extra) if extra else ''}")
        ok = ok and cond

    try:
        mod = boot(tmp)
        mod.db_init()
        mod.migrate_bindings()
        mod.ensure_template()

        # ---- migration fidelity -------------------------------------------
        check("migrate imported 4 legacy lines",
              len(mod._binding_rows()) == 4, str(len(mod._binding_rows())))
        check("parsed shapes preserved (hostname kept)",
              any(r[0] == "98:3b:8f:aa:7d:37" and r[3] == "24h"
                  and r[4] == "ar-lmsi" for r in mod._binding_rows()))
        check("deny parsed as deny",
              any(r[0] == "1a:91:6c:4c:02:89" and r[1] == "deny"
                  for r in mod._binding_rows()))

        # ---- first render: no device-line change, no reload ----------------
        written, reloaded = mod.render_and_apply()
        check("first render written", written)
        check("first render does NOT poke dnsmasq (line set unchanged)",
              reloaded and poke_count(tmp) == 0,
              f"pokes so far: {poke_count(tmp)} — a reload here would "
              f"disturb the live dnsmasq on deploy")
        conf = os.environ["CONFIG"]

        # ---- idempotency ----------------------------------------------------
        written, reloaded = mod.render_and_apply()
        check("re-render is a no-op", not written and reloaded)

        # ---- template preserved the static part ----------------------------
        with open(os.environ["TEMPLATE"]) as f:
            tpl = f.read()
        check("template kept static settings",
              all(s in tpl for s in ("interface=wlxlab0", "dhcp-authoritative",
                                     "log-dhcp")))
        check("template stripped device lines", "dhcp-host=" not in tpl)

        # ---- approve ---------------------------------------------------------
        check("next_free_ip skips used leases", mod.next_free_ip() == NEXT_IP)
        check("binding write ok",
              mod.db_set_binding(NEW_MAC, "approve", ip=NEXT_IP, spec="24h",
                                 hostname="labphone"))
        pokes_before = poke_count(tmp)
        written, reloaded = mod.render_and_apply()
        check("approve rendered", written and reloaded)
        check("approve poked dnsmasq (line set changed)",
              poke_count(tmp) == pokes_before + 1)
        check("rendered conf is world-readable (mode 644)",
              os.stat(conf).st_mode & 0o777 == 0o644)
        check("approve line present", f"dhcp-host={new_mac_line(NEW_MAC)},"
              f"{NEXT_IP},labphone,24h" in open(conf).read())

        # ---- note (comment-only change must not poke dnsmasq) ---------------
        check("db_set_note ok", mod.db_set_note(NEW_MAC, "Bob"))
        pokes_before = poke_count(tmp)
        written, reloaded = mod.render_and_apply()
        check("note re-render skips reload", reloaded
              and poke_count(tmp) == pokes_before)
        with open(conf) as f:
            conf_text = f.read()
        check("note marker rendered", "# doorbell note: Bob" in conf_text)

        # ---- static template edit (dns-server) must poke dnsmasq ------------
        tpl_path = os.environ["TEMPLATE"]
        tpl = open(tpl_path).read()
        with open(tpl_path, "w") as f:
            f.write(tpl.replace("1.1.1.1,1.0.0.1", "1.1.1.1,192.168.1.1"))
        pokes_before = poke_count(tmp)
        written, reloaded = mod.render_and_apply()
        check("static option edit rendered", written and reloaded)
        check("static option edit poked dnsmasq",
              poke_count(tmp) == pokes_before + 1)
        check("new dns-server in rendered conf",
              "dns-server,1.1.1.1,192.168.1.1" in open(conf).read())

        # ---- deny replaces approve ------------------------------------------
        check("deny write ok", mod.db_set_binding(NEW_MAC, "deny"))
        mod.render_and_apply()
        conf_text = open(conf).read()
        check("deny line rendered",
              f"dhcp-host={new_mac_line(NEW_MAC)},ignore" in conf_text)
        check("old approve line gone",
              f"{NEXT_IP},labphone,24h" not in conf_text)

        # ---- undo returns to pending ----------------------------------------
        check("undo clear ok", mod.db_clear_binding(NEW_MAC))
        written, reloaded = mod.render_and_apply()
        check("undo rendered + reloaded", written and reloaded)
        check("undo removed the line",
              f"{new_mac_line(NEW_MAC)}" not in
              "\n".join(lines_of(conf)))

        # ---- guest pass -------------------------------------------------------
        check("temp binding ok",
              mod.db_set_binding(NEW_MAC, "temp", ip=NEXT_IP, spec="15m",
                                 hostname=None, expires="2026-11-16T12:00"))
        mod.render_and_apply()
        check("temp line rendered (15m, no hostname)",
              f"dhcp-host={new_mac_line(NEW_MAC)},{NEXT_IP},15m"
              in open(conf).read())

        # ---- raw preservation --------------------------------------------------
        raw_line = f"dhcp-host={new_mac_line(NEW_MAC)},infinite"
        check("raw binding ok", mod.db_set_binding(NEW_MAC, "raw", raw=raw_line))
        mod.render_and_apply()
        check("unparsable legacy line preserved verbatim",
              raw_line in open(conf).read())

        # ---- syntax validity of the rendered conf -----------------------------
        if shutil.which("dnsmasq"):
            r = subprocess.run(["dnsmasq", "--test", "-C", conf],
                               capture_output=True, text=True)
            combined = (r.stdout + r.stderr)
            check("dnsmasq --test accepts rendered conf",
                  r.returncode == 0 and "syntax check OK" in combined,
                  combined.strip().splitlines()[-1] if combined.strip() else "")
        else:
            print("  ⏭️  dnsmasq not found — syntax check skipped")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print("\n" + ("ALL CHECKS PASSED" if ok else "FAILURES — see ❌ above"))
    return 0 if ok else 1


def new_mac_line(mac):
    """MACs are already lowercase in fixtures; keeps f-strings readable."""
    return mac


if __name__ == "__main__":
    sys.exit(main())
