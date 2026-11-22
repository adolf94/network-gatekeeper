# Network Gatekeeper — single image, two roles (CONTAINER.md Phase 3).
#   core container  : supervisord runs dnsmasq + the doorbell (this CMD)
#   portal container: same image, command overridden in compose (Phase 4)
#
# host networking is mandatory (Wi-Fi gate NIC, DHCP broadcasts, AF_PACKET
# sniffing, portal binds the host-owned 192.168.214.2) — see compose file.
FROM ubuntu:24.04

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
         dnsmasq supervisor python3 python3-pip ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    # Admin web stack (scripts/admin_web.py): FastAPI + uvicorn + the
    # ar-auth SDK (OAuth BFF, ADMIN.md SEC-9). PEP 668: ubuntu's python is
    # externally managed — the container is the sole owner of this
    # interpreter, so --break-system-packages is safe here.
    && pip3 install --no-cache-dir --break-system-packages \
         "ar-auth-python-client[fastapi] @ https://github.com/adolf94/ar-oauth2/releases/download/1.3.2/ar_auth_python_client-1.3.2-py3-none-any.whl" \
         uvicorn \
    && python3 -c "import ar_auth.bff, fastapi, uvicorn" \
    && dnsmasq --version | head -1

COPY scripts/doorbell-dhcp.py /opt/doorbell/doorbell.py
COPY scripts/admin_web.py /opt/doorbell/admin_web.py
COPY scripts/pending-portal.py /opt/doorbell/pending-portal.py
COPY scripts/admin-page.html /opt/doorbell/admin-page.html
COPY docker/supervisord-core.conf /etc/supervisor/conf.d/gatekeeper-core.conf

RUN chmod 700 /opt/doorbell/doorbell.py && chmod 755 /opt/doorbell/pending-portal.py

# State (config, leases, SQLite, dnsmasq log) is bind-mounted at runtime —
# the image stays stateless; decisions live in the volumes, not the image.
CMD ["/usr/bin/supervisord", "-n", "-c", "/etc/supervisor/conf.d/gatekeeper-core.conf"]
