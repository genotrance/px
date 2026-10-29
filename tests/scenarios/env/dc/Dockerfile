FROM debian:12.12-slim

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        krb5-kdc netcat-openbsd samba samba-ad-dc samba-ad-provision squid \
        squid-common winbind \
    && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /entrypoint.sh
RUN chmod 0755 /entrypoint.sh

EXPOSE 53 53/udp 88 88/udp 389 445 464 464/udp 3128 3129
HEALTHCHECK --start-period=10s --interval=5s --timeout=3s --retries=30 \
    CMD nc -z 127.0.0.1 445 && nc -z 127.0.0.1 3128 && nc -z 127.0.0.1 3129
ENTRYPOINT ["/entrypoint.sh"]
