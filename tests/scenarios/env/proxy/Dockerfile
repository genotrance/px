FROM debian:12.12-slim

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        krb5-user openssl python3 samba-common-bin squid squid-common winbind \
    && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /entrypoint.sh
RUN chmod 0755 /entrypoint.sh

EXPOSE 3128
HEALTHCHECK --interval=5s --timeout=3s --retries=30 \
    CMD test -s /run/squid.pid && kill -0 "$(cat /run/squid.pid)"
ENTRYPOINT ["/entrypoint.sh"]
