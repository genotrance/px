FROM python:3.13.9-slim-bookworm

COPY --from=ghcr.io/astral-sh/uv:0.9.18 /uv /uvx /bin/

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl gss-ntlmssp krb5-user netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*
COPY krb5.conf /etc/krb5.conf
ENTRYPOINT ["sleep", "infinity"]
