FROM python:3.13.9-slim-bookworm

COPY --from=ghcr.io/astral-sh/uv:0.9.18 /uv /uvx /bin/

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl gss-ntlmssp krb5-user netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*
COPY krb5.conf /etc/krb5.conf
# Runs as the host user (see compose.yaml); create its HOME and tool caches
# under /tmp since the image has no account for an arbitrary host uid/gid.
ENTRYPOINT ["sh", "-c", "mkdir -p \"$HOME\" \"$UV_CACHE_DIR\" \"$XDG_CACHE_HOME\" \"$PIP_CACHE_DIR\" \"$UV_PYTHON_INSTALL_DIR\" && exec sleep infinity"]
