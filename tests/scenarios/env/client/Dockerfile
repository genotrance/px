FROM debian:12.12-slim

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl krb5-user netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*
COPY krb5.conf /etc/krb5.conf
ENTRYPOINT ["sleep", "infinity"]
