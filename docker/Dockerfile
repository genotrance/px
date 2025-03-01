# Main image to use
FROM python:alpine AS base

FROM base AS builder

# VERSION argument
ARG VERSION
ENV VERSION=$VERSION

# Copy and extract binary
COPY px.dist-linux-musl-x86_64-wheels/px-v${VERSION}-linux-musl-x86_64-wheels.tar.gz /tmp/wheels.tar.gz
RUN tar -xzf /tmp/wheels.tar.gz -C /tmp

# Install px
RUN python -m pip install --user px-proxy --no-index -f /tmp --no-cache-dir

###
# Create mini image
FROM base AS mini

# Install dependencies
RUN apk add --no-cache krb5 tini

# Copy python packages installed in user
COPY --from=builder /root /root

# Setup for run
WORKDIR /px
ENV PATH="/root/.local/bin:$PATH"

# Run px using tini
ENTRYPOINT ["tini", "--", "px"]

###
# Create full image
FROM mini

# Install dbus and gnome-keyring
RUN apk add --no-cache dbus gnome-keyring

# Copy start script
COPY docker/start.sh /px/start.sh

# Run start.sh using tini
ENTRYPOINT ["tini", "--", "/bin/sh", "/px/start.sh"]
