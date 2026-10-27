# Select builder: --build-arg BUILDER=local for local builds (default: ci)
ARG BUILDER=ci

# CPython minor version, always the newest patch release of it
ARG PYTHON_MINOR=3.14

# Main image to use
FROM python:${PYTHON_MINOR}-alpine AS base

###
# CI builder — installs from pre-built wheel archives
FROM base AS builder-ci

# VERSION argument
ARG VERSION
ARG WHEELS_DIR=px.dist-linux-musl-x86_64-wheels

# Copy and extract wheels
COPY ${WHEELS_DIR}/px-v${VERSION}-linux-musl-x86_64-wheels.tar.gz /tmp/wheels.tar.gz
RUN tar -xzf /tmp/wheels.tar.gz -C /tmp

# Install px
RUN python -m pip install --user px-proxy --no-index -f /tmp --no-cache-dir && \
    python -c "import importlib.metadata as m; print(\"quickjs-ng version:\", m.version(\"quickjs-ng\"))"

###
# Local builder — installs from source tree
FROM base AS builder-local

COPY . /src
RUN pip install --upgrade --user /src && \
    python -c "import importlib.metadata as m; print(\"quickjs-ng version:\", m.version(\"quickjs-ng\"))"

###
# Select builder based on BUILDER arg
FROM builder-${BUILDER} AS builder

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
