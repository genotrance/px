# Main image to use
FROM python:alpine as base

FROM base as builder

# VERSION argument
ARG VERSION
ENV VERSION=$VERSION

# Install dependencies
RUN apk add --no-cache curl upx

# Download and extract wheels
RUN curl -SLs https://github.com/genotrance/px/releases/download/v${VERSION}/px-v${VERSION}-linux-musl-x86_64-wheels.tar.gz -o /tmp/wheels.tar.gz \
 && tar -xzf /tmp/wheels.tar.gz -C /tmp

# Install px
RUN python -m pip install --user px-proxy --no-index -f /tmp

# Compress libs
RUN find /root/.local -type f -iname "*.so.*" -exec upx {} \+ || true

###
# Create mini image
FROM base as mini

# Install dependencies
RUN apk add --no-cache libcurl

# Copy python packages installed in user
COPY --from=builder /root /root

# Setup for run
WORKDIR /px
ENV PATH="/root/.local/bin:$PATH"

# Run px by default
ENTRYPOINT ["px"]

###
# Create full image
FROM mini

# Install dbus and gnome-keyring
RUN apk add --no-cache dbus gnome-keyring

# Copy start script
COPY start.sh /px/start.sh

# Run start.sh by default
ENTRYPOINT [ "/px/start.sh" ]