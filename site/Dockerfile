# SPDX-FileCopyrightText: 2026 tokenless contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

# The website: the landing page, the documentation (built with mdBook) and
# the install script, served by Caddy on port 8080. Build it from this
# directory: `docker build -t tokenless-site site`.

FROM --platform=$BUILDPLATFORM alpine:3.22 AS docs
ARG BUILDARCH
ARG MDBOOK_VERSION=0.5.4
RUN apk add --no-cache curl
# The release archives' published SHA-256 digests, per build machine.
RUN set -eu; \
    case "$BUILDARCH" in \
      amd64) arch=x86_64; sum=5222beabd3e37dc5be0d18ff99b79058469354db5c220153a1b92db5ba12be89 ;; \
      arm64) arch=aarch64; sum=753e5c5c363ee8a56972344dcf91466f005a51db84a7aeffe427ae3ef83d6d44 ;; \
      *) echo "no mdBook build for $BUILDARCH" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/mdbook.tar.gz \
      "https://github.com/rust-lang/mdBook/releases/download/v${MDBOOK_VERSION}/mdbook-v${MDBOOK_VERSION}-${arch}-unknown-linux-musl.tar.gz"; \
    echo "$sum  /tmp/mdbook.tar.gz" | sha256sum -c -; \
    tar -xzf /tmp/mdbook.tar.gz -C /usr/local/bin mdbook
COPY docs /book
RUN mdbook build /book --dest-dir /out/docs

FROM caddy:2.10-alpine
# The image grants caddy a file capability to bind ports below 1024. Port
# 8080 needs none, and a host that starts containers with no-new-privileges
# refuses to run a binary that carries one.
RUN apk add --no-cache libcap && setcap -r /usr/bin/caddy && apk del libcap
COPY Caddyfile /etc/caddy/Caddyfile
COPY index.html styles.css favicon.svg install.sh /srv/
COPY fonts /srv/fonts
COPY logos /srv/logos
COPY --from=docs /out/docs /srv/docs
EXPOSE 8080
