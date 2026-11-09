# SPDX-FileCopyrightText: 2026 tokenless contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

# The website: the documentation (Next.js and Fumadocs, exported as static
# files), whose introduction is the home page, and the install script,
# served by Caddy on port 8080.
# Build it from this directory: `docker build -t tokenless-site site`.

FROM --platform=$BUILDPLATFORM oven/bun:1.4.2-alpine AS docs
WORKDIR /docs
COPY docs/package.json docs/bun.lock ./
# The postinstall step reads the content, which is not copied yet.
RUN bun install --frozen-lockfile --ignore-scripts
COPY docs ./
RUN bun run build

FROM caddy:2.10-alpine
# The image grants caddy a file capability to bind ports below 1024. Port
# 8080 needs none, and a host that starts containers with no-new-privileges
# refuses to run a binary that carries one.
RUN apk add --no-cache libcap && setcap -r /usr/bin/caddy && apk del libcap
COPY Caddyfile /etc/caddy/Caddyfile
COPY --from=docs /docs/out /srv
COPY install.sh /srv/
EXPOSE 8080
