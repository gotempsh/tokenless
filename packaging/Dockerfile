# SPDX-FileCopyrightText: 2026 tokenless contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

# The release image, assembled from the static Linux binaries the release
# workflow already built (linux/<arch>/tokenless in this directory), so the
# image runs exactly the binary in the release archives.
#
# The default command runs the control plane with its data in /data.
# Mount a volume there: it holds the database. Supply the root key from
# outside it (TOKENLESS_ROOT_KEY or --root-key-file with a mounted secret).
#   docker run -v tokenless:/data -p 127.0.0.1:8080:8080 -p 8443:8443 \
#     ghcr.io/gotempsh/tokenless
# Run a proxy instead with: ... ghcr.io/gotempsh/tokenless node run ...

# An empty /data owned by the runtime user, made without running anything
# on the target platform.
FROM --platform=$BUILDPLATFORM busybox:1.37 AS data
RUN mkdir /data

FROM gcr.io/distroless/static-debian12:nonroot
ARG TARGETPLATFORM
COPY --chmod=0755 ${TARGETPLATFORM}/tokenless /usr/local/bin/tokenless
COPY --from=data --chown=65532:65532 /data /data
VOLUME /data
EXPOSE 8080 8443
# `tokenless update` reads this and says to pull a new image instead. The
# release workflow passes the name it publishes under.
ARG IMAGE=ghcr.io/gotempsh/tokenless
ENV TOKENLESS_CONTAINER_IMAGE=${IMAGE}
# No built-in proxy: agents outside the container could not reach one on
# its loopback. An environment variable rather than a flag in CMD, so a
# command given to `docker run` keeps it; set it to 0 to turn it back on.
ENV TOKENLESS_NO_BUILTIN_PROXY=1
ENTRYPOINT ["/usr/local/bin/tokenless"]
CMD ["serve", "--data-dir", "/data", "--api-listen", "0.0.0.0:8080", "--node-listen", "0.0.0.0:8443"]
