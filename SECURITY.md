<!--
SPDX-FileCopyrightText: 2026 tokenless contributors
SPDX-License-Identifier: MIT OR Apache-2.0
-->

# Security policy

tokenless holds other people's credentials, so we treat security reports
as the highest priority.

## Reporting a vulnerability

Please report it privately through
[GitHub security advisories](https://github.com/gotempsh/tokenless/security/advisories/new),
not in a public issue or pull request. Include what you found, how to
reproduce it, and the version (`tokenless --version`).

We will acknowledge the report, keep you updated while we fix it, and
credit you in the advisory unless you'd rather not be named.

## Supported versions

Fixes go into the latest release. Upgrade to it before reporting, if
you can.

## Verifying a release

Every release archive and container image is signed with Sigstore by the
release workflow and carries a build provenance attestation. See the
[install documentation](site/docs/src/install.md#download-a-release-yourself).
