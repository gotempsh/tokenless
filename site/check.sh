#!/bin/sh
# SPDX-FileCopyrightText: 2026 tokenless contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

# Checks a running website image: its pages, its 404 and its redirects from
# the old /docs/ paths, which must never lead off the site.
# Usage: site/check.sh http://127.0.0.1:8080
set -eu

base=${1:?usage: site/check.sh <base URL>}
failed=0

# expect <path> <status> [<redirect target>]
expect() {
	got=$(curl -s --path-as-is -o /dev/null -w '%{http_code} %{redirect_url}' "$base$1")
	want="$2 ${3:+$base$3}"
	if [ "$got" != "$want" ]; then
		echo "FAIL $1: got '$got', want '$want'"
		failed=1
	else
		echo "ok   $1 -> $got"
	fi
}

expect / 200
expect /quickstart.html 200
expect /install.sh 200
expect /no-such-page 404
expect /docs 308 /
expect /docs/ 308 /
expect /docs/quickstart.html 308 /quickstart.html
# Browsers read a Location of `/\evil.example` or `/<tab>/evil.example`
# as `//evil.example`: none of these may carry the path over.
expect '/docs/%5Cevil.example' 308 /
expect '/docs/%5C%5Cevil.example' 308 /
expect '/docs/\evil.example' 308 /
expect '/docs/%09/evil.example' 308 /
expect '/docs//evil.example' 308 /
expect '/docs/%2F%2Fevil.example' 308 /
expect '/docs/quickstart.html%5Cevil.example' 308 /

exit "$failed"
