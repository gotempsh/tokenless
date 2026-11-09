#!/bin/sh
# SPDX-FileCopyrightText: 2026 tokenless contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

# Checks a running website image: its pages, its 404, the headers on both,
# each page's Markdown for agents, and the redirects from the old /docs/
# paths, which must never lead off the site.
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

# headers <path>: the site's security headers are set and Server is not.
headers() {
	got=$(curl -s --path-as-is -o /dev/null -D - "$base$1" | tr -d '\r' | tr '[:upper:]' '[:lower:]')
	ok=1
	for want in 'x-frame-options: deny' 'x-content-type-options: nosniff' 'referrer-policy: strict-origin-when-cross-origin'; do
		if ! printf '%s\n' "$got" | grep -qx "$want"; then
			echo "FAIL $1: no '$want'"
			ok=0
		fi
	done
	if printf '%s\n' "$got" | grep -q '^server:'; then
		echo "FAIL $1: names its server"
		ok=0
	fi
	if [ "$ok" = 1 ]; then echo "ok   $1 headers"; else failed=1; fi
}

# type <path> <content type>: the response's Content-Type starts with it.
type() {
	got=$(curl -s --path-as-is -o /dev/null -w '%{content_type}' "$base$1")
	case "$got" in
	"$2"*) echo "ok   $1 is $got" ;;
	*)
		echo "FAIL $1: got type '$got', want '$2'"
		failed=1
		;;
	esac
}

# cache <path> <text>: the response's Cache-Control contains it, and a
# missing file's is never "immutable".
cache() {
	got=$(curl -s --path-as-is -o /dev/null -D - "$base$1" | tr -d '\r' | grep -i '^cache-control:' || true)
	case "$got" in
	*"$2"*)
		if [ "$2" != immutable ] && printf '%s' "$got" | grep -q immutable; then
			echo "FAIL $1: '$got' is immutable"
			failed=1
		else
			echo "ok   $1 $got"
		fi
		;;
	*)
		echo "FAIL $1: got '$got', want '$2'"
		failed=1
		;;
	esac
}

# body <path> <text>: the response contains it.
body() {
	if curl -s --path-as-is "$base$1" | grep -qF "$2"; then
		echo "ok   $1 has '$2'"
	else
		echo "FAIL $1: no '$2'"
		failed=1
	fi
}

expect / 200
expect /quickstart 200
expect /quickstart.html 200
expect /install.sh 200
expect /no-such-page 404
expect /no-such-page.md 404
# A missing page is HTML however it was asked for.
type /no-such-page.md text/html
headers /
headers /no-such-page
body / 'Copy prompt'
body / '/_next/static/media/console-vault.'
body /no-such-page 'Page not found'

# Each page as Markdown, for agents, and the indexes of them all.
expect /install.md 200
type /install.md text/markdown
body /install.md '# Install'
expect /index.md 200
body /index.md 'Set up tokenless on this machine'
# llms.txt lists the home page as /, so /.md is its Markdown too.
expect /.md 200
type /.md text/markdown
body /.md 'Set up tokenless on this machine'
expect /introduction.md 200
type /llms.txt text/plain
body /llms.txt '[Quickstart](/quickstart)'
body /llms-full.txt '# Concepts'
type /api/search application/json
type /install.sh text/plain

# Built files never change, so they are cached for good; a missing one
# must not be.
asset=$(curl -s "$base/" | grep -oE '/_next/static/[^"]+\.js' | head -n 1)
cache "$asset" immutable
cache /_next/static/chunks/no-such-chunk.js no-cache
type /_next/static/chunks/no-such-chunk.js text/html

# The introduction was its own page before it became the home page.
expect /introduction 308 /
expect /introduction.html 308 /
expect /docs/introduction.html 308 /
expect /docs 308 /
expect /docs/ 308 /
expect /docs/quickstart.html 308 /quickstart
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
