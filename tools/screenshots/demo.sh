#!/bin/bash
# SPDX-FileCopyrightText: 2026 tokenless contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# The README's terminal demo, typed out for asciinema:
#   asciinema rec --window-size 120x36 -c ./demo.sh demo.cast
#   agg --font-size 16 demo.cast ../../docs/images/demo.gif
# Needs a signed-in server seeded by seed.ts, whose `demo` bundle in the
# `personal` vault reaches httpbin.org, GET only.

say() { printf '\033[2m# %s\033[0m\n' "$1"; sleep 0.8; }
type_out() {
  printf '\033[1;32m$\033[0m '
  for ((i = 0; i < ${#1}; i++)); do printf '%s' "${1:i:1}"; sleep 0.025; done
  printf '\n'
  sleep 0.3
}
run() { type_out "$1"; eval "$1"; printf '\n'; sleep 2.2; }

clear
sleep 0.5
run "tokenless status"
say "The agent has no key of its own: on its own, the API turns it away."
run "curl -s -o /dev/null -w '%{http_code}\\n' https://httpbin.org/bearer"
say "The proxy adds the key on the way out, and redacts it if the API echoes it back."
run "tokenless run --vault personal --bundle demo -- curl -s https://httpbin.org/bearer"
say "A request outside the bundle's rules is refused before it reaches the API."
run "tokenless run --vault personal --bundle demo -- curl -s -X DELETE https://httpbin.org/anything"
sleep 1.5
