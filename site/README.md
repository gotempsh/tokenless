<!--
SPDX-FileCopyrightText: 2026 tokenless contributors
SPDX-License-Identifier: MIT OR Apache-2.0
-->

# Landing page

A static page in plain HTML and CSS, with no JavaScript, no build step and
nothing loaded from another host, so any static file server can host it. To
preview it, run `python3 -m http.server -d site` from the repository root and
open <http://localhost:8000/>. It follows the system's light or dark setting;
switch your OS appearance (or emulate `prefers-color-scheme` in the browser's
dev tools) to check both.

Fonts (Public Sans, OFL-1.1) are in `fonts/` and service logos (svgl, MIT)
in `logos/`; `REUSE.toml` records their licences.
