#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 tokenless contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Downloads the openly licensed logo collections generate.py draws from
# into tools/catalog/.cache (not committed). Versions are pinned so a
# regeneration is reproducible; bump them deliberately.
set -euo pipefail

SVGL_REF="c0ec7ab121354ac1096b17b3aebbb293c8ce5600" # github.com/pheralb/svgl, MIT
SIMPLE_ICONS_VERSION="16.36.0"                      # simple-icons, CC0-1.0
LOBE_ICONS_VERSION="1.102.0"                        # @lobehub/icons-static-svg, MIT
GILBARBARA_REF="22f03ffc4a652309d1fea4ade70f46e9e1d6602c" # github.com/gilbarbara/logos, CC0-1.0

here="$(cd "$(dirname "$0")" && pwd)"
cache="$here/.cache"
mkdir -p "$cache"

if [ ! -d "$cache/svgl/.git" ]; then
  git clone --quiet --filter=blob:none --no-checkout https://github.com/pheralb/svgl.git "$cache/svgl"
  git -C "$cache/svgl" sparse-checkout set --no-cone /static/library/ /src/data/svgs.ts /LICENSE
fi
git -C "$cache/svgl" fetch --quiet --depth 1 origin "$SVGL_REF"
git -C "$cache/svgl" checkout --quiet "$SVGL_REF"

if [ ! -d "$cache/gilbarbara/.git" ]; then
  git clone --quiet --filter=blob:none --no-checkout https://github.com/gilbarbara/logos.git "$cache/gilbarbara"
  git -C "$cache/gilbarbara" sparse-checkout set --no-cone /logos/ /LICENSE.txt
fi
git -C "$cache/gilbarbara" fetch --quiet --depth 1 origin "$GILBARBARA_REF"
git -C "$cache/gilbarbara" checkout --quiet "$GILBARBARA_REF"

mkdir -p "$cache/npm"
cat > "$cache/npm/package.json" <<JSON
{
  "private": true,
  "dependencies": {
    "simple-icons": "$SIMPLE_ICONS_VERSION",
    "@lobehub/icons-static-svg": "$LOBE_ICONS_VERSION"
  }
}
JSON
(cd "$cache/npm" && bun install --silent)

echo "logo sources ready in $cache"
