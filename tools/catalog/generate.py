#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 credential-broker contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Generates the built-in service catalogue from tools/catalog/services.toml.

    tools/catalog/fetch-sources.sh            # once: download the logo collections
    python3 tools/catalog/generate.py         # write templates, the Rust list and logos
    python3 tools/catalog/generate.py --check # exit 1 if the committed output is stale

To add a service, append a [[service]] entry to services.toml and run the
generator. Its logo is found automatically in svgl, Lobe Icons, Simple Icons
or gilbarbara/logos (in that order); set `icon` to pick one explicitly. Everything this
writes is committed; never edit the generated files by hand.

A built-in template is stored once per (id, version) by every install, so
changing anything a template injects or allows means bumping its version.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
import tempfile
import tomllib
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HERE = ROOT / "tools" / "catalog"
CACHE = HERE / ".cache"
SOURCE = HERE / "services.toml"
TEMPLATES = Path("crates/broker-core/templates")
RUST_LIST = Path("crates/broker-core/src/builtin_catalog.rs")
LOGOS = Path("broker-ui/src/assets/logos")

HEADER = "SPDX-FileCopyrightText: 2026 credential-broker contributors\nSPDX-License-Identifier: MIT OR Apache-2.0"

CATEGORIES = {
    "llm_providers", "developer_tools", "infrastructure", "communication", "monitoring",
    "productivity", "payments", "commerce", "search", "custom",
}
KEYS = {
    "id", "version", "name", "description", "category", "kind", "hosts", "popular", "aliases",
    "variable", "auth", "field", "label", "field_description", "header", "prefix",
    "username_label", "username_description", "password_label", "password_description",
    "headers", "validate", "expect", "override", "paths", "methods", "logo", "icon",
    "icon_dark_fills", "docs", "mcp_path",
}
SLUG = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
VAR = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")

SOURCES = {
    "svgl": ("https://github.com/pheralb/svgl", "MIT License — Copyright (c) 2022 Pablo Hdez"),
    "Lobe Icons": ("https://github.com/lobehub/lobe-icons", "MIT License — Copyright (c) 2023 LobeHub"),
    "Simple Icons": ("https://github.com/simple-icons/simple-icons", "CC0 1.0 Universal (public domain dedication)"),
    "gilbarbara/logos": ("https://github.com/gilbarbara/logos", "CC0 1.0 Universal (public domain dedication)"),
}


class CatalogError(Exception):
    pass


def q(s: str) -> str:
    return json.dumps(s, ensure_ascii=False)


# ----- templates ----------------------------------------------------------------


def check_service(s: dict, seen: set[str]) -> None:
    sid = s.get("id", "?")
    unknown = set(s) - KEYS
    if unknown:
        raise CatalogError(f"service '{sid}': unknown key(s) {sorted(unknown)}")
    for key in ("id", "name", "description", "category", "auth"):
        if key not in s:
            raise CatalogError(f"service '{sid}': missing '{key}'")
    if not SLUG.match(s["id"]):
        raise CatalogError(f"service '{sid}': id must be a lowercase slug")
    if s["id"] in seen:
        raise CatalogError(f"service '{sid}' is listed twice")
    seen.add(s["id"])
    if s["category"] not in CATEGORIES:
        raise CatalogError(f"service '{sid}': unknown category '{s['category']}'")
    if s["auth"] not in ("bearer", "header", "basic"):
        raise CatalogError(f"service '{sid}': auth must be bearer, header or basic")
    if s["auth"] == "header" and "header" not in s:
        raise CatalogError(f"service '{sid}': header auth needs 'header'")
    if "variable" in s and not VAR.match(s["variable"]):
        raise CatalogError(f"service '{sid}': variable '{s['variable']}' is not UPPER_SNAKE_CASE")
    if not s.get("hosts") and "override" not in s:
        raise CatalogError(f"service '{sid}': no hosts, so it needs an 'override'")
    if "mcp_path" in s:
        if s.get("kind") != "mcp":
            raise CatalogError(f"service '{sid}': mcp_path is only for kind = \"mcp\"")
        if not s["mcp_path"].startswith("/") or "?" in s["mcp_path"]:
            raise CatalogError(f"service '{sid}': mcp_path must be a path starting with '/'")


def template_yaml(s: dict) -> str:
    y = [*(f"# {line}" for line in HEADER.splitlines())]
    y += [f"id: {s['id']}", f"version: {s.get('version', 1)}", f"name: {q(s['name'])}",
          f"description: {q(s['description'])}", f"category: {s['category']}"]
    if s.get("kind", "http") != "http":
        y.append(f"kind: {s['kind']}")
    if s.get("mcp_path"):
        y.append(f"mcp_path: {q(s['mcp_path'])}")
    if s.get("logo"):
        y.append(f"logo: {s['logo']}")
    if s.get("popular"):
        y.append("popular: true")
    if s.get("aliases"):
        y.append("aliases: [" + ", ".join(s["aliases"]) + "]")
    if s.get("variable"):
        y.append(f"suggested_variable: {s['variable']}")
    hosts = s.get("hosts", [])
    y.append("hosts:" + ("" if hosts else " []"))
    y += [f"  - {q(h) if h.startswith('*') else h}" for h in hosts]
    y += ["allow:", f"  paths: {json.dumps(s.get('paths', ['/*']))}",
          f"  methods: {json.dumps(s.get('methods', ['*']))}", "credential_fields:"]

    def field(name: str, label: str, description: str | None) -> None:
        y.append(f"  - name: {name}")
        y.append(f"    label: {q(label)}")
        if description:
            y.append(f"    description: {q(description)}")

    auth = s["auth"]
    if auth == "basic":
        field("username", s.get("username_label", "Username"), s.get("username_description"))
        field("password", s.get("password_label", "Password"), s.get("password_description"))
        y += ["injection:", "  method: basic", "  username_field: username", "  password_field: password"]
    else:
        name = s.get("field", "token" if auth == "bearer" else "api_key")
        field(name, s.get("label", "API key"), s.get("field_description"))
        y.append("injection:")
        if auth == "bearer":
            y += ["  method: bearer", f"  field: {name}"]
        else:
            y += ["  method: header", f"  name: {q(s['header'])}", f"  field: {name}"]
            if s.get("prefix"):
                y.append(f"  prefix: {q(s['prefix'])}")
    if s.get("headers"):
        y.append("default_headers:")
        for n, v in s["headers"].items():
            y += [f"  - name: {n}", f"    value: {q(v)}"]
    if s.get("validate"):
        method, path = s["validate"].split(" ", 1)
        y += ["validation:", f"  method: {method}", f"  path: {path}",
              f"  expect_status: {json.dumps(s.get('expect', [200]))}"]
    if "override" in s:
        o = s["override"]
        y += ["host_override:", "  allowed: true", f"  required: {str(o.get('required', False)).lower()}"]
        if o.get("label"):
            y.append(f"  label: {q(o['label'])}")
    return "\n".join(y) + "\n"


def rust_list(services: list[dict]) -> str:
    lines = [f"// {line}" for line in HEADER.splitlines()]
    lines += [
        "",
        "// @generated by tools/catalog/generate.py from tools/catalog/services.toml.",
        "// Do not edit: add or change services there and run the generator.",
        "",
        "/// Built-in templates in catalogue order, with their YAML source.",
        "#[rustfmt::skip]",
        "pub(crate) const BUILTIN_YAML: &[(&str, &str)] = &[",
    ]
    lines += [f'    ("{s["id"]}", include_str!("../templates/{s["id"]}.yaml")),' for s in services]
    lines.append("];")
    return "\n".join(lines) + "\n"


# ----- logos --------------------------------------------------------------------


@dataclass
class Logo:
    light: str
    dark: str | None
    source: str
    upstream: str


def norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", s.lower())


class LogoSources:
    def __init__(self, cache: Path) -> None:
        self.svgl_dir = cache / "svgl"
        self.lobe_dir = cache / "npm/node_modules/@lobehub/icons-static-svg/icons"
        self.simple_dir = cache / "npm/node_modules/simple-icons"
        self.gilbarbara_dir = cache / "gilbarbara/logos"
        data = self.svgl_dir / "src/data/svgs.ts"
        if not all(p.exists() for p in (data, self.lobe_dir, self.simple_dir, self.gilbarbara_dir)):
            raise CatalogError(f"logo sources missing in {cache}; run tools/catalog/fetch-sources.sh")
        self.svgl: dict[str, tuple[str, str | None]] = {}
        for m in re.finditer(r'title: "([^"]+)",(.*?)\n  \}', data.read_text(), re.S):
            title, body = m.group(1), m.group(2)
            pair = re.search(r"route: \{(.*?)\}", body, re.S)
            single = re.search(r'route: "([^"]+)"', body)
            if pair:
                light = re.search(r'light: "([^"]+)"', pair.group(1))
                dark = re.search(r'dark: "([^"]+)"', pair.group(1))
                if light:
                    self.svgl[title] = (light.group(1), dark.group(1) if dark else None)
            elif single:
                self.svgl[title] = (single.group(1), None)
        self.svgl_norm = {norm(t): t for t in self.svgl}
        icons = json.loads((self.simple_dir / "data/simple-icons.json").read_text())
        icons = icons if isinstance(icons, list) else icons.get("icons", [])
        self.simple_hex = {i.get("slug") or norm(i["title"]): i["hex"] for i in icons}

    def _svgl(self, title: str) -> Logo | None:
        if title not in self.svgl:
            return None
        light, dark = self.svgl[title]
        read = lambda p: (self.svgl_dir / "static" / p.lstrip("/")).read_text()
        return Logo(read(light), read(dark) if dark and dark != light else None, "svgl", title)

    def _lobe(self, key: str) -> Logo | None:
        color, mono = self.lobe_dir / f"{key}-color.svg", self.lobe_dir / f"{key}.svg"
        if color.exists():
            return Logo(color.read_text(), None, "Lobe Icons", key)
        if mono.exists():
            svg = mono.read_text()
            return Logo(svg.replace('fill="currentColor"', 'fill="#000"'),
                        svg.replace('fill="currentColor"', 'fill="#fff"'), "Lobe Icons", key)
        return None

    def _simple(self, slug: str) -> Logo | None:
        path = self.simple_dir / f"icons/{slug}.svg"
        if not path.exists() or slug not in self.simple_hex:
            return None
        svg, hx = path.read_text(), self.simple_hex[slug]
        r, g, b = (int(hx[i:i + 2], 16) / 255 for i in (0, 2, 4))
        dark = svg.replace("<svg ", '<svg fill="#fff" ', 1) if 0.2126 * r + 0.7152 * g + 0.0722 * b < 0.25 else None
        return Logo(svg.replace("<svg ", f'<svg fill="#{hx}" ', 1), dark, "Simple Icons", slug)

    def _gilbarbara(self, key: str) -> Logo | None:
        # Prefer the square mark ("-icon") over the wordmark.
        for name in (f"{key}-icon.svg", f"{key}.svg"):
            path = self.gilbarbara_dir / name
            if path.exists():
                return Logo(path.read_text(), None, "gilbarbara/logos", name[:-4])
        return None

    def resolve(self, s: dict) -> Logo | None:
        spec = s.get("icon")
        if spec == "none":
            return None
        if spec:
            kind, _, ref = spec.partition(":")
            found = {"svgl": self._svgl, "lobe": self._lobe, "simple": self._simple,
                     "gilbarbara": self._gilbarbara}.get(kind, lambda _: None)(ref)
            if not found:
                raise CatalogError(f"service '{s['id']}': icon '{spec}' not found in the logo sources")
        else:
            key = s.get("logo", s["id"])
            title = self.svgl_norm.get(norm(s["name"])) or self.svgl_norm.get(norm(key))
            found = ((self._svgl(title) if title else None) or self._lobe(key) or self._simple(key)
                     or self._gilbarbara(key))
        if found and s.get("icon_dark_fills"):
            dark = found.light
            for fill in s["icon_dark_fills"]:
                dark = dark.replace(f'fill="{fill}"', 'fill="#fff"')
            found.dark = dark
        elif found and not found.dark:
            found.dark = auto_dark(found.light)
        return found


def _luminance(color: str) -> float | None:
    c = color.strip().lower()
    if c in ("black",):
        return 0.0
    if c in ("white",):
        return 1.0
    m = re.fullmatch(r"#([0-9a-f]{3}|[0-9a-f]{6})", c)
    if not m:
        return None
    h = m.group(1)
    if len(h) == 3:
        h = "".join(ch * 2 for ch in h)
    r, g, b = (int(h[i:i + 2], 16) / 255 for i in (0, 2, 4))
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def auto_dark(svg: str) -> str | None:
    """A white variant for a mark drawn only in near-black, which would vanish on a dark background."""
    if re.search(r"<(linearGradient|radialGradient|image)\b", svg):
        return None
    colors = re.findall(r'(?:fill|stroke)="([^"]+)"|(?:fill|stroke):\s*([^;"]+)', svg)
    values = [a or b for a, b in colors if (a or b).strip().lower() not in ("none", "currentcolor")]
    if not values:
        # No colour at all: SVG paints it black.
        return svg.replace("<svg ", '<svg fill="#fff" ', 1)
    lums = [_luminance(v) for v in values]
    if any(l is None or l > 0.2 for l in lums):
        return None
    out = svg
    for v in set(values):
        out = out.replace(f'"{v}"', '"#fff"').replace(f":{v}", ":#fff").replace(f": {v}", ": #fff")
    return out


def clean_svg(svg: str) -> str:
    svg = re.sub(r"<\?xml[^>]*\?>", "", svg)
    svg = re.sub(r"<!DOCTYPE[^>]*>", "", svg)
    svg = re.sub(r"<!--.*?-->", "", svg, flags=re.S).strip()
    if re.search(r"<script|<foreignObject|\son[a-z]+=", svg, re.I):
        raise CatalogError("a logo contains script or event handlers; refusing to ship it")
    return svg + "\n"


def notice(used: dict[str, list[str]]) -> str:
    out = [
        "# Third-party service logos", "",
        "<!-- @generated by tools/catalog/generate.py; do not edit. -->", "",
        "The SVG files in this directory identify the services the built-in templates",
        "integrate with. Each logo is a trademark of its owner, used only to identify",
        "that service; no endorsement is implied. The files were taken from the",
        "collections below under their licences. `<key>.dark.svg` is the variant for",
        "dark backgrounds; where a collection had none, it is the same artwork with its",
        "dark fill set to white.", "",
        "Services without a logo here are shown with a generic icon.", "",
    ]
    for source, keys in used.items():
        url, licence = SOURCES[source]
        out += [f"## {source}", "", f"- Source: {url}", f"- Licence: {licence}",
                f"- Logos: {', '.join(sorted(keys))}", ""]
    out += [
        "## MIT License (svgl, Lobe Icons)", "",
        'Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:', "",
        "The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.", "",
        'THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.', "",
    ]
    return "\n".join(out)


# ----- driver -------------------------------------------------------------------


def build(out: Path, with_logos: bool) -> list[str]:
    """Writes every generated file under `out`; returns services without a logo."""
    services = tomllib.loads(SOURCE.read_text())["service"]
    seen: set[str] = set()
    for s in services:
        check_service(s, seen)
    (out / TEMPLATES).mkdir(parents=True, exist_ok=True)
    for s in services:
        (out / TEMPLATES / f"{s['id']}.yaml").write_text(template_yaml(s))
    (out / RUST_LIST).parent.mkdir(parents=True, exist_ok=True)
    (out / RUST_LIST).write_text(rust_list(services))
    if not with_logos:
        return []
    sources = LogoSources(CACHE)
    (out / LOGOS).mkdir(parents=True, exist_ok=True)
    used: dict[str, list[str]] = {}
    missing, done = [], set()
    for s in services:
        key = s.get("logo", s["id"])
        if key in done:
            continue
        done.add(key)
        logo = sources.resolve(s)
        if not logo:
            if s.get("icon") != "none":
                missing.append(s["id"])
            continue
        (out / LOGOS / f"{key}.svg").write_text(clean_svg(logo.light))
        if logo.dark:
            (out / LOGOS / f"{key}.dark.svg").write_text(clean_svg(logo.dark))
        used.setdefault(logo.source, []).append(key)
    (out / LOGOS / "NOTICE.md").write_text(notice(dict(sorted(used.items()))))
    return missing


def generated_files(base: Path, logos: bool) -> dict[str, bytes]:
    files = {str(p.relative_to(base)): p.read_bytes() for p in (base / TEMPLATES).glob("*.yaml")}
    files[str(RUST_LIST)] = (base / RUST_LIST).read_bytes() if (base / RUST_LIST).exists() else b""
    if logos:
        for p in (base / LOGOS).glob("*"):
            files[str(p.relative_to(base))] = p.read_bytes()
    return files


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true", help="fail if committed output differs")
    parser.add_argument("--no-logos", action="store_true", help="templates only (no logo sources needed)")
    args = parser.parse_args()
    logos = not args.no_logos
    if args.check and logos and not (CACHE / "svgl").exists():
        print("logo sources not downloaded; checking templates only", file=sys.stderr)
        logos = False
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp)
        missing = build(out, logos)
        fresh = generated_files(out, logos)
        if args.check:
            current = generated_files(ROOT, logos)
            stale = sorted(k for k in fresh.keys() | current.keys() if fresh.get(k) != current.get(k))
            if stale:
                print("generated catalogue is out of date; run tools/catalog/generate.py:", file=sys.stderr)
                for path in stale:
                    print(f"  {path}", file=sys.stderr)
                return 1
            print(f"catalogue up to date ({sum(1 for k in fresh if k.endswith('.yaml'))} templates)")
            return 0
        for p in (ROOT / TEMPLATES).glob("*.yaml"):
            p.unlink()
        if logos:
            shutil.rmtree(ROOT / LOGOS, ignore_errors=True)
        for rel, data in fresh.items():
            (ROOT / rel).parent.mkdir(parents=True, exist_ok=True)
            (ROOT / rel).write_bytes(data)
    templates = sum(1 for k in fresh if k.endswith(".yaml"))
    svgs = sum(1 for k in fresh if k.endswith(".svg") and not k.endswith(".dark.svg"))
    print(f"wrote {templates} templates" + (f" and {svgs} logos" if logos else ""))
    if missing:
        print(f"no logo found for: {', '.join(missing)} (set `icon`, or `icon = \"none\"`)")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except CatalogError as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(2)
