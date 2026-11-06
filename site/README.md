<!--
SPDX-FileCopyrightText: 2026 tokenless contributors
SPDX-License-Identifier: MIT OR Apache-2.0
-->

# Website

The tokenless website: the landing page, the documentation and the install
script.

| Path | Served at | |
|---|---|---|
| `index.html`, `styles.css`, `fonts/`, `logos/` | `/` | Plain HTML and CSS, no JavaScript, nothing loaded from another host |
| `docs/` | `/docs/` | Markdown, built with [mdBook](https://rust-lang.github.io/mdBook/) |
| `install.sh` | `/install.sh` | The install script (also used straight from GitHub) |

## Preview

The landing page needs no build: `python3 -m http.server -d site` from the
repository root, then open <http://localhost:8000/>. It follows the
system's light or dark setting.

For the whole site, docs included, build the image:

```sh
docker build -t tokenless-site site
docker run --rm -p 127.0.0.1:8080:8080 tokenless-site
```

With mdBook installed, `mdbook serve site/docs` previews the docs alone
with live reload (the landing page's fonts won't load there).

## Deploy on Temps

The `Dockerfile` here builds everything and serves it with Caddy on port
8080, so the site deploys as an ordinary Temps project:

1. Create a project from the repository, with **directory** `site` and the
   **Dockerfile** preset. The port is read from `EXPOSE 8080`.
2. Add the site's domain to the project. Temps terminates TLS.
3. Deploy on pushes to `main`.

The Dockerfile pins mdBook's version and checks its download against the
published SHA-256. To upgrade, change `MDBOOK_VERSION` and both digests.

## Licences

Fonts (Public Sans, OFL-1.1) are in `fonts/` and service logos (svgl, MIT)
in `logos/`; `REUSE.toml` records their licences.
