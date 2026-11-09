<!--
SPDX-FileCopyrightText: 2026 tokenless contributors
SPDX-License-Identifier: MIT OR Apache-2.0
-->

# Website

The tokenless website: the documentation, whose introduction is the home
page, and the install script.

| Path | Served at | |
|---|---|---|
| `docs/` | `/` | Markdown, built with [mdBook](https://rust-lang.github.io/mdBook/); the introduction's **Copy prompt** button copies a set-up prompt for coding agents (`docs/copy-prompt.js`) |
| `fonts/` | `/fonts/` | The docs' typeface |
| `install.sh` | `/install.sh` | The install script (also used straight from GitHub) |

Old `/docs/...` links redirect to the same page at the root.

## Preview

Build the image:

```sh
docker build -t tokenless-site site
docker run --rm -p 127.0.0.1:8080:8080 tokenless-site
```

With mdBook installed, `mdbook serve site/docs` previews the docs with
live reload (the fonts won't load there).

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

The fonts (Public Sans, OFL-1.1) are in `fonts/`; `REUSE.toml` records
their licence.
