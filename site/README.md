<!--
SPDX-FileCopyrightText: 2026 tokenless contributors
SPDX-License-Identifier: MIT OR Apache-2.0
-->

# Website

The tokenless website: the documentation, whose introduction is the home
page, and the install script.

| Path | Served at | |
|---|---|---|
| `docs/content/` | `/` | The pages, in MDX; `meta.json` orders the sidebar. Screenshots are in `docs/content/screenshots/` |
| `docs/` | | A [Next.js](https://nextjs.org) and [Fumadocs](https://fumadocs.dev) app, exported as static files |
| `install.sh` | `/install.sh` | The install script (also used straight from GitHub) |

Every page is also Markdown at its address plus `.md` (`/install.md`),
which **Copy Markdown** copies; `/llms.txt` lists the pages and
`/llms-full.txt` holds them all. The home page's **Copy prompt** button
copies a set-up prompt for coding agents (`docs/components/prompt.ts`).
Search runs in the browser on an index built with the site.

Old `/docs/<page>.html` links redirect to the same page at the root; any
other `/docs/...` path redirects to the home page.

## Write and preview

```sh
cd site/docs
bun install
bun run dev        # http://localhost:3000, reloads as you edit
```

A new page is a file in `docs/content/`; add its name to
`docs/content/meta.json` to place it in the sidebar (a folder has its own
`meta.json`). Link to other pages by their file (`./quickstart.mdx#next`,
`../settings.mdx` from a folder), so the links also work on GitHub; the
site and each page's Markdown turn them into addresses.

Draw a diagram as a ` ```mermaid ` block with an `accTitle` and
`accDescr`, never as box-drawing text; `bun run test` fails on one. GitHub
draws the same block, and a page's Markdown keeps it as written.

To check the image as it is deployed:

```sh
docker build -t tokenless-site site
docker run --rm -p 127.0.0.1:8080:8080 tokenless-site
site/check.sh http://127.0.0.1:8080
```

`check.sh` checks the pages, headers, Markdown and redirects, as CI does.

## Deploy on Temps

The `Dockerfile` here builds everything and serves it with Caddy on port
8080, so the site deploys as an ordinary Temps project:

1. Create a project from the repository, with **directory** `site` and the
   **Dockerfile** preset. The port is read from `EXPOSE 8080`.
2. Add the site's domain to the project. Temps terminates TLS.
3. Deploy on pushes to `main`.

## GitHub Pages

`.github/workflows/pages.yml` also publishes the site to
<https://gotempsh.github.io/tokenless/> on every push to `main` that
touches `site/`; a pull request only builds it. Pages serves a project
under `/tokenless`, so the workflow builds with `BASE_PATH=/tokenless`
and checks that no link leaves it. It also builds with
`TRAILING_SLASH=1`, which writes each page as `<page>/index.html`:
Pages serves a folder's `index.html`, and Next.js writes a `<page>/`
folder of navigation data next to every page, which would shadow a
`<page>.html`. Pages has no rewrites or redirects:
the build writes each page's Markdown to `/<page>.md` as a file
(`docs/scripts/markdown-files.mjs`), and old `/docs/<page>.html` links
only redirect on the Caddy deployment.

To try a base-path build locally:

```sh
cd site/docs
BASE_PATH=/tokenless TRAILING_SLASH=1 bun run build    # out/, as Pages serves it
```
