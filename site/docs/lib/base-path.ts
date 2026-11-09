// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

/**
 * The path the site is served under: empty at a domain's root (Caddy), and
 * `/tokenless` on GitHub Pages. Set at build time with `BASE_PATH`.
 */
export const basePath = process.env.BASE_PATH ?? '';

/**
 * A root-relative address under the site's base path. Next.js adds it to its
 * own links and assets; anything else built from a `/...` address needs this.
 */
export function withBasePath(href: string): string {
  return href.startsWith('/') && !href.startsWith('//') ? basePath + href : href;
}

/** Markdown with its root-relative links moved under the base path. */
export function markdownWithBasePath(md: string): string {
  return basePath ? md.replace(/\]\(\//g, `](${basePath}/`) : md;
}
