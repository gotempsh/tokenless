// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

/**
 * Pages link to each other by file (`./settings.mdx#single-sign-on`), so the
 * links also work when the content is read on GitHub. The site resolves them
 * as it renders; this does the same for a page's Markdown, with `resolve`
 * turning a file link into the page's address.
 */
export function resolveFileLinks(md: string, resolve: (href: string) => string): string {
  return md.replace(/\]\((\.{1,2}\/[^)\s]+)\)/g, (link, href: string) => {
    const url = resolve(href);
    return url === href ? link : `](${url})`;
  });
}
