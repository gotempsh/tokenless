// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import { docs } from 'collections/server';
import { createGetUrl, llms, loader } from 'fumadocs-core/source';
import { agentPrompt } from '@/components/prompt';

// The documentation is the site: its introduction is the home page.
export const source = loader({
  baseUrl: '/',
  source: docs.toFumadocsSource(),
});

export const docsLlms = llms(source, {
  renderPage: async (page) => {
    const body = plainMarkdown(await page.data.getText('processed'));
    return [`# ${page.slugs.length === 0 ? 'tokenless' : page.data.title}`, page.data.description, body].filter(Boolean).join('\n\n');
  },
});

/** A page's Markdown without the site's components, for agents to read. */
export function plainMarkdown(md: string): string {
  return (
    md
      // Headings carry their anchor as `## Title [#title]`.
      .replace(/^(#{1,6} .*?) \[#[^\]]+\]$/gm, '$1')
      .replace('<CopyPrompt />', '```text\n' + agentPrompt + '\n```')
      .replace(/<Card title="([^"]+)" href="([^"]+)">\s*([\s\S]*?)\s*<\/Card>/g, (_, title, href, text) => `- [${title}](${href}): ${text.replace(/\s+/g, ' ')}`)
      .replace(/^\s*<\/?(Cards|Steps|Step)>\s*$/gm, '')
      .replace(/\n{3,}/g, '\n\n')
  );
}

/** The `llms.txt` index: every page, with what it covers. */
export function llmsIndex(): string {
  return docsLlms
    .index()
    .replace(/^# .*$/m, '# tokenless\n\n> Give AI agents access to APIs without giving them the keys. Every page is also Markdown at its address plus `.md`.');
}

const contentUrl = createGetUrl('/llms.mdx');

/** Where a page's Markdown is built. Caddy also serves it at `/<page>.md`. */
export function markdownUrl(page: { slugs: string[] }): string {
  return contentUrl([...page.slugs, 'content.md']);
}
