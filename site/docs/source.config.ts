// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import { remarkMdxMermaid } from 'fumadocs-core/mdx-plugins';
import { defineConfig, defineDocs } from 'fumadocs-mdx/config';

export const docs = defineDocs({
  dir: 'content',
  docs: {
    // Each page's Markdown, for "Copy page" and the .md files agents read.
    postprocess: { includeProcessedMarkdown: true },
  },
});

export default defineConfig({
  mdxOptions: {
    // ```mermaid blocks become <Mermaid>; a page's Markdown keeps the block.
    remarkPlugins: [remarkMdxMermaid],
  },
});
