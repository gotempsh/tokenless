// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// Writes each page's Markdown, built at out/llms.mdx/<page>/content.md, to
// out/<page>.md, and the home page's to out/index.md. A host that only
// serves files (GitHub Pages) has no rewrites to map one onto the other.
import { cp, readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

// A file path, not the URL's percent-encoded pathname: a checkout under
// `My Projects/` would otherwise be looked for under `My%20Projects/`.
const out = fileURLToPath(new URL('../out/', import.meta.url));
const built = join(out, 'llms.mdx');

let written = 0;
for (const entry of await readdir(built, { recursive: true })) {
  if (entry !== 'content.md' && !entry.endsWith('/content.md')) continue;
  const page = entry.slice(0, -'content.md'.length).replace(/\/$/, '');
  await cp(join(built, entry), join(out, `${page || 'index'}.md`));
  written++;
}
if (written === 0) throw new Error(`no page Markdown found under ${built}; did next build run?`);
console.log(`wrote ${written} Markdown pages next to their HTML`);
