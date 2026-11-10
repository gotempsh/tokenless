// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import { expect, test } from 'bun:test';
import { readdirSync, readFileSync } from 'node:fs';
import { join, relative } from 'node:path';

const content = join(import.meta.dir, '..', 'content');

function pages(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((e) =>
    e.isDirectory() ? pages(join(dir, e.name)) : e.name.endsWith('.mdx') ? [join(dir, e.name)] : [],
  );
}

// Box-drawing characters and drawn arrows: what an ASCII diagram is made of.
const DRAWING = /[─│┌┐└┘├┤┬┴┼▲▼▶◀►◄]/;

test('diagrams are Mermaid, never drawn in a code block', () => {
  const drawn: string[] = [];
  for (const file of pages(content)) {
    const text = readFileSync(file, 'utf8');
    for (const block of text.matchAll(/^```(\w*)[^\n]*\n([\s\S]*?)^```/gm)) {
      if (block[1] !== 'mermaid' && DRAWING.test(block[2])) {
        drawn.push(`${relative(content, file)}:${text.slice(0, block.index).split('\n').length}`);
      }
    }
  }
  expect(drawn).toEqual([]);
});
