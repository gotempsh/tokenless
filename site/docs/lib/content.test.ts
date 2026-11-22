// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import { expect, test } from 'bun:test';
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
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
    // Backtick or tilde fences, indented too (a block inside a numbered step).
    for (const block of text.matchAll(/^[ \t]*(`{3,}|~{3,})(\w*)[^\n]*\n([\s\S]*?)^[ \t]*\1/gm)) {
      if (block[2] !== 'mermaid' && DRAWING.test(block[3])) {
        drawn.push(`${relative(content, file)}:${text.slice(0, block.index).split('\n').length}`);
      }
    }
  }
  expect(drawn).toEqual([]);
});

test('the invite example preserves retry files until acceptance succeeds', () => {
  const guide = readFileSync(join(content, 'cli.mdx'), 'utf8');
  const block = Array.from(guide.matchAll(/^```sh\n([\s\S]*?)^```/gm))
    .find(([, script]) => script.includes('POST /invites/accept'));
  if (!block) throw new Error('Missing invitation acceptance example');

  const work = mkdtempSync(join(tmpdir(), 'invite-'));
  const files = ['invite.json', 'proof.json', 'enrollment.json'];
  try {
    for (const file of files) writeFileSync(join(work, file), '{}');
    const script = 'jq() { echo "{}"; }\ntokenless() { cat >/dev/null; return "$status"; }\n' + block[1];
    const accept = (status: number) => Bun.spawnSync(['sh', '-c', script], {
      env: { ...process.env, work, EDITOR: 'true', status: String(status) },
    }).exitCode;
    expect(accept(1)).toBe(1);
    expect(readdirSync(work).sort()).toEqual(files.sort());
    expect(accept(0)).toBe(0);
    expect(existsSync(work)).toBe(false);
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
});
