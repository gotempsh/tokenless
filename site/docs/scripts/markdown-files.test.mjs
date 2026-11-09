// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import { afterEach, expect, test } from 'bun:test';
import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const script = fileURLToPath(new URL('./markdown-files.mjs', import.meta.url));
let site;

afterEach(async () => {
  if (site) await rm(site, { recursive: true, force: true });
});

/** A site with a built out/ of two pages, in a folder named `name`. */
async function builtSite(name) {
  site = join(await mkdtemp(join(tmpdir(), 'markdown-files-')), name);
  await mkdir(join(site, 'scripts'), { recursive: true });
  await cp(script, join(site, 'scripts', 'markdown-files.mjs'));
  await mkdir(join(site, 'out', 'llms.mdx', 'install'), { recursive: true });
  await writeFile(join(site, 'out', 'llms.mdx', 'content.md'), '# tokenless\n');
  await writeFile(join(site, 'out', 'llms.mdx', 'install', 'content.md'), '# Install\n');
  await mkdir(join(site, 'out', 'llms.mdx', 'console', 'vaults'), { recursive: true });
  await writeFile(join(site, 'out', 'llms.mdx', 'console', 'vaults', 'content.md'), '# Vaults\n');
  return site;
}

function run(cwd) {
  return Bun.spawnSync([process.execPath, join(cwd, 'scripts', 'markdown-files.mjs')], { cwd });
}

for (const name of ['site', 'My Projects ü #1']) {
  test(`writes each page's Markdown next to its HTML, in a folder named ${JSON.stringify(name)}`, async () => {
    const dir = await builtSite(name);
    const result = run(dir);
    expect(result.stderr.toString()).toBe('');
    expect(result.exitCode).toBe(0);
    expect(await readFile(join(dir, 'out', 'index.md'), 'utf8')).toBe('# tokenless\n');
    expect(await readFile(join(dir, 'out', 'install.md'), 'utf8')).toBe('# Install\n');
    // A page in a folder.
    expect(await readFile(join(dir, 'out', 'console', 'vaults.md'), 'utf8')).toBe('# Vaults\n');
  });
}

test('fails when there is no built Markdown', async () => {
  const dir = await builtSite('empty');
  await rm(join(dir, 'out', 'llms.mdx'), { recursive: true });
  await mkdir(join(dir, 'out', 'llms.mdx'));
  const result = run(dir);
  expect(result.exitCode).not.toBe(0);
  expect(result.stderr.toString()).toContain('no page Markdown found');
});
