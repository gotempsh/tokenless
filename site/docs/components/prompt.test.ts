// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import { describe, expect, test } from 'bun:test';
import { agentPrompt } from './prompt';

// The prompt's set-up runs in the person's project, where the root key or
// a proxy's private keys would sit one `git add .` away from a commit.
describe('the copy prompt', () => {
  const commands = [...agentPrompt.matchAll(/`(tokenless [^`]+)`/g)].map((m) => m[1]);

  test('puts the control plane data outside the project', () => {
    const serve = commands.filter((c) => c.startsWith('tokenless serve'));
    expect(serve.length).toBeGreaterThan(0);
    for (const c of serve) expect(c).toMatch(/--data-dir (~\/|\/)/);
  });

  test('leaves the proxy to serve, so no proxy identity lands in the project', () => {
    const proxy = commands.filter((c) => /^tokenless (proxy add|node (join|run))\b/.test(c));
    expect(proxy).toEqual([]);
    expect(agentPrompt).toContain('runs the proxy your commands go through');
  });

  test('has the key handed over in a file or the console, never through the agent', () => {
    const adds = commands.filter((c) => c.startsWith('tokenless service add'));
    expect(adds.length).toBeGreaterThan(0);
    for (const c of adds) expect(c).toMatch(/--secret-file|--web/);
  });
});
