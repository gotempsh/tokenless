// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import { expect, test } from 'bun:test';
import { resolveFileLinks } from './markdown-links';

const pages: Record<string, string> = {
  './settings.mdx#single-sign-on': '/settings#single-sign-on',
  '../security.mdx': '/security',
  './console/index.mdx': '/console',
};
const resolve = (href: string) => pages[href] ?? href;

test('file links become page addresses', () => {
  expect(
    resolveFileLinks(
      'See [SSO](./settings.mdx#single-sign-on), [the model](../security.mdx) and [the tour](./console/index.mdx).',
      resolve,
    ),
  ).toBe('See [SSO](/settings#single-sign-on), [the model](/security) and [the tour](/console).');
});

test('other links are left alone', () => {
  const md =
    '[llms.txt](/llms.txt), [GitHub](https://github.com), ![shot](<../screenshots/a.png>), ![shot](../screenshots/a.png) and [gone](./missing.mdx)';
  expect(resolveFileLinks(md, resolve)).toBe(md);
});
