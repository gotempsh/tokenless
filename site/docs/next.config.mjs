// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import { createMDX } from 'fumadocs-mdx/next';

const basePath = process.env.BASE_PATH ?? '';

/** @type {import('next').NextConfig} */
const config = {
  reactStrictMode: true,
  // A static site, served by Caddy (see ../Caddyfile) at a domain's root, or
  // by GitHub Pages under /tokenless (BASE_PATH=/tokenless).
  output: 'export',
  basePath,
  env: { BASE_PATH: basePath },
  images: { unoptimized: true },
};

export default createMDX()(config);
