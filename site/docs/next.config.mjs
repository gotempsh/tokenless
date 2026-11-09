// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import { createMDX } from 'fumadocs-mdx/next';

/** @type {import('next').NextConfig} */
const config = {
  reactStrictMode: true,
  // A static site, served by Caddy (see ../Caddyfile).
  output: 'export',
  images: { unoptimized: true },
};

export default createMDX()(config);
