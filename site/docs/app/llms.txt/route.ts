// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import { llmsIndex } from '@/lib/source';

export const revalidate = false;

export async function GET() {
  return new Response(llmsIndex());
}
