// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import { docsLlms } from '@/lib/source';

export const revalidate = false;

export async function GET() {
  return new Response(await docsLlms.full());
}
