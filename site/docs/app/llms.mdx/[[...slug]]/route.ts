// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import { notFound } from 'next/navigation';
import { docsLlms, source } from '@/lib/source';

export const revalidate = false;

export async function GET(_req: Request, { params }: { params: Promise<{ slug?: string[] }> }) {
  const { slug } = await params;
  // Drop the "content.md" each page's path ends with.
  const page = source.getPage(slug?.slice(0, -1) ?? []);
  if (!page) notFound();
  return new Response(await docsLlms.page(page), {
    headers: { 'Content-Type': 'text/markdown; charset=utf-8' },
  });
}

export function generateStaticParams() {
  return source.generateParams().map((item) => ({ slug: [...(item.slug ?? []), 'content.md'] }));
}
