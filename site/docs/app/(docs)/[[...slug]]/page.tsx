// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import { createRelativeLink } from 'fumadocs-ui/mdx';
import {
  DocsBody,
  DocsDescription,
  DocsPage,
  DocsTitle,
  MarkdownCopyButton,
  ViewOptionsPopover,
} from 'fumadocs-ui/layouts/notebook/page';
import type { Metadata } from 'next';
import type { ComponentProps } from 'react';
import { notFound } from 'next/navigation';
import { getMDXComponents } from '@/components/mdx';
import { repo } from '@/lib/layout.shared';
import { markdownUrl, source } from '@/lib/source';

type Props = { params: Promise<{ slug?: string[] }> };

export default async function Page(props: Props) {
  const { slug } = await props.params;
  const page = source.getPage(slug);
  if (!page) notFound();
  const MDX = page.data.body;
  const md = markdownUrl(page);
  const PageLink = createRelativeLink(source, page);
  // A file such as /llms.txt or /install.md is not a page: the client-side
  // router would turn /llms.txt into /llms, so load it as a plain link.
  const a = (props: ComponentProps<'a'>) =>
    /\.(md|txt|sh)(#.*)?$/.test(props.href ?? '') ? <a {...props} /> : <PageLink {...props} />;

  return (
    <DocsPage toc={page.data.toc} full={page.data.full}>
      {/* The home page is listed as "Introduction" and titled with the name. */}
      <DocsTitle>{page.slugs.length === 0 ? 'tokenless' : page.data.title}</DocsTitle>
      <DocsDescription className="mb-0">{page.data.description}</DocsDescription>
      <div className="flex flex-row items-center gap-2 border-b pb-6">
        <MarkdownCopyButton markdownUrl={md} />
        <ViewOptionsPopover markdownUrl={md} githubUrl={`${repo}/blob/main/site/docs/content/${page.path}`} />
      </div>
      <DocsBody>
        <MDX components={getMDXComponents({ a })} />
      </DocsBody>
    </DocsPage>
  );
}

export function generateStaticParams() {
  return source.generateParams();
}

export async function generateMetadata(props: Props): Promise<Metadata> {
  const { slug } = await props.params;
  const page = source.getPage(slug);
  if (!page) notFound();
  return {
    // The home page keeps the site's own title.
    title: page.slugs.length === 0 ? { absolute: 'tokenless: let AI agents use your API keys without holding them' } : page.data.title,
    description: page.data.description,
  };
}
