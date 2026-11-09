// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import { HomeLayout } from 'fumadocs-ui/layouts/home';
import Link from 'next/link';
import { baseOptions } from '@/lib/layout.shared';

export default function NotFound() {
  return (
    <HomeLayout {...baseOptions()}>
      <main className="mx-auto flex max-w-xl flex-1 flex-col items-center justify-center gap-3 px-4 py-24 text-center">
        <h1 className="text-2xl font-semibold">Page not found</h1>
        <p className="text-fd-muted-foreground">
          There is no page at this address. The documentation starts on the{' '}
          <Link href="/" className="underline">home page</Link>, and the search box finds the rest.
        </p>
      </main>
    </HomeLayout>
  );
}
