// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import type { BaseLayoutProps } from 'fumadocs-ui/layouts/shared';
import { CopyPromptButton } from '@/components/copy-prompt';
import { Logo } from '@/components/logo';

export const repo = 'https://github.com/gotempsh/tokenless';

export function baseOptions(): BaseLayoutProps {
  return {
    nav: {
      title: (
        <>
          <Logo />
          <span className="font-semibold">tokenless</span>
        </>
      ),
    },
    githubUrl: repo,
    links: [
      { text: 'Install', url: '/install' },
      { text: 'Releases', url: `${repo}/releases`, external: true },
      // The set-up prompt, on every page, for whoever lands deep in the docs.
      { type: 'custom', children: <CopyPromptButton /> },
    ],
  };
}
