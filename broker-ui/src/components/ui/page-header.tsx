// SPDX-FileCopyrightText: 2024-2026 Temps Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Ported from the Temps console (web/packages/ds/src/page-header.tsx),
// used here under the same licence.

import type { ReactNode } from 'react'
import { cn } from '../../lib/utils'

export interface PageContainerProps {
  /** Extra classes on the padded outer wrapper. */
  className?: string
  /** Extra classes on the content wrapper (e.g. spacing). */
  innerClassName?: string
  children: ReactNode
}

/** Standard full-width page shell — owns responsive horizontal padding. */
export function PageContainer({ className, innerClassName, children }: PageContainerProps) {
  return (
    <div data-page-container className={cn('w-full px-4 py-6 sm:px-6 lg:px-8', className)}>
      <div className={cn('w-full min-w-0 space-y-6', innerClassName)}>{children}</div>
    </div>
  )
}

export interface PageHeaderProps {
  /** Use h2 for a nested example or section; page titles remain h1. */
  headingLevel?: 'h1' | 'h2'
  title: ReactNode
  description?: ReactNode
  /**
   * The record recipe's second beat: a `Status` or similar one-glance
   * verdict, rendered directly under the title before any facts. Omit on
   * list/settings pages — only record (`Detail`) pages have a verdict.
   */
  verdict?: ReactNode
  actions?: ReactNode
  className?: string
}

export function PageHeader({
  headingLevel: Heading = 'h1',
  title,
  description,
  verdict,
  actions,
  className,
}: PageHeaderProps) {
  return (
    <div
      data-page-header
      className={cn(
        'flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between',
        className,
      )}
    >
      <div className="min-w-0">
        <div className="flex flex-wrap items-center gap-2">
          <Heading className="text-2xl font-semibold tracking-tight">{title}</Heading>
          {verdict}
        </div>
        {description ? (
          <p className="mt-1 text-sm text-muted-foreground">{description}</p>
        ) : null}
      </div>
      {actions ? (
        // Never narrower than its buttons: the description wraps instead
        // of running under them.
        <div className="flex shrink-0 flex-wrap items-center gap-2 sm:justify-end">
          {actions}
        </div>
      ) : null}
    </div>
  )
}
