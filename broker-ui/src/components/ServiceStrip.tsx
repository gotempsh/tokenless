// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import type { ReactNode } from "react";
import type { ServiceTemplate } from "../api";
import { cn } from "../lib/utils";
import { serviceStrip } from "../serviceStrip";
import { ServiceLogo } from "./ServiceLogo";

export interface StripService {
  key: string;
  name: string;
  logo: (Pick<ServiceTemplate, "id" | "kind"> & { logo?: string | null }) | undefined;
  /** A turned-off rule: its logo is dimmed. */
  off?: boolean;
}

/**
 * A record panel's services: up to four logos in one row and "+N", their
 * names on one line below. One height however many services there are, so
 * panels in a grid line up. `empty` takes the names line when there are none.
 */
export function ServiceStrip({ services, total, empty }: { services: StripService[]; total: number; empty: ReactNode }) {
  const { shown, more } = serviceStrip(services, total);
  const names = shown.map((s) => (s.off ? `${s.name} (off)` : s.name)).join(", ");
  return (
    <div className="space-y-2">
      <div className="flex h-8 items-center gap-1.5">
        {shown.length === 0 ? (
          <span className="size-8 rounded-md border border-dashed" aria-hidden="true" />
        ) : (
          shown.map((s) => (
            <ServiceLogo key={s.key} template={s.logo} size="sm" className={cn(s.off && "opacity-40")} />
          ))
        )}
        {more > 0 && (
          <span className="flex h-8 min-w-8 items-center justify-center rounded-md border px-1.5 text-xs tabular-nums text-muted-foreground">
            +{more}
          </span>
        )}
      </div>
      <p className="h-4 truncate text-xs text-muted-foreground">
        {shown.length === 0 ? empty : more > 0 ? `${names} and ${more} more` : names}
      </p>
    </div>
  );
}
