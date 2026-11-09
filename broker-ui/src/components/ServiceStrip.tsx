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
 * names on one line below, the same height however many there are, so
 * panels in a grid line up. With none, only `empty` is shown, in the same
 * height: a placeholder where logos would go reads as a service that failed
 * to load.
 */
export function ServiceStrip({ services, total, empty }: { services: StripService[]; total: number; empty: ReactNode }) {
  const { shown, more } = serviceStrip(services, total);
  if (shown.length === 0 && more === 0) {
    // As tall as a strip with logos (h-8, the gap, h-4), so panels in a grid still line up.
    return (
      <div className="flex h-14 items-center">
        <p className="truncate text-xs text-muted-foreground">{empty}</p>
      </div>
    );
  }
  const names = shown.map((s) => (s.off ? `${s.name} (off)` : s.name)).join(", ");
  return (
    <div className="space-y-2">
      <div className="flex h-8 items-center">
        <ServiceLogos services={services} total={total} />
      </div>
      <p className="h-4 truncate text-xs text-muted-foreground">
        {shown.length === 0 ? `${more} ${more === 1 ? "service" : "services"}` : more > 0 ? `${names} and ${more} more` : names}
      </p>
    </div>
  );
}

/**
 * Up to four of `services`' logos in a row and "+N" for the rest of
 * `total`, to tell records apart at a glance. The logos are decorative:
 * name the services in text nearby.
 */
export function ServiceLogos({
  services,
  total,
  size = "sm",
}: {
  services: StripService[];
  total: number;
  size?: "xs" | "sm";
}) {
  const { shown, more } = serviceStrip(services, total);
  return (
    <span className={cn("flex items-center", size === "xs" ? "gap-1" : "gap-1.5")}>
      {shown.map((s) => (
        <ServiceLogo key={s.key} template={s.logo} size={size} className={cn(s.off && "opacity-40")} />
      ))}
      {more > 0 && (
        <span
          className={cn(
            "flex items-center justify-center border px-1.5 text-xs tabular-nums text-muted-foreground",
            size === "xs" ? "h-6 min-w-6 rounded" : "h-8 min-w-8 rounded-md",
          )}
        >
          +{more}
        </span>
      )}
    </span>
  );
}
