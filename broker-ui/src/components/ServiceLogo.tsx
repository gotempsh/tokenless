// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// Bundled service logos (see assets/logos/NOTICE.md for sources and
// licences). A template names a logo key; `<key>.dark.svg`, when present, is
// shown on dark backgrounds instead.

import { Blocks, Bot, type LucideIcon } from "lucide-react";
import type { ServiceTemplate } from "../api";
import { cn } from "../lib/utils";

const files = import.meta.glob<string>("../assets/logos/*.svg", {
  eager: true,
  query: "?url",
  import: "default",
});

export interface LogoFiles {
  light?: string;
  dark?: string;
}

/** Bundled SVGs by key, from `import.meta.glob` paths to their URLs. */
export function logoMap(files: Record<string, string>): Map<string, LogoFiles> {
  const logos = new Map<string, LogoFiles>();
  for (const [path, url] of Object.entries(files)) {
    const file = path.slice(path.lastIndexOf("/") + 1, -".svg".length);
    const dark = file.endsWith(".dark");
    const key = dark ? file.slice(0, -".dark".length) : file;
    const entry = logos.get(key) ?? {};
    if (dark) entry.dark = url;
    else entry.light = url;
    logos.set(key, entry);
  }
  return logos;
}

const LOGOS = logoMap(files);

type LogoSource = Pick<ServiceTemplate, "id" | "kind"> & { logo?: string | null };

const SIZES = {
  xs: { tile: "size-6 rounded", img: "size-3.5", icon: "size-3" },
  sm: { tile: "size-8 rounded-md", img: "size-4.5", icon: "size-4" },
  md: { tile: "size-10 rounded-lg", img: "size-6", icon: "size-5" },
  lg: { tile: "size-12 rounded-lg", img: "size-7", icon: "size-6" },
} as const;

/** The service's logo on a neutral tile, or a generic icon when there is none. */
export function ServiceLogo({
  template,
  size = "md",
  className,
}: {
  template: LogoSource | undefined;
  size?: keyof typeof SIZES;
  className?: string;
}) {
  return (
    <LogoTile
      logo={template ? (template.logo ?? template.id) : undefined}
      fallback={template?.kind === "mcp" ? Bot : Blocks}
      size={size}
      className={className}
    />
  );
}

/**
 * A bundled logo by key (`anthropic`, `openai`, ...) on the same tile as
 * service logos, or `fallback` when there is none: for things that are not
 * services, such as the agents a bundle can start.
 */
export function LogoTile({
  logo: key,
  fallback: Fallback,
  size = "md",
  className,
}: {
  logo: string | undefined;
  fallback: LucideIcon;
  size?: keyof typeof SIZES;
  className?: string;
}) {
  const s = SIZES[size];
  const logo = key ? LOGOS.get(key) : undefined;
  return (
    <span
      className={cn("flex shrink-0 items-center justify-center border bg-background", s.tile, className)}
      aria-hidden="true"
    >
      {logo?.light ? (
        <>
          <img src={logo.light} alt="" className={cn("object-contain", s.img, logo.dark && "dark:hidden")} />
          {logo.dark && <img src={logo.dark} alt="" className={cn("hidden object-contain dark:block", s.img)} />}
        </>
      ) : (
        <Fallback className={cn("text-muted-foreground", s.icon)} />
      )}
    </span>
  );
}
