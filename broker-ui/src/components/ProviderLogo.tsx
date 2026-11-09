// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// The logo of the identity provider a sign-in button leads to (see
// assets/sign-in/NOTICE.md for sources and licences); the OpenID logo for a
// provider the server did not recognise.

import type { ProviderBrand } from "../api";
import { cn } from "../lib/utils";
import { logoMap } from "./ServiceLogo";

const LOGOS = logoMap(
  import.meta.glob<string>("../assets/sign-in/*.svg", {
    eager: true,
    query: "?url",
    import: "default",
  }),
);

export function ProviderLogo({ brand, className }: { brand: ProviderBrand | undefined; className?: string }) {
  const logo = (brand && LOGOS.get(brand)) || LOGOS.get("openid");
  if (!logo?.light) return null;
  const size = cn("size-4 shrink-0 object-contain", className);
  return (
    <>
      <img src={logo.light} alt="" aria-hidden="true" className={cn(size, logo.dark && "dark:hidden")} />
      {logo.dark && <img src={logo.dark} alt="" aria-hidden="true" className={cn(size, "hidden dark:block")} />}
    </>
  );
}
