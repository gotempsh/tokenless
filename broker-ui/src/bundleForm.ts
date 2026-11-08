// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// The address of the page that creates or edits an access bundle.

/** What the bundle form page opens with. */
export interface BundleFormContext {
  /** The bundle being edited; absent when creating one. */
  bundle?: string;
  /** The vault a new bundle goes in; absent lets the form ask. */
  vault?: string;
  /** The hash path to return to, such as `vaults/<id>/bundles`. */
  back?: string;
}

/** The hash link to the create or edit page for `ctx`. */
export function bundleFormHref(ctx: BundleFormContext = {}): string {
  const path = ctx.bundle ? `#/bundles/${encodeURIComponent(ctx.bundle)}/edit` : "#/bundles/new";
  const query = new URLSearchParams();
  if (!ctx.bundle && ctx.vault) query.set("vault", ctx.vault);
  if (ctx.back) query.set("back", ctx.back);
  const qs = query.toString();
  return qs ? `${path}?${qs}` : path;
}

/** Reads the page's context back from its route and hash query. */
export function parseBundleFormContext(bundle: string | undefined, query: URLSearchParams): BundleFormContext {
  const back = query.get("back") ?? undefined;
  return {
    bundle: bundle ? decodeURIComponent(bundle) : undefined,
    vault: bundle ? undefined : (query.get("vault") ?? undefined),
    // Only an in-app hash path: never a URL somewhere else.
    back: back && /^[A-Za-z0-9/_-]+$/.test(back) ? back : undefined,
  };
}
