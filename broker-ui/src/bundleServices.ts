// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// The services an access bundle reaches, by name and logo: each of its
// rules, the credential the rule uses and that credential's template.

import { useMemo } from "react";
import { get, type AccessBundle, type CredentialMeta, type Page, type Rule, type ServiceTemplate, type StoredTemplate } from "./api";
import type { StripService } from "./components/ServiceStrip";
import { useLoad } from "./hooks";

/** The template a credential was made from, at the version it uses. */
export function templateOf(templates: StoredTemplate[], c: CredentialMeta): ServiceTemplate | undefined {
  return templates.find((t) => t.template.id === c.template_id && t.template.version === c.template_version)?.template;
}

/** `rules` as services: the credential's name and its template's logo. */
export function ruleServices(rules: Rule[], credentials: CredentialMeta[], templates: StoredTemplate[]): StripService[] {
  const byId = new Map(credentials.map((c) => [c.id, c]));
  return rules.map((r) => {
    const c = byId.get(r.credential_id);
    return {
      key: r.id,
      name: c?.name ?? r.name,
      logo: (c && templateOf(templates, c)) ?? { id: c?.template_id ?? "", kind: "http" },
      off: !r.enabled,
    };
  });
}

/** The rules of `b` found in `ruleById`, in the bundle's order. */
export function bundleRules(b: AccessBundle, ruleById: Map<string, Rule>): Rule[] {
  return b.rule_ids.map((id) => ruleById.get(id)).filter((r) => r !== undefined);
}

export interface BundleServices {
  /** A bundle's rules that were found. */
  rulesOf: (b: AccessBundle) => Rule[];
  /** A bundle's services, or undefined until they have loaded. */
  servicesOf: (b: AccessBundle) => StripService[] | undefined;
  /** Why the vaults' rules and credentials could not be loaded. */
  error: string | null;
}

export interface VaultServices {
  /** The vaults these were loaded for: their IDs, sorted, joined with commas. */
  key: string;
  rules: Rule[];
  credentials: CredentialMeta[];
}

interface Loading<T> {
  data: T | undefined;
  error: string | null;
}

/** The vaults `bundles` belong to, as the key their services are loaded under. */
export function vaultsKey(bundles: AccessBundle[] | undefined): string {
  return [...new Set((bundles ?? []).map((b) => b.vault_id))].sort().join(",");
}

/**
 * Bundles' services from what has loaded so far for the vaults in `key`.
 * They stay undefined while loading. A failed load still settles them, as
 * well as it can: without templates, every service gets a generic logo;
 * without the vaults' rules, a bundle's services are only counted.
 */
export function bundleServices(key: string, vaults: Loading<VaultServices>, templates: Loading<StoredTemplate[]>): BundleServices {
  // Until the bundles' own vaults have loaded, what is there belongs to others.
  const data = vaults.data?.key === key ? vaults.data : undefined;
  const ruleById = new Map((data?.rules ?? []).map((r) => [r.id, r]));
  const rulesOf = (b: AccessBundle) => bundleRules(b, ruleById);
  const settled = (data !== undefined || vaults.error !== null) && (templates.data !== undefined || templates.error !== null);
  return {
    rulesOf,
    servicesOf: (b) => (settled ? ruleServices(rulesOf(b), data?.credentials ?? [], templates.data ?? []) : undefined),
    error: data ? null : vaults.error,
  };
}

/**
 * Loads what naming `bundles`' services takes: their vaults' rules and
 * credentials, and the templates. Nothing is loaded while `bundles` is
 * undefined, for a form that is closed or not choosing a bundle.
 */
export function useBundleServices(bundles: AccessBundle[] | undefined): BundleServices {
  const key = vaultsKey(bundles);
  const wanted = bundles !== undefined;
  const vaults = useLoad(async (): Promise<VaultServices> => {
    const ids = key ? key.split(",") : [];
    const per = await Promise.all(
      ids.map((id) =>
        Promise.all([
          get<Page<Rule>>(`/vaults/${id}/rules?page_size=100`),
          get<Page<CredentialMeta>>(`/vaults/${id}/credentials?page_size=100`),
        ]),
      ),
    );
    return {
      key,
      rules: per.flatMap(([rules]) => rules.items),
      credentials: per.flatMap(([, credentials]) => credentials.items),
    };
  }, [key]);
  const templates = useLoad(
    () => (wanted ? get<StoredTemplate[]>("/templates") : Promise.resolve(undefined)),
    [wanted],
  );
  return useMemo(
    () => bundleServices(key, vaults, templates),
    // `vaults` and `templates` are new objects on every render; what matters is in them.
    [key, vaults.data, vaults.error, templates.data, templates.error],
  );
}
