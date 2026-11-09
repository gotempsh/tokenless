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
  loading: boolean;
  error: string | null;
}

/** Loads what naming `bundles`' services takes: their vaults' rules and credentials, and the templates. */
export function useBundleServices(bundles: AccessBundle[] | undefined): BundleServices {
  const vaultIds = [...new Set((bundles ?? []).map((b) => b.vault_id))].sort();
  const key = vaultIds.join(",");
  const vaults = useLoad(async () => {
    const per = await Promise.all(
      vaultIds.map((id) =>
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
  const templates = useLoad(() => get<StoredTemplate[]>("/templates"), []);
  return useMemo(() => {
    // Until the bundles' own vaults have loaded, what is there belongs to others.
    const data = vaults.data?.key === key ? vaults.data : undefined;
    const ruleById = new Map((data?.rules ?? []).map((r) => [r.id, r]));
    const rulesOf = (b: AccessBundle) => bundleRules(b, ruleById);
    const all = templates.data;
    return {
      rulesOf,
      servicesOf: (b) => (data && all ? ruleServices(rulesOf(b), data.credentials, all) : undefined),
      loading: (!data && !vaults.error) || (!all && !templates.error),
      error: vaults.error ?? templates.error,
    };
  }, [key, vaults.data, vaults.error, templates.data, templates.error]);
}
