// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// "Add a service to a vault" in one go: the vault (new or existing), the
// credential, a rule for it and, if chosen, its place in access bundles.
// Each step that succeeded is remembered, so trying again after a
// failure continues from the step that failed instead of creating a second
// credential.

import type { AccessBundle, CredentialMeta, CustomHeader, Rule, Vault } from "./api";

export interface CredentialBody {
  name: string;
  template_id: string;
  template_version: number;
  host_override: string[];
  fields: Record<string, string>;
  custom_headers: CustomHeader[];
}

export type VaultChoice = { kind: "existing"; id: string; name: string } | { kind: "new"; name: string };

/** The access bundles the new rule goes into; none is a valid choice. */
export interface BundlePlan {
  /** Bundles of the vault to add the rule to. */
  join: { id: string; name: string }[];
  /** A new bundle to create holding the rule. */
  create?: { name: string; description: string };
}

/** How much of the template's scope the new rule allows. */
export type AccessPreset = "full" | "read_only";

export const READ_ONLY_METHODS = ["GET", "HEAD"];

export interface AddServicePlan {
  vault: VaultChoice;
  credential: CredentialBody;
  access: AccessPreset;
  bundles: BundlePlan;
}

export interface AddServiceApi {
  createVault(name: string): Promise<Vault>;
  createCredential(vaultId: string, body: CredentialBody): Promise<CredentialMeta>;
  createRule(vaultId: string, body: { name: string; credential_id: string; methods?: string[] }): Promise<Rule>;
  getBundle(bundleId: string): Promise<AccessBundle>;
  createBundle(vaultId: string, body: { name: string; description: string; rule_ids: string[] }): Promise<AccessBundle>;
  setBundleRules(bundleId: string, ruleIds: string[]): Promise<AccessBundle>;
}

/** What has been created so far; pass it back in to resume. */
export interface AddServiceProgress {
  vault?: { id: string; name: string; created: boolean };
  credential?: CredentialMeta;
  rule?: Rule;
  /** The bundles that hold the rule so far, in the order they were done. */
  bundles?: AccessBundle[];
}

export type AddServiceStep = "vault" | "credential" | "rule" | "bundle";

export class AddServiceError extends Error {
  constructor(
    readonly step: AddServiceStep,
    readonly progress: AddServiceProgress,
    readonly cause: unknown,
    label: string = STEP_LABEL[step],
  ) {
    super(describeFailure(label, progress, cause));
    this.name = "AddServiceError";
  }
}

function reason(cause: unknown): string {
  return cause instanceof Error ? cause.message : String(cause);
}

const STEP_LABEL: Record<AddServiceStep, string> = {
  vault: "creating the vault",
  credential: "saving the service",
  rule: "creating its rule",
  bundle: "adding it to an access bundle",
};

function describeFailure(label: string, progress: AddServiceProgress, cause: unknown): string {
  const done: string[] = [];
  if (progress.vault?.created) done.push(`vault "${progress.vault.name}"`);
  if (progress.credential) done.push(`service "${progress.credential.name}"`);
  if (progress.rule) done.push(`rule "${progress.rule.name}"`);
  const failed = `${label} failed: ${reason(cause)}`;
  if (done.length === 0) return `${failed.charAt(0).toUpperCase()}${failed.slice(1)}`;
  return `Created ${done.join(", ")}, but ${failed}. Try again to continue from that step; nothing is created twice.`;
}

/** The methods the rule is limited to, or `undefined` for the template's. */
export function presetMethods(access: AccessPreset): string[] | undefined {
  return access === "read_only" ? READ_ONLY_METHODS : undefined;
}

async function step<T>(
  name: AddServiceStep,
  progress: AddServiceProgress,
  run: () => Promise<T>,
  label?: string,
): Promise<T> {
  try {
    return await run();
  } catch (e) {
    throw new AddServiceError(name, { ...progress }, e, label);
  }
}

/**
 * Runs the plan, skipping whatever `progress` says is done. Resolves with
 * everything that exists afterwards; rejects with an `AddServiceError`
 * naming the failed step and what was already created.
 */
export async function addService(
  plan: AddServicePlan,
  api: AddServiceApi,
  progress: AddServiceProgress = {},
): Promise<AddServiceProgress> {
  const p: AddServiceProgress = { ...progress };
  if (!p.vault) {
    const choice = plan.vault;
    p.vault =
      choice.kind === "existing"
        ? { id: choice.id, name: choice.name, created: false }
        : await step("vault", p, async () => {
            const v = await api.createVault(choice.name.trim());
            return { id: v.id, name: v.name, created: true };
          });
  }
  const vaultId = p.vault.id;
  if (!p.credential) {
    p.credential = await step("credential", p, () => api.createCredential(vaultId, plan.credential));
  }
  const credential = p.credential;
  if (!p.rule) {
    p.rule = await step("rule", p, () =>
      api.createRule(vaultId, {
        name: credential.name,
        credential_id: credential.id,
        methods: presetMethods(plan.access),
      }),
    );
  }
  const rule = p.rule;
  for (const bundle of plan.bundles.join) {
    if (p.bundles?.some((b) => b.id === bundle.id)) continue;
    const joined = await step(
      "bundle",
      p,
      async () => {
        // Read the bundle just before writing it, so rules added since the
        // page opened are kept.
        const current = await api.getBundle(bundle.id);
        if (current.rule_ids.includes(rule.id)) return current;
        return api.setBundleRules(bundle.id, [...current.rule_ids, rule.id]);
      },
      `adding it to access bundle "${bundle.name}"`,
    );
    p.bundles = [...(p.bundles ?? []), joined];
  }
  const create = plan.bundles.create;
  const name = create?.name.trim();
  if (create && name && !p.bundles?.some((b) => b.name === name)) {
    const created = await step(
      "bundle",
      p,
      () => api.createBundle(vaultId, { name, description: create.description, rule_ids: [rule.id] }),
      `creating access bundle "${name}"`,
    );
    p.bundles = [...(p.bundles ?? []), created];
  }
  return p;
}

// ----- the page's address ------------------------------------------------

/** What the add-service page starts with; anything given is fixed. */
export interface AddServiceContext {
  template?: string;
  vault?: string;
  bundle?: string;
  /** The hash path to return to, such as `vaults/<id>/bundles`. */
  back?: string;
}

/** The hash link to the add-service page for `ctx`. */
export function addServiceHref(ctx: AddServiceContext = {}): string {
  const path = ctx.template ? `#/add-service/${encodeURIComponent(ctx.template)}` : "#/add-service";
  const query = new URLSearchParams();
  if (ctx.vault) query.set("vault", ctx.vault);
  if (ctx.bundle) query.set("bundle", ctx.bundle);
  if (ctx.back) query.set("back", ctx.back);
  const qs = query.toString();
  return qs ? `${path}?${qs}` : path;
}

/** Reads the page's context back from its route part and hash query. */
export function parseAddServiceContext(template: string | undefined, query: URLSearchParams): AddServiceContext {
  const back = query.get("back") ?? undefined;
  return {
    template: template ? decodeURIComponent(template) : undefined,
    vault: query.get("vault") ?? undefined,
    bundle: query.get("bundle") ?? undefined,
    // Only an in-app hash path: never a URL somewhere else.
    back: back && /^[A-Za-z0-9/_-]+$/.test(back) ? back : undefined,
  };
}

/** Whether `name` is already a service in the vault (names are unique per vault). */
export function nameTaken(name: string, taken: readonly string[]): boolean {
  const wanted = name.trim();
  return wanted !== "" && taken.includes(wanted);
}

/** `base`, or the first of "base 2", "base 3", … the vault does not have yet. */
export function freeName(base: string, taken: readonly string[]): string {
  const trimmed = base.trim();
  if (!nameTaken(trimmed, taken)) return trimmed;
  for (let n = 2; ; n++) {
    const candidate = `${trimmed} ${n}`;
    if (!taken.includes(candidate)) return candidate;
  }
}
