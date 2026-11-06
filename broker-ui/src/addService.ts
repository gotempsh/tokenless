// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// "Add a service to a vault and a bundle" in one go: the vault (new or
// existing), the credential, a rule for it and its place in an access
// bundle. Each step that succeeded is remembered, so trying again after a
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

export type BundleChoice =
  | { kind: "none" }
  | { kind: "existing"; id: string; name: string }
  | { kind: "new"; name: string; description: string };

/** How much of the template's scope the new rule allows. */
export type AccessPreset = "full" | "read_only";

export const READ_ONLY_METHODS = ["GET", "HEAD"];

export interface AddServicePlan {
  vault: VaultChoice;
  credential: CredentialBody;
  access: AccessPreset;
  bundle: BundleChoice;
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
  bundle?: AccessBundle;
}

export type AddServiceStep = "vault" | "credential" | "rule" | "bundle";

export class AddServiceError extends Error {
  constructor(
    readonly step: AddServiceStep,
    readonly progress: AddServiceProgress,
    readonly cause: unknown,
  ) {
    super(describeFailure(step, progress, cause));
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
  bundle: "adding it to the access bundle",
};

function describeFailure(step: AddServiceStep, progress: AddServiceProgress, cause: unknown): string {
  const done: string[] = [];
  if (progress.vault?.created) done.push(`vault "${progress.vault.name}"`);
  if (progress.credential) done.push(`service "${progress.credential.name}"`);
  if (progress.rule) done.push(`rule "${progress.rule.name}"`);
  const failed = `${STEP_LABEL[step]} failed: ${reason(cause)}`;
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
): Promise<T> {
  try {
    return await run();
  } catch (e) {
    throw new AddServiceError(name, { ...progress }, e);
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
  const bundle = plan.bundle;
  if (!p.bundle && bundle.kind !== "none") {
    p.bundle = await step("bundle", p, async () => {
      if (bundle.kind === "new") {
        return api.createBundle(vaultId, {
          name: bundle.name.trim(),
          description: bundle.description,
          rule_ids: [rule.id],
        });
      }
      // Read the bundle just before writing it, so rules added since the
      // dialog opened are kept.
      const current = await api.getBundle(bundle.id);
      if (current.rule_ids.includes(rule.id)) return current;
      return api.setBundleRules(bundle.id, [...current.rule_ids, rule.id]);
    });
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
