// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import { describe, expect, test } from "bun:test";
import type { AccessBundle, CredentialMeta, Rule, Vault } from "./api";
import {
  addService,
  freeName,
  nameTaken,
  AddServiceError,
  addServiceHref,
  parseAddServiceContext,
  type AddServiceApi,
  type AddServicePlan,
} from "./addService";

const at = "2026-01-01T00:00:00Z";

/** An in-memory API that records calls and can fail one of them once. */
function fakeApi(failOnce?: keyof AddServiceApi) {
  const calls: string[] = [];
  const bundles = new Map<string, AccessBundle>([
    ["b1", { id: "b1", vault_id: "v1", name: "code-review", description: "", rule_ids: ["r0"], created_by: "u", created_at: at, updated_at: at }],
  ]);
  let failed = false;
  const guard = (name: keyof AddServiceApi) => {
    calls.push(name);
    if (name === failOnce && !failed) {
      failed = true;
      throw new Error(`${name} refused`);
    }
  };
  const api: AddServiceApi = {
    async createVault(name) {
      guard("createVault");
      return { id: "v-new", name, scope: "vault:v-new", created_at: at } satisfies Vault;
    },
    async createCredential(vaultId, body) {
      guard("createCredential");
      return {
        id: "c1",
        vault_id: vaultId,
        name: body.name,
        template_id: body.template_id,
        template_version: body.template_version,
        host_override: [],
        field_names: Object.keys(body.fields),
        custom_headers: [],
        variable_refs: [],
        substitutions: [],
        created_by: "u",
        created_at: at,
        updated_at: at,
      } satisfies CredentialMeta;
    },
    async createRule(vaultId, body) {
      guard("createRule");
      return {
        id: "r1",
        vault_id: vaultId,
        credential_id: body.credential_id,
        name: body.name,
        allow: { hosts: ["api.example.com"], paths: ["/*"], methods: body.methods ?? ["*"] },
        enabled: true,
        created_by: "u",
        created_at: at,
        updated_at: at,
      } satisfies Rule;
    },
    async getBundle(id) {
      guard("getBundle");
      const b = bundles.get(id);
      if (!b) throw new Error(`bundle ${id} not found`);
      return b;
    },
    async createBundle(vaultId, body) {
      guard("createBundle");
      const b = { id: "b-new", vault_id: vaultId, ...body, created_by: "u", created_at: at, updated_at: at };
      bundles.set(b.id, b);
      return b;
    },
    async setBundleRules(id, ruleIds) {
      guard("setBundleRules");
      const b = bundles.get(id);
      if (!b) throw new Error(`bundle ${id} not found`);
      const updated = { ...b, rule_ids: ruleIds };
      bundles.set(id, updated);
      return updated;
    },
  };
  return { api, calls, bundles };
}

const credential = {
  name: "Example API",
  template_id: "example",
  template_version: 1,
  host_override: [],
  fields: { token: "s3cret" },
  custom_headers: [],
};

describe("addService", () => {
  test("adds a read-only service to an existing bundle, keeping its rules", async () => {
    const { api, calls } = fakeApi();
    const plan: AddServicePlan = {
      vault: { kind: "existing", id: "v1", name: "main" },
      credential,
      access: "read_only",
      bundle: { kind: "existing", id: "b1", name: "code-review" },
    };
    const done = await addService(plan, api);
    expect(calls).toEqual(["createCredential", "createRule", "getBundle", "setBundleRules"]);
    expect(done.rule?.allow.methods).toEqual(["GET", "HEAD"]);
    expect(done.rule?.name).toBe("Example API");
    expect(done.bundle?.rule_ids).toEqual(["r0", "r1"]);
  });

  test("creates the vault and a new bundle", async () => {
    const { api, calls } = fakeApi();
    const done = await addService(
      {
        vault: { kind: "new", name: "  agents  " },
        credential,
        access: "full",
        bundle: { kind: "new", name: "research", description: "" },
      },
      api,
    );
    expect(calls).toEqual(["createVault", "createCredential", "createRule", "createBundle"]);
    expect(done.vault).toEqual({ id: "v-new", name: "agents", created: true });
    expect(done.rule?.allow.methods).toEqual(["*"]);
    expect(done.bundle).toMatchObject({ vault_id: "v-new", name: "research", rule_ids: ["r1"] });
  });

  test("skips the bundle when none is chosen", async () => {
    const { api, calls } = fakeApi();
    const done = await addService(
      { vault: { kind: "existing", id: "v1", name: "main" }, credential, access: "full", bundle: { kind: "none" } },
      api,
    );
    expect(calls).toEqual(["createCredential", "createRule"]);
    expect(done.bundle).toBeUndefined();
  });

  test("a failed step names what exists, and a retry resumes without duplicates", async () => {
    const { api, calls } = fakeApi("createRule");
    const plan: AddServicePlan = {
      vault: { kind: "existing", id: "v1", name: "main" },
      credential,
      access: "full",
      bundle: { kind: "existing", id: "b1", name: "code-review" },
    };
    let error: unknown;
    try {
      await addService(plan, api);
    } catch (e) {
      error = e;
    }
    expect(error).toBeInstanceOf(AddServiceError);
    const failure = error as AddServiceError;
    expect(failure.step).toBe("rule");
    expect(failure.message).toBe(
      'Created service "Example API", but creating its rule failed: createRule refused. Try again to continue from that step; nothing is created twice.',
    );
    expect(failure.progress.credential?.id).toBe("c1");

    const done = await addService(plan, api, failure.progress);
    expect(calls.filter((c) => c === "createCredential")).toHaveLength(1);
    expect(done.bundle?.rule_ids).toEqual(["r0", "r1"]);
  });

  test("a failure on the first step reads as a plain error", async () => {
    const { api } = fakeApi("createVault");
    const run = addService(
      { vault: { kind: "new", name: "x" }, credential, access: "full", bundle: { kind: "none" } },
      api,
    );
    await expect(run).rejects.toThrow("Creating the vault failed: createVault refused");
  });

  test("adding a rule that is already in the bundle does not write it again", async () => {
    const { api, calls, bundles } = fakeApi();
    const existing = bundles.get("b1");
    if (existing) bundles.set("b1", { ...existing, rule_ids: ["r0", "r1"] });
    await addService(
      {
        vault: { kind: "existing", id: "v1", name: "main" },
        credential,
        access: "full",
        bundle: { kind: "existing", id: "b1", name: "code-review" },
      },
      api,
    );
    expect(calls).not.toContain("setBundleRules");
  });
});

describe("add-service links", () => {
  test("round-trip the context through the hash", () => {
    const href = addServiceHref({ template: "github", vault: "v1", bundle: "b1", back: "vaults/v1/bundles" });
    expect(href).toBe("#/add-service/github?vault=v1&bundle=b1&back=vaults%2Fv1%2Fbundles");
    const [path, qs = ""] = href.slice(2).split("?");
    const template = path?.split("/")[1];
    expect(parseAddServiceContext(template, new URLSearchParams(qs))).toEqual({
      template: "github",
      vault: "v1",
      bundle: "b1",
      back: "vaults/v1/bundles",
    });
  });

  test("the catalogue link has no query when nothing is fixed", () => {
    expect(addServiceHref()).toBe("#/add-service");
  });

  test("a return path that is not an in-app route is dropped", () => {
    const ctx = parseAddServiceContext(undefined, new URLSearchParams("back=https://example.com/x"));
    expect(ctx.back).toBeUndefined();
  });
});

describe("service names", () => {
  test("a name is taken only by an exact match, ignoring surrounding space", () => {
    expect(nameTaken(" GitHub ", ["GitHub"])).toBe(true);
    expect(nameTaken("github", ["GitHub"])).toBe(false);
    expect(nameTaken("  ", ["GitHub"])).toBe(false);
  });

  test("the suggestion is the template name, or the first free numbered one", () => {
    expect(freeName("GitHub", [])).toBe("GitHub");
    expect(freeName("GitHub", ["GitHub"])).toBe("GitHub 2");
    expect(freeName("GitHub", ["GitHub", "GitHub 2", "GitHub1"])).toBe("GitHub 3");
  });
});
