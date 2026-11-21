// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// Build broker-ui, then run "bun rule-editor.ts" here with Chromium installed.
import assert from "node:assert/strict";
import { join } from "node:path";
import { chromium } from "playwright";

const browser = await chromium.launch();
try {
  const page = await browser.newPage();
  const origin = "http://console.test";
  const dist = join(import.meta.dir, "../../broker-ui/dist");
  const release = Promise.withResolvers<void>();
  const rejectConflict = Promise.withResolvers<void>();
  const releaseOther = Promise.withResolvers<void>();
  const revision = (n: number) => `2026-01-01T00:00:00.12345${n}Z`;
  let currentRevision = revision(6);
  let latestName: string | undefined;
  const rejectDelete = Promise.withResolvers<void>();
  let deleteAttempts = 0;
  const deleted = new Set<string>();
  const patches: string[] = [];
  const creates: unknown[] = [];
  let templateLoads = 0;
  const rule = (vault: string) => ({
    id: vault + "-rule", name: (vault === "b" && latestName) || vault + "-read", credential_id: "service", vault_id: vault,
    updated_at: currentRevision, enabled: vault !== "a", allow: { ...(vault === "a" ? { mcp_tools: [], git: { repositories: ["example/repo"], push: false } } : {}), hosts: ["api.example.com"], paths: ["/reports "], methods: ["GET"] },
  });
  await page.route(origin + "/**", async route => {
    const path = new URL(route.request().url()).pathname;
    if (!path.startsWith("/api/v1/")) {
      return route.fulfill({ path: join(dist, path === "/" ? "index.html" : path) });
    }
    const [, , , resource, id, section] = path.split("/");
    if (resource === "auth") return route.fulfill({ json: {
      user: { username: "editor", role: "user" }, csrf_token: "test",
      vaults: ["a", "b"].map(vault_id => ({ vault_id, role: "editor" })),
    } });
    if (resource === "rules" && deleted.has(id)) return route.fulfill({ status: 404, body: "already deleted" });
    if (resource === "rules" && id === "b-rule" && route.request().method() === "DELETE") {
      deleted.add(id);
      return route.fulfill({ status: 503, body: "upstream response lost" });
    }
    if (resource === "rules" && id === "other-rule") {
      const method = route.request().method();
      if (method === "GET") return route.fulfill({ json: rule("other") });
      if (method === "DELETE") {
        deleteAttempts++;
        if (deleteAttempts === 2) {
          deleted.add(id);
          return route.fulfill({ status: 404, body: "already deleted" });
        }
        await rejectDelete.promise;
      }
      if (method === "DELETE" || route.request().postDataJSON().enabled === false) {
        const detail = method === "DELETE" ? "Delete failed" : "Toggle failed";
        return route.fulfill({ status: 503, json: { status: 503, code: "unavailable", title: "Unavailable", detail } });
      }
      await releaseOther.promise;
      return route.fulfill({ json: rule("other") });
    }
    if (resource === "rules" && route.request().method() === "GET") return route.fulfill({ json: rule("b") });
    if (resource === "rules" && route.request().method() === "PATCH") {
      patches.push(id);
      if (patches.length === 2) return; // Leave the second request pending until its real deadline.
      if (patches.length === 3 || patches.length === 5) {
        await rejectConflict.promise;
        currentRevision = revision(patches.length === 3 ? 7 : 8);
        latestName = patches.length === 3 ? "concurrent rename" : "latest rename";
        return route.fulfill({ status: 409, json: {
          status: 409, code: "conflict", title: "Conflict", detail: "The rule revision changed.",
        } });
      }
      await release.promise;
      return route.fulfill({ json: rule("b") });
    }
    if (section === "rules" && route.request().method() === "POST") {
      creates.push(route.request().postDataJSON());
      return route.fulfill({ status: 201, json: { ...rule(id), id: "new-rule" } });
    }
    if (section === "credentials") return route.fulfill({ json: {
      items: [{ id: "service", name: "Example", template_id: "example" }], total: 1, page: 1, page_size: 100,
    } });
    if (section === "overview") return route.fulfill({ json: { id, name: id, service_count: 1 } });
    if (resource === "templates") {
      templateLoads++;
      return route.fulfill({ json: [] });
    }
    const items = section === "rules" ? (id === "b" ? [rule(id), rule("other")] : [rule(id)]).filter(r => !deleted.has(r.id)) : [];
    return route.fulfill({ json: { items, total: items.length, page: 1, page_size: 20 } });
  });
  const closeEditor = async () => {
    await page.locator('[role="menu"]').waitFor({ state: "detached" });
    await page.keyboard.press("Escape");
    await page.getByRole("dialog", { includeHidden: true }).waitFor({ state: "detached" });
  };
  const edit = async (vault: string) => {
    await page.getByRole("button", { name: "Actions for " + vault + "-read" }).click();
    await page.getByRole("menuitem", { name: "Edit rule" }).click();
  };
  await page.goto(origin + "/#/vaults/a/rules");
  // Exercise the dialog transitions independently of the theme’s entrance and exit animations.
  await page.addStyleTag({ content: "*, *::before, *::after { animation: none !important; transition: none !important; }" });
  await edit("a");
  const save = page.getByRole("button", { name: "Save changes" });
  assert.equal(await save.isDisabled(), true);
  await page.locator("#rule-name").fill("changed");
  for (const field of ["hosts", "paths", "methods"]) {
    const input = page.locator("#rule-" + field);
    const value = await input.inputValue();
    await input.fill(" ");
    assert.equal(await save.isDisabled(), true, field + " must have a value");
    await input.fill(value);
    assert.equal(await save.isEnabled(), true);
  }

  await page.evaluate(() => { location.hash = "/vaults/b/rules"; });
  assert.deepEqual(patches, []);
  await edit("b");
  assert.equal(await page.locator("#rule-name").inputValue(), "b-read");
  await page.locator("#rule-name").fill("renamed");
  await page.locator("#rule-paths").fill("/reports \n/health");
  const [request] = await Promise.all([page.waitForRequest(r => r.method() === "PATCH"), save.click()]);
  assert.deepEqual(request.postDataJSON(), {
    expected_updated_at: rule("b").updated_at, name: "renamed", paths: ["/reports ", "/health"],
  });
  assert.equal(await page.getByRole("button", { name: "Close", exact: true }).first().isEnabled(), true);
  for (const field of ["name", "hosts", "paths", "methods"]) {
    assert.equal(await page.locator("#rule-" + field).isDisabled(), true);
  }
  await closeEditor();
  await edit("b");
  await page.locator("#rule-name").fill("next draft");
  await Promise.all([page.waitForResponse(r => r.url().includes("/vaults/b/rules?")), Promise.resolve().then(() => release.resolve())]);
  assert.equal(await page.locator("#rule-name").inputValue(), "next draft");
  await closeEditor();
  assert.deepEqual(patches, ["b-rule"]);
  await edit("b");
  await page.locator("#rule-name").fill("timeout draft");
  await Promise.all([page.waitForRequest(r => r.method() === "PATCH"), save.click()]);
  await closeEditor();
  await page.getByText(/Saving rule "timeout draft".*timed out/).waitFor({ timeout: 45_000 });
  await edit("other");
  await page.locator("#rule-name").fill("older save");
  await Promise.all([page.waitForRequest(r => r.method() === "PATCH"), save.click()]);
  await closeEditor();
  await edit("b");
  await page.locator("#rule-paths").fill("/narrow");
  await Promise.all([page.waitForRequest(r => r.method() === "PATCH"), save.click()]);
  await closeEditor();
  rejectConflict.resolve();
  await page.getByText(/Saving rule "b-read".*The rule revision changed/).waitFor();
  await page.getByRole("button", { name: "Actions for concurrent rename" }).click();
  await page.getByRole("menuitem", { name: "Edit rule" }).click();
  assert.equal(await page.locator("#rule-name").inputValue(), "concurrent rename");
  assert.equal(await page.locator("#rule-paths").inputValue(), "/reports ");
  await page.locator("#rule-paths").fill("/reopened");
  const [reopened] = await Promise.all([page.waitForRequest(r => r.method() === "PATCH"), save.click()]);
  assert.equal(reopened.postDataJSON().expected_updated_at, revision(7));
  await page.getByRole("dialog").waitFor({ state: "hidden" });

  await page.getByRole("button", { name: "Actions for concurrent rename" }).click();
  await page.getByRole("menuitem", { name: "Edit rule" }).click();
  await page.locator("#rule-paths").fill("/pending");
  await save.click();
  const reload = page.getByRole("button", { name: "Reload rule" });
  await reload.waitFor();
  assert.equal(await save.isDisabled(), true);
  await reload.click();
  await reload.waitFor({ state: "hidden" });
  assert.equal(await page.locator("#rule-name").inputValue(), "latest rename");
  assert.equal(await page.locator("#rule-paths").inputValue(), "/pending");
  const [retry] = await Promise.all([page.waitForRequest(r => r.method() === "PATCH"), save.click()]);
  assert.deepEqual(retry.postDataJSON(), { expected_updated_at: revision(8), paths: ["/pending"] });
  await page.getByRole("dialog").waitFor({ state: "hidden" });
  await Promise.all([page.waitForResponse(r => r.url().includes("/vaults/b/rules?")), Promise.resolve().then(() => releaseOther.resolve())]);
  const conflict = page.getByText(/Saving rule "b-read".*The rule revision changed/);
  await conflict.waitFor();
  await page.getByRole("switch", { name: "Turn off other-read" }).click();
  await page.getByText("Unavailable: Toggle failed", { exact: true }).waitFor();
  assert.equal(await conflict.isVisible(), true);
  await page.getByRole("button", { name: "Actions for other-read" }).click();
  await page.getByRole("menuitem", { name: "Delete rule" }).click();
  const deletion = page.getByRole("dialog");
  const submitDelete = deletion.getByRole("button", { name: "Delete rule" });
  await Promise.all([page.waitForRequest(r => r.method() === "DELETE"), submitDelete.click()]);
  await deletion.getByRole("button", { name: "Cancel" }).click();
  await page.keyboard.press("Escape");
  await deletion.getByRole("button", { name: "Close" }).click();
  assert.equal(await submitDelete.isDisabled(), true);
  rejectDelete.resolve();
  await deletion.getByText("Unavailable: Delete failed", { exact: true }).waitFor();
  await submitDelete.click();
  await deletion.waitFor({ state: "hidden" });
  assert.equal(deleteAttempts, 2);
  await page.getByRole("button", { name: "Actions for other-read" }).waitFor({ state: "hidden" });
  await page.getByRole("button", { name: "Actions for latest rename" }).click();
  await page.getByRole("menuitem", { name: "Delete rule" }).click();
  await submitDelete.click();
  await deletion.waitFor({ state: "hidden" });
  await page.getByRole("button", { name: "Actions for latest rename" }).waitFor({ state: "hidden" });
  assert.equal(await conflict.isVisible(), true);
  assert.equal(templateLoads, 0);
  await Promise.all([
    page.waitForResponse(r => new URL(r.url()).pathname === "/api/v1/templates"),
    page.getByRole("button", { name: "Add rule" }).first().click(),
  ]);
  assert.equal(templateLoads, 1);
  await closeEditor();
  await page.evaluate(() => { location.hash = "/vaults/a/rules"; });
  const duplicate = async () => {
    await page.getByRole("button", { name: "Actions for a-read" }).click();
    await page.getByRole("menuitem", { name: "Duplicate rule" }).click();
    await page.getByRole("dialog", { name: "Duplicate rule" }).waitFor();
  };
  await duplicate();
  assert.equal(await page.locator("#rule-name").inputValue(), "a-read (copy)");
  assert.equal(await page.locator("#rule-paths").inputValue(), "/reports ");
  assert.match(await page.locator("#rule-cred").innerText(), /Example/);
  await closeEditor();
  assert.equal(creates.length, 0);
  await duplicate();
  assert.equal(await page.locator("#rule-git-repos").inputValue(), "example/repo");
  assert.equal(await page.getByRole("switch", { name: "Enabled", exact: true }).isChecked(), false);
  assert.equal(await page.getByRole("switch", { name: "Limit MCP tools" }).isChecked(), true);
  await page.locator("#rule-git-repos").fill("example/another");
  await page.locator("#rule-name").fill("another rule");
  await page.locator("#rule-methods").fill("HEAD");
  await page.getByRole("button", { name: "Create rule" }).click();
  await page.getByRole("dialog").waitFor({ state: "hidden" });
  assert.deepEqual(creates, [{ name: "another rule", credential_id: "service",
    hosts: ["api.example.com"], paths: ["/reports "], methods: ["HEAD"], enabled: false,
    mcp_tools: [], git: { repositories: ["example/another"], push: false },
  }]);
  console.log("Passed: scope validation, vault navigation, save recovery, and editable rule duplication.");
} finally {
  await browser.close();
}
