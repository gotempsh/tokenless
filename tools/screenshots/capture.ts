// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// Captures the console screenshots the README and the docs use: fills a
// throwaway server with seed.ts, then takes each page in the light theme
// at 1360x780, 2x.
//
//   tokenless serve --data-dir "$(mktemp -d)"     # prints the admin password
//   bun install && TOKENLESS_PASSWORD=... bun capture.ts [name ...]
//
// Writes site/docs/content/screenshots/<name>.png, and the README's
// copies in docs/images, relative to the repository root (OUT_ROOT,
// default ../..). Names limit it to those screenshots; SEED=0 skips the
// seeding, for a server seeded before. The audit export's receiver and
// the identity provider are served from here while it runs.

import { mkdirSync, copyFileSync } from "node:fs";
import { join } from "node:path";
import { chromium, type Page } from "playwright";
import { seed, startFakes } from "./seed.ts";

const BASE = process.env.TOKENLESS_URL ?? "http://127.0.0.1:8080";
const API = `${BASE}/api/v1`;
const ROOT = process.env.OUT_ROOT ?? join(import.meta.dir, "..", "..");
const SHOTS = join(ROOT, "site/docs/content/screenshots");
const README_IMAGES = join(ROOT, "docs/images");
const README_SHOTS = ["console-add-service", "console-vault", "console-run-agent", "console-session", "console-audit"];

type Item = { id: string; name: string; labels?: Record<string, string> };
type Page_<T> = { items: T[] };

interface Ids {
  work: string;
  github: string;
  releaseManager: string;
  standupBot: string;
  standupSession: string;
  releaseSession: string;
  proxy: string;
  destination: string;
  provider: string;
}

async function ids(page: Page): Promise<Ids> {
  const get = async <T>(path: string): Promise<T> => {
    const res = await page.request.get(`${API}${path}`);
    if (!res.ok()) throw new Error(`GET ${path}: ${res.status()} ${await res.text()}`);
    return (await res.json()) as T;
  };
  const named = <T extends { name: string }>(items: T[], name: string): T => {
    const found = items.find((i) => i.name === name);
    if (!found) throw new Error(`no ${name} among ${items.map((i) => i.name).join(", ")}`);
    return found;
  };
  const vaults = await get<Page_<Item>>("/vaults");
  const work = named(vaults.items, "work").id;
  const credentials = await get<Page_<Item>>(`/vaults/${work}/credentials`);
  const bundles = await get<Page_<Item>>(`/vaults/${work}/bundles`);
  const sessions = await get<Page_<Item>>(`/vaults/${work}/sessions?page_size=100`);
  const session = (name: string) => {
    const s = sessions.items.find((i) => i.labels?.name === name);
    if (!s) throw new Error(`no session named ${name}`);
    return s.id;
  };
  const nodes = await get<Page_<Item>>("/nodes");
  const destinations = await get<Item[]>("/audit-export/destinations");
  const providers = await get<Item[] | Page_<Item>>("/identity-providers");
  const providerList = Array.isArray(providers) ? providers : providers.items;
  return {
    work,
    github: named(credentials.items, "github").id,
    releaseManager: named(bundles.items, "release-manager").id,
    standupBot: named(bundles.items, "standup-bot").id,
    standupSession: session("standup-bot"),
    releaseSession: session("release-agent"),
    proxy: nodes.items[0].id,
    destination: named(destinations, "Security team SIEM").id,
    provider: named(providerList, "Keycloak").id,
  };
}

interface Shot {
  name: string;
  hash: (ids: Ids) => string;
  /** What to do on the page before the picture. */
  then?: (page: Page) => Promise<void>;
}

/** Taken while the tripwire's alert is open; it is acknowledged after. */
const WITH_ALERT: Shot[] = [
  { name: "console-alerts", hash: () => "/alerts" },
  { name: "console-vault-tripwires", hash: (i) => `/vaults/${i.work}/tripwires` },
];

const SHOTS_LIST: Shot[] = [
  { name: "console-vaults", hash: () => "/vaults" },
  { name: "console-vault", hash: (i) => `/vaults/${i.work}` },
  { name: "console-vault-services", hash: (i) => `/vaults/${i.work}/credentials` },
  { name: "console-vault-rules", hash: (i) => `/vaults/${i.work}/rules` },
  { name: "console-service", hash: (i) => `/vaults/${i.work}/services/${i.github}` },
  {
    name: "console-session-logs",
    hash: (i) => `/vaults/${i.work}/services/${i.github}`,
    then: async (page) => {
      await page.getByRole("heading", { name: "Logs" }).scrollIntoViewIfNeeded();
      await page.mouse.wheel(0, 260);
    },
  },
  { name: "console-add-service", hash: (i) => `/add-service?vault=${i.work}` },
  {
    name: "console-add-service-catalogue",
    hash: (i) => `/add-service?vault=${i.work}`,
    then: async (page) => {
      await page.getByRole("button", { name: /LLM providers/ }).first().click();
    },
  },
  { name: "console-bundles", hash: () => "/bundles" },
  { name: "console-bundle-services", hash: (i) => `/bundles/${i.releaseManager}/services` },
  { name: "console-bundle-run-agent", hash: (i) => `/bundles/${i.releaseManager}/connect` },
  { name: "console-sessions", hash: () => "/sessions" },
  {
    name: "console-new-session",
    hash: () => "/sessions",
    then: async (page) => {
      await page.getByRole("button", { name: "New session" }).first().click();
      const dialog = page.getByRole("dialog");
      await dialog.waitFor();
      await dialog.getByText("standup-bot").first().click();
      await dialog.getByLabel("Name").fill("laptop-claude");
      // Back to the top, so the dialog's title shows.
      await dialog.evaluate((el) => {
        for (const e of [el, ...el.querySelectorAll("*")]) if (e.scrollTop > 0) e.scrollTop = 0;
      });
    },
  },
  { name: "console-session", hash: (i) => `/sessions/${i.standupSession}` },
  { name: "console-session-page", hash: (i) => `/sessions/${i.releaseSession}` },
  { name: "console-templates", hash: () => "/templates" },
  { name: "console-variables", hash: () => "/variables" },
  { name: "console-people", hash: () => "/people" },
  { name: "console-api-keys", hash: () => "/api-keys" },
  { name: "console-proxies", hash: () => "/proxies" },
  { name: "console-proxy", hash: (i) => `/proxies/${i.proxy}` },
  { name: "console-audit", hash: () => "/audit" },
  {
    name: "console-audit-log",
    hash: () => "/audit",
    then: async (page) => {
      await page.getByRole("combobox").first().click();
      await page.getByRole("option", { name: "Agent requests" }).click();
    },
  },
  {
    name: "console-audit-event",
    hash: () => "/audit",
    then: async (page) => {
      await page.getByRole("combobox").first().click();
      await page.getByRole("option", { name: "Agent requests" }).click();
      await page.getByText(/got a 401 for GET api\.stripe\.com/).first().click();
      await page.getByRole("dialog").waitFor();
    },
  },
  { name: "console-audit-export", hash: (i) => `/settings/audit-export/${i.destination}` },
  { name: "console-settings", hash: () => "/settings" },
  { name: "console-sso-provider", hash: (i) => `/settings/sso/${i.provider}` },
  { name: "console-account", hash: () => "/account" },
  // Last: it starts a session, which would show on the other pages.
  {
    name: "console-run-agent",
    hash: (i) => `/bundles/${i.standupBot}/connect`,
    then: async (page) => {
      await page.getByRole("button", { name: "New session" }).first().click();
      await page.getByRole("dialog").getByRole("button", { name: "Create session" }).click();
      const created = page.getByRole("dialog", { name: "Session created" });
      await created.waitFor();
      // The address a default install's agents reach, whatever this
      // server's proxy listens on.
      await created.locator("#handoff-proxy").fill("127.0.0.1:3128");
      await created.getByRole("heading", { name: "Session created" }).click();
    },
  },
];

const only = new Set(process.argv.slice(2));
const fakes = startFakes(18799, 18180);
if (process.env.SEED !== "0") await seed(fakes);

const browser = await chromium.launch();
const context = await browser.newContext({
  viewport: { width: 1360, height: 780 },
  deviceScaleFactor: 2,
  colorScheme: "light",
  reducedMotion: "reduce",
});
await context.addInitScript(() => window.localStorage.setItem("tokenless.theme", "light"));
const page = await context.newPage();
const login = await page.request.post(`${API}/auth/login`, {
  data: { username: process.env.TOKENLESS_USERNAME ?? "admin", password: process.env.TOKENLESS_PASSWORD },
});
if (!login.ok()) throw new Error(`sign-in failed: ${login.status()} ${await login.text()}`);
const { csrf_token } = (await login.json()) as { csrf_token: string };
const found = await ids(page);

mkdirSync(SHOTS, { recursive: true });
mkdirSync(README_IMAGES, { recursive: true });

async function take(shot: Shot) {
  if (only.size > 0 && !only.has(shot.name)) return;
  await page.goto(`${BASE}/#${shot.hash(found)}`);
  await page.waitForLoadState("networkidle");
  await page.locator("main").first().waitFor();
  // Let the data load and the relative times settle.
  await page.waitForTimeout(800);
  try {
    await shot.then?.(page);
  } catch (e) {
    console.error(`${shot.name}: ${(e as Error).message}`);
    return;
  }
  await page.waitForTimeout(500);
  const out = join(SHOTS, `${shot.name}.png`);
  await page.screenshot({ path: out });
  if (README_SHOTS.includes(shot.name)) copyFileSync(out, join(README_IMAGES, `${shot.name}.png`));
  console.log(out);
}

for (const shot of WITH_ALERT) await take(shot);
const alerts = await page.request.get(`${API}/alerts`);
for (const alert of ((await alerts.json()) as Page_<Item>).items) {
  await page.request.post(`${API}/alerts/${alert.id}/acknowledge`, { headers: { "x-csrf-token": csrf_token }, data: {} });
}
for (const shot of SHOTS_LIST) await take(shot);
await browser.close();
fakes.audit.stop();
fakes.idp.stop();
