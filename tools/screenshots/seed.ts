// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// Fills a throwaway tokenless server with the example data the console
// screenshots show: two vaults, catalogue services with made-up secrets,
// bundles, API keys, sessions with real traffic through the built-in proxy,
// a tripwire that went off, an audit export and a single sign-on provider.
//
// Never point it at a server someone uses: it creates all of the above.
//
// capture.ts runs it before taking the pictures.
//
// TOKENLESS_URL (default http://127.0.0.1:8080) is the server,
// TOKENLESS_PROXY_ADDRESS (default 127.0.0.1:3128) its built-in proxy and
// TOKENLESS_BIN (default `tokenless`) the binary whose `run` sends the
// traffic. The secrets are fake, so the APIs answer 401; that is still
// traffic, which is what the pages show.

import { spawnSync } from "node:child_process";

const BASE = process.env.TOKENLESS_URL ?? "http://127.0.0.1:8080";
const API = `${BASE}/api/v1`;
const BIN = process.env.TOKENLESS_BIN ?? "tokenless";
const USERNAME = process.env.TOKENLESS_USERNAME ?? "admin";
const PASSWORD = process.env.TOKENLESS_PASSWORD;

type Json = Record<string, unknown>;

let cookie = "";
let csrf = "";

async function call<T = Json>(method: string, path: string, body?: unknown, apiKey?: string): Promise<T> {
  const headers: Record<string, string> = { "content-type": "application/json", "user-agent": "tokenless-screenshots" };
  if (apiKey) headers.authorization = `Bearer ${apiKey}`;
  else {
    if (cookie) headers.cookie = cookie;
    if (csrf) headers["x-csrf-token"] = csrf;
  }
  const res = await fetch(`${API}${path}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  const text = await res.text();
  if (!res.ok) throw new Error(`${method} ${path}: ${res.status} ${text}`);
  const setCookie = res.headers.get("set-cookie");
  if (setCookie) cookie = setCookie.split(";")[0];
  return (text ? JSON.parse(text) : {}) as T;
}

const post = <T = Json>(path: string, body: unknown = {}, apiKey?: string) => call<T>("POST", path, body, apiKey);

/** A local endpoint for the audit export and the identity provider's discovery document. */
export function startFakes(auditPort: number, idpPort: number) {
  const received: unknown[] = [];
  const audit = Bun.serve({
    port: auditPort,
    hostname: "127.0.0.1",
    async fetch(req) {
      received.push(await req.text());
      return new Response(null, { status: 204 });
    },
  });
  const issuer = `http://127.0.0.1:${idpPort}/realms/tokenless`;
  const idp = Bun.serve({
    port: idpPort,
    hostname: "127.0.0.1",
    fetch(req) {
      const url = new URL(req.url);
      if (url.pathname.endsWith("/.well-known/openid-configuration")) {
        return Response.json({
          issuer,
          authorization_endpoint: `${issuer}/protocol/openid-connect/auth`,
          token_endpoint: `${issuer}/protocol/openid-connect/token`,
          jwks_uri: `${issuer}/protocol/openid-connect/certs`,
          response_types_supported: ["code"],
          subject_types_supported: ["public"],
          id_token_signing_alg_values_supported: ["RS256"],
        });
      }
      if (url.pathname.endsWith("/certs")) return Response.json({ keys: [] });
      return new Response("not found", { status: 404 });
    },
  });
  return { audit, idp, issuer, auditUrl: `http://localhost:${auditPort}/tokenless-audit` };
}

/**
 * Runs `bin` and returns what it printed. Throws when it could not be
 * started or exited non-zero: curl exits 0 on a 401 or a refusal, so a
 * failure means no traffic was recorded and the pictures would be empty.
 */
export function runChecked(bin: string, args: string[], env: Record<string, string | undefined> = process.env): string {
  const r = spawnSync(bin, args, { env, encoding: "utf8" });
  if (r.error) throw new Error(`could not run ${bin} (set TOKENLESS_BIN to the tokenless binary): ${r.error.message}`);
  if (r.status !== 0) {
    const why = r.status === null ? `was killed by ${r.signal}` : `exited ${r.status}`;
    throw new Error(`${bin} ${args.join(" ")} ${why}: ${(r.stderr || r.stdout).trim()}`);
  }
  return r.stdout.trim();
}

/** Runs `curl` behind a session through `tokenless run`, as an agent would. */
function agent(token: string, ...requests: string[][]) {
  const env = { ...process.env, TOKENLESS_URL: BASE, TOKENLESS_SESSION_TOKEN: token, TOKENLESS_NO_SKILL_HINT: "1" };
  for (const args of requests) {
    const status = runChecked(BIN, ["run", "--", "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}\\n", "--max-time", "20", ...args], env);
    console.log(`  ${args.at(-1)} -> ${status}`);
  }
}

export async function seed(fakes: ReturnType<typeof startFakes>) {
  if (!PASSWORD) throw new Error("set TOKENLESS_PASSWORD to the password `tokenless serve` printed");
  // Before anything is created: a server seeded halfway cannot be seeded again.
  runChecked(BIN, ["--version"]);
  const login = await post<{ csrf_token: string }>("/auth/login", { username: USERNAME, password: PASSWORD });
  csrf = login.csrf_token;

  const vault = (name: string) => post<{ id: string }>("/vaults", { name });
  const work = await vault("work");
  const personal = await vault("personal");

  const service = async (v: string, name: string, template: string, fields: Json) =>
    post<{ id: string }>(`/vaults/${v}/credentials`, { name, template_id: template, fields });
  const slack = await service(work.id, "slack-bot", "slack", { token: "xoxb-0000000000-example-not-a-token" });
  const stripe = await service(work.id, "stripe-test", "stripe", { secret_key: "sk_test_example_not_a_key" });
  const openai = await service(work.id, "openai", "openai", { api_key: "sk-example-not-a-key" });
  const github = await service(work.id, "github", "github", { token: "ghp_example_not_a_token" });
  const anthropic = await service(personal.id, "anthropic", "anthropic", { api_key: "sk-ant-example-not-a-key" });

  const rule = (v: string, name: string, credential_id: string, extra: Json = {}) =>
    post<{ id: string }>(`/vaults/${v}/rules`, { name, credential_id, ...extra });
  const slackRead = await rule(work.id, "slack-post-and-read", slack.id, {
    methods: ["GET", "POST"],
    paths: ["/api/chat.postMessage", "/api/conversations.history", "/api/conversations.list"],
  });
  const slackAll = await rule(work.id, "slack-bot", slack.id);
  const stripeRule = await rule(work.id, "stripe-test", stripe.id);
  const openaiRule = await rule(work.id, "openai", openai.id);
  const githubRule = await rule(work.id, "github", github.id);
  const anthropicRule = await rule(personal.id, "anthropic", anthropic.id);

  const bundle = (v: string, name: string, description: string, rule_ids: string[]) =>
    post<{ id: string; name: string }>(`/vaults/${v}/bundles`, { name, description, rule_ids });
  await bundle(work.id, "billing-agent", "Answer billing questions from Stripe", [openaiRule.id, stripeRule.id]);
  await bundle(work.id, "code-review", "Read repositories and post review comments", [githubRule.id]);
  await bundle(work.id, "release-manager", "Tag releases, publish notes, announce them", [
    openaiRule.id,
    githubRule.id,
    stripeRule.id,
    slackAll.id,
  ]);
  await bundle(work.id, "standup-bot", "Read the team channel and post the daily summary", [slackRead.id]);
  await bundle(work.id, "support-triage", "Summarise tickets with an LLM", [openaiRule.id, slackAll.id]);
  await bundle(personal.id, "my-agent", "Claude for side projects", [anthropicRule.id]);

  // The README's terminal demo: an echo service, GET only.
  const httpbin = await post<{ id: string }>(`/vaults/${personal.id}/credentials`, {
    name: "httpbin",
    template_id: "generic-bearer",
    host_override: ["https://httpbin.org"],
    fields: { token: "example-token-the-agent-never-sees" },
  });
  const httpbinRule = await rule(personal.id, "httpbin-read", httpbin.id, { methods: ["GET"] });
  await bundle(personal.id, "demo", "Read from httpbin", [httpbinRule.id]);

  await post("/variables", { key: "SUPPORT_EMAIL", value: "support@example.com" });
  await post("/invites", { role: "editor", expires_in_hours: 72 });

  const key = (name: string) =>
    post<{ api_key: string }>("/api-keys", { name, vault_id: work.id, role: "editor", expires_in_days: 90 });
  const ci = await key("ci-runner");
  await key("release-bot");

  await post("/audit-export/destinations", {
    name: "Security team SIEM",
    url: fakes.auditUrl,
    format: "ndjson",
    auth_header_name: "Authorization",
    auth_header_value: "Bearer example-receiver-token",
  });
  await post("/identity-providers", {
    slug: "keycloak",
    name: "Keycloak",
    issuer: fakes.issuer,
    client_id: "tokenless-console",
    client_secret: "example-client-secret",
    redirect_uri: "https://tokenless.example.com/api/v1/auth/oidc/callback",
    role_mappings: [{ group: "platform", role: "editor" }],
  });

  const tripwire = await post<{ value: string }>(`/vaults/${work.id}/tripwires`, {
    name: "build-server",
    kind: "github",
  });

  // Sessions minted by CI's API key, as a pipeline would.
  const mint = (bundle: string, name: string, labels: Json = {}) =>
    post<{ token: string; session: { id: string } }>(
      `/vaults/${work.id}/sessions`,
      { bundle, ttl_secs: 3600, labels: { name, ...labels } },
      ci.api_key,
    );
  const nightly = await mint("code-review", "nightly-sync", { agent: "codex" });
  const standup = await mint("standup-bot", "standup-bot", { agent: "claude-code", team: "platform" });
  const release = await mint("release-manager", "release-agent", {
    agent: "claude-code",
    command: "agent-work.sh",
    team: "platform",
  });

  console.log("traffic: standup-bot");
  agent(
    standup.token,
    ["-X", "POST", "https://slack.com/api/chat.postMessage"],
    ["https://slack.com/api/conversations.history"],
    ["https://slack.com/api/users.list"],
    ["-X", "POST", "https://slack.com/api/conversations.archive"],
    ["-X", "POST", "https://slack.com/api/chat.postMessage"],
  );
  console.log("traffic: release-agent");
  agent(
    release.token,
    ["https://example.com/"],
    ["https://api.stripe.com/v1/balance"],
    ["https://api.github.com/user"],
    ["https://api.openai.com/v1/models"],
    ["https://slack.com/api/chat.postMessage"],
    ["https://api.github.com/repos/example-org/example/tags"],
  );
  // The decoy planted on the build server turns up in a request: the
  // session is cut off and an alert is raised.
  console.log("traffic: nightly-sync trips the wire");
  agent(nightly.token, ["-H", `Authorization: Bearer ${tripwire.value}`, "https://api.github.com/user"]);
  return { work, personal };
}

