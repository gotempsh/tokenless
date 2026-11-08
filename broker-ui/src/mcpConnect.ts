// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// The MCP gateway URLs of a session's MCP services and the client
// configuration that uses them. Mirrors `tokenless mcp`.

import type { CredentialMeta, DiscoveredService, StoredTemplate } from "./api";
import { shellQuote } from "./bundleConnect";

/** Where `node run` serves the MCP gateway unless told otherwise. */
export const DEFAULT_GATEWAY = "http://127.0.0.1:3129";

export interface McpEndpoint {
  /** The name to give it in the client: the credential's, as a slug. */
  name: string;
  service: string;
  credential: string;
  url: string;
}

function slug(value: string): string {
  const out = value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
  return out || "mcp";
}

/** Enabled MCP services with their gateway URLs; names are unique. */
export function mcpEndpoints(services: DiscoveredService[], gateway: string = DEFAULT_GATEWAY): McpEndpoint[] {
  const base = gateway.trim().replace(/\/+$/, "");
  const out: McpEndpoint[] = [];
  for (const s of services) {
    if (s.kind !== "mcp" || !s.enabled) continue;
    const host = s.hosts.find((h) => !h.includes("*"));
    if (!host) continue;
    const first = slug(s.credential);
    let name = first;
    for (let n = 2; out.some((e) => e.name === name); n++) name = `${first}-${n}`;
    out.push({ name, service: s.service, credential: s.credential, url: `${base}/mcp/${host}${s.mcp_path ?? "/"}` });
  }
  return out;
}

/** `claude mcp add` for one endpoint. */
export function claudeMcpCommand(endpoint: McpEndpoint, token: string): string {
  return `claude mcp add --transport http ${shellQuote(endpoint.name)} ${shellQuote(endpoint.url)} --header ${shellQuote(`Authorization: Bearer ${token}`)}`;
}

/** The `mcpServers` JSON most other MCP clients read. */
export function mcpClientJson(endpoints: McpEndpoint[], token: string): string {
  const servers: Record<string, { type: "http"; url: string; headers: Record<string, string> }> = {};
  for (const e of endpoints) servers[e.name] = { type: "http", url: e.url, headers: { Authorization: `Bearer ${token}` } };
  return JSON.stringify({ mcpServers: servers }, null, 2);
}

/** The bundle's credentials whose template is an MCP server. */
export function mcpCredentials(credentials: CredentialMeta[], templates: StoredTemplate[]): CredentialMeta[] {
  return credentials.filter((c) =>
    templates.some((t) => t.template.id === c.template_id && t.template.version === c.template_version && t.template.kind === "mcp"),
  );
}

/** The services a freshly minted token reaches, asked with the token itself. */
export async function tokenServices(token: string): Promise<DiscoveredService[]> {
  const response = await fetch("/api/v1/sessions/self", {
    headers: { authorization: `Bearer ${token}` },
    credentials: "omit",
    cache: "no-store",
  });
  if (!response.ok) throw new Error(`Looking up the token's MCP servers failed with HTTP ${response.status}`);
  const found = (await response.json()) as { services: DiscoveredService[] };
  return found.services;
}
