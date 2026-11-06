// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import { describe, expect, test } from "bun:test";
import type { DiscoveredService } from "./api";
import { claudeMcpCommand, mcpClientJson, mcpEndpoints } from "./mcpConnect";

function service(credential: string, host: string, extra: Partial<DiscoveredService> = {}): DiscoveredService {
  return {
    rule_id: credential,
    rule: credential,
    credential,
    template_id: "github-mcp",
    service: "GitHub MCP",
    hosts: [host],
    enabled: true,
    kind: "mcp",
    ...extra,
  };
}

describe("MCP gateway endpoints", () => {
  test("only enabled MCP services with a concrete host get a URL", () => {
    const found = mcpEndpoints(
      [
        service("Work GitHub", "api.githubcopilot.com", { mcp_path: "/mcp/" }),
        service("Plain API", "api.example.com", { kind: "http" }),
        service("Root", "mcp.example.com:8443"),
        service("Wild", "*.example.com"),
        service("Off", "mcp.example.com", { enabled: false }),
      ],
      "http://127.0.0.1:3129/",
    );
    expect(found.map((e) => [e.name, e.url])).toEqual([
      ["work-github", "http://127.0.0.1:3129/mcp/api.githubcopilot.com/mcp/"],
      ["root", "http://127.0.0.1:3129/mcp/mcp.example.com:8443/"],
    ]);
  });

  test("names are unique slugs", () => {
    const found = mcpEndpoints([service("GitHub", "a.example.com"), service("github!", "b.example.com"), service("***", "c.example.com")]);
    expect(found.map((e) => e.name)).toEqual(["github", "github-2", "mcp"]);
  });

  test("client configuration carries the token as a bearer header", () => {
    const [e] = mcpEndpoints([service("GitHub", "api.githubcopilot.com", { mcp_path: "/mcp/" })]);
    expect(claudeMcpCommand(e!, "v4.public.abc")).toBe(
      "claude mcp add --transport http github http://127.0.0.1:3129/mcp/api.githubcopilot.com/mcp/ --header 'Authorization: Bearer v4.public.abc'",
    );
    const json = JSON.parse(mcpClientJson([e!], "v4.public.abc"));
    expect(json.mcpServers.github).toEqual({
      type: "http",
      url: "http://127.0.0.1:3129/mcp/api.githubcopilot.com/mcp/",
      headers: { Authorization: "Bearer v4.public.abc" },
    });
  });
});
