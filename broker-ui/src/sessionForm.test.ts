// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import { describe, expect, test } from "bun:test";
import {
  agentEnv,
  agentScript,
  defaultLifetime,
  gatewayFor,
  lifetimeLabel,
  lifetimesUpTo,
  shortToken,
  suggestedProxy,
} from "./sessionForm";

describe("new session form", () => {
  test("offers the presets up to the cap, and the cap itself", () => {
    expect(lifetimesUpTo(7 * 86400).map((l) => l.label)).toEqual(["1 hour", "8 hours", "1 day", "7 days"]);
    expect(lifetimesUpTo(3600).map((l) => l.label)).toEqual(["1 hour"]);
    expect(lifetimesUpTo(2 * 86400).map((l) => l.label)).toEqual(["1 hour", "8 hours", "1 day", "2 days"]);
    expect(lifetimesUpTo(15 * 60).map((l) => l.label)).toEqual(["15 minutes"]);
  });

  test("defaults to a day, or the cap when it is shorter", () => {
    expect(defaultLifetime(90 * 86400)).toBe(86400);
    expect(defaultLifetime(3600)).toBe(3600);
  });

  test("names a lifetime in its largest whole unit", () => {
    expect(lifetimeLabel(86400)).toBe("1 day");
    expect(lifetimeLabel(8 * 3600)).toBe("8 hours");
    expect(lifetimeLabel(90)).toBe("2 minutes");
  });

  test("gives the agent's terminal everything it needs, ready to paste", () => {
    const token = `v4.public.${"x".repeat(60)}`;
    const target = { url: "https://broker.example.test", proxy: "broker.example.test:3128", token };
    const { copy, display } = agentScript(target, "claude");
    expect(copy).toBe(
      [
        "export TOKENLESS_URL=https://broker.example.test",
        "export TOKENLESS_PROXY_ADDRESS=broker.example.test:3128",
        `export TOKENLESS_SESSION_TOKEN=${token}`,
        "tokenless run -- claude",
      ].join("\n"),
    );
    // Shown shortened, copied whole.
    expect(display).toContain(`TOKENLESS_SESSION_TOKEN=${shortToken(token)}`);
    expect(display).not.toContain(token);
    expect(agentEnv(target).copy).toBe(
      `TOKENLESS_URL=https://broker.example.test\nTOKENLESS_PROXY_ADDRESS=broker.example.test:3128\nTOKENLESS_SESSION_TOKEN=${token}\n`,
    );
  });

  test("suggests the proxy on the console's host unless one was used before", () => {
    expect(suggestedProxy("localhost")).toBe("127.0.0.1:3128");
    expect(suggestedProxy("127.0.0.1")).toBe("127.0.0.1:3128");
    expect(suggestedProxy("broker.example.test")).toBe("broker.example.test:3128");
    expect(suggestedProxy("broker.example.test", " 10.0.0.5:13128 ")).toBe("10.0.0.5:13128");
  });

  test("finds the MCP gateway one port above the proxy", () => {
    expect(gatewayFor("127.0.0.1:3128")).toBe("http://127.0.0.1:3129");
    expect(gatewayFor("[::1]:13128")).toBe("http://[::1]:13129");
    expect(gatewayFor("proxy.example.test")).toBe("http://proxy.example.test:3129");
  });
});
