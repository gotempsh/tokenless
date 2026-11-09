// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import { describe, expect, mock, test } from "bun:test";
import { renderToStaticMarkup } from "react-dom/server";
import type { AccessBundle } from "../api";
import type { StripService } from "./ServiceStrip";

// The real logos are found with Vite's import.meta.glob; the services come from the API.
mock.module("./ServiceLogo", () => ({ ServiceLogo: () => <span data-logo="" /> }));
let services: StripService[] | undefined;
mock.module("../bundleServices", () => ({
  useBundleServices: () => ({ servicesOf: () => services, rulesOf: () => [], loading: !services, error: null }),
}));
const { BundleChoice } = await import("./BundleChoice");

const bundle = {
  id: "b1",
  vault_id: "v",
  name: "code-review",
  description: "",
  rule_ids: ["r1", "r2", "r3", "r4", "r5", "r6"],
  created_by: "user:u",
  created_at: "2026-01-01T00:00:00Z",
  updated_at: "2026-01-01T00:00:00Z",
} satisfies AccessBundle;

const service = (name: string): StripService => ({ key: name, name, logo: { id: name, kind: "http" } });

const render = () =>
  renderToStaticMarkup(
    <BundleChoice name="t" bundles={[bundle]} total={1} value="" onChange={() => {}} empty="none" />,
  );

describe("BundleChoice", () => {
  test("a bundle shows its first four services' logos and how many more", () => {
    services = ["GitHub", "Stripe", "Slack", "OpenAI", "Notion"].map(service);
    const html = render();
    expect(html.match(/data-logo/g)).toHaveLength(4);
    expect(html).toContain("+2");
    expect(html).toContain("GitHub, Stripe, Slack, OpenAI, Notion and 1 more");
    expect(html).not.toContain("6 rules");
  });

  test("until its services load, a bundle shows how many rules it has", () => {
    services = undefined;
    const html = render();
    expect(html).not.toContain("data-logo");
    expect(html).toContain("6 rules");
  });
});
