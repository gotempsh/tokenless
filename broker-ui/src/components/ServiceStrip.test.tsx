// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import { describe, expect, mock, test } from "bun:test";
import { renderToStaticMarkup } from "react-dom/server";

// The real logos are found with Vite's import.meta.glob.
mock.module("./ServiceLogo", () => ({ ServiceLogo: () => <span data-logo="" /> }));
const { ServiceStrip } = await import("./ServiceStrip");

const service = (name: string) => ({ key: name, name, logo: { id: name, kind: "http" as const } });

describe("ServiceStrip", () => {
  test("with no services, only the empty message: no placeholder logo", () => {
    const html = renderToStaticMarkup(<ServiceStrip services={[]} total={0} empty="No services yet." />);
    expect(html).toContain("No services yet.");
    expect(html).not.toContain("border-dashed");
    expect(html).not.toContain("data-logo");
  });

  test("with services, their logos and names", () => {
    const html = renderToStaticMarkup(
      <ServiceStrip services={[service("GitHub"), service("Stripe")]} total={3} empty="No services yet." />,
    );
    expect(html.match(/data-logo/g)).toHaveLength(2);
    expect(html).toContain("GitHub, Stripe and 1 more");
    expect(html).not.toContain("No services yet.");
  });

  test("with services it cannot name, how many there are", () => {
    const one = renderToStaticMarkup(<ServiceStrip services={[]} total={1} empty="No services yet." />);
    expect(one).toContain("+1");
    expect(one).toContain("1 service<");
    const three = renderToStaticMarkup(<ServiceStrip services={[]} total={3} empty="No services yet." />);
    expect(three).toContain("3 services<");
    expect(three).not.toContain("No services yet.");
  });
});
