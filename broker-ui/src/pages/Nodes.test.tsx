// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import { describe, expect, mock, test } from "bun:test";
import { renderToStaticMarkup } from "react-dom/server";

// The real logos are found with Vite's import.meta.glob.
mock.module("../components/ServiceLogo", () => ({ ServiceLogo: () => <span />, LogoTile: () => <span /> }));
const { OtherHosts } = await import("./Nodes");

describe("OtherHosts", () => {
  test("allowed is a warning with the way to block them", () => {
    const html = renderToStaticMarkup(<OtherHosts policy="passthrough" />);
    expect(html).toContain("allowed");
    expect(html).toContain("Block other hosts");
    expect(html).toContain('href="#/settings"');
  });

  test("blocked says what agents still reach", () => {
    const html = renderToStaticMarkup(<OtherHosts policy="deny" />);
    expect(html).toContain("blocked");
    expect(html).toContain("only their sessions&#x27; services");
    expect(html).not.toContain("Block other hosts");
  });
});
