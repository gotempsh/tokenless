// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import { describe, expect, test } from "bun:test";
import { opensRow } from "./common";

// A minimal element tree: `closest` matches by tag or role, like the DOM.
interface Node {
  tag: string;
  role?: string;
  parent?: Node;
}

function el(node: Node): Element {
  const self = {
    contains: (other: Element) => {
      for (let n: Node | undefined = (other as unknown as { node: Node }).node; n; n = n.parent) {
        if (n === node) return true;
      }
      return false;
    },
    closest: (selector: string) => {
      const wanted = selector.split(",");
      for (let n: Node | undefined = node; n; n = n.parent) {
        if (wanted.includes(n.tag) || (n.role && wanted.includes(`[role=${n.role}]`))) return el(n);
      }
      return null;
    },
    node,
  };
  return self as unknown as Element;
}

describe("opensRow", () => {
  const row: Node = { tag: "tr" };
  const cell: Node = { tag: "td", parent: row };

  test("a click on plain cell content opens the row", () => {
    expect(opensRow(el(row), el({ tag: "span", parent: cell }))).toBe(true);
    expect(opensRow(el(row), el(cell))).toBe(true);
  });

  test("a click on a control inside the row keeps its own meaning", () => {
    const button: Node = { tag: "button", parent: cell };
    expect(opensRow(el(row), el({ tag: "svg", parent: button }))).toBe(false);
    expect(opensRow(el(row), el({ tag: "a", parent: cell }))).toBe(false);
  });

  test("a click in a portal the row opened does not open it", () => {
    const menu: Node = { tag: "div" };
    expect(opensRow(el(row), el({ tag: "div", role: "menuitem", parent: menu }))).toBe(false);
    expect(opensRow(el(row), el({ tag: "div" }))).toBe(false);
  });

  test("a row inside a link-like container still opens", () => {
    const outer: Node = { tag: "a" };
    const nested: Node = { tag: "tr", parent: outer };
    expect(opensRow(el(nested), el({ tag: "td", parent: nested }))).toBe(true);
  });
});
