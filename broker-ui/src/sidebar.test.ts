// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import { describe, expect, test } from "bun:test";
import { isToggleShortcut } from "./sidebar";

const keys = (key: string, mods: Partial<Record<"metaKey" | "ctrlKey" | "altKey" | "shiftKey", boolean>> = {}) => ({
  key,
  metaKey: false,
  ctrlKey: false,
  altKey: false,
  shiftKey: false,
  ...mods,
});

describe("sidebar shortcut", () => {
  test("⌘B and Ctrl+B toggle the sidebar", () => {
    expect(isToggleShortcut(keys("b", { metaKey: true }))).toBe(true);
    expect(isToggleShortcut(keys("B", { ctrlKey: true }))).toBe(true);
  });

  test("plain b and other chords do not", () => {
    expect(isToggleShortcut(keys("b"))).toBe(false);
    expect(isToggleShortcut(keys("b", { metaKey: true, shiftKey: true }))).toBe(false);
    expect(isToggleShortcut(keys("b", { ctrlKey: true, altKey: true }))).toBe(false);
    expect(isToggleShortcut(keys("k", { metaKey: true }))).toBe(false);
  });
});
