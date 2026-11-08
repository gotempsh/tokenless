// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import { describe, expect, test } from "bun:test";
import { copyText } from "./clipboard";

describe("copyText", () => {
  test("says it worked when the browser took the text", async () => {
    let written = "";
    const ok = await copyText("v4.public.token", {
      writeText: async (text) => {
        written = text;
      },
    });
    expect(ok).toBe(true);
    expect(written).toBe("v4.public.token");
  });

  test("says it failed when the browser refuses the write", async () => {
    const refused = { writeText: () => Promise.reject(new DOMException("denied", "NotAllowedError")) };
    expect(await copyText("v4.public.token", refused)).toBe(false);
  });

  test("says it failed where there is no clipboard (plain HTTP)", async () => {
    expect(await copyText("v4.public.token", undefined)).toBe(false);
  });
});
