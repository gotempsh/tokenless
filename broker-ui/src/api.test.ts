// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import { afterEach, describe, expect, test } from "bun:test";
import { ApiError, get, post, setStepUpHandler } from "./api";

const realFetch = globalThis.fetch;

/** Answers every request with `step_up_required` until confirmed. */
function needsStepUp(): { prompts: number } {
  const state = { prompts: 0, confirmed: false };
  setStepUpHandler(async () => {
    state.prompts += 1;
    state.confirmed = true;
    return true;
  });
  globalThis.fetch = (async () =>
    state.confirmed
      ? new Response("{}", { status: 200 })
      : new Response(JSON.stringify({ title: "Step-up required", status: 403, code: "step_up_required", detail: "confirm first" }), {
          status: 403,
        })) as unknown as typeof fetch;
  return state;
}

afterEach(() => {
  globalThis.fetch = realFetch;
  setStepUpHandler(null);
});

describe("step-up", () => {
  test("a read never asks to confirm: pages read in the background", async () => {
    const state = needsStepUp();
    await expect(get("/nodes")).rejects.toBeInstanceOf(ApiError);
    expect(state.prompts).toBe(0);
  });

  test("a change asks once, then is retried", async () => {
    const state = needsStepUp();
    await expect(post("/api-keys", { name: "ci" })).resolves.toEqual({});
    expect(state.prompts).toBe(1);
  });
});
