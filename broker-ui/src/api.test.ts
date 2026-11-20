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
  for (const accepted of [true, false]) {
    test(`overlapping challenges share one prompt and both settle (accepted=${accepted})`, async () => {
      let prompts = 0;
      let finish!: (ok: boolean) => void;
      let passed = false;
      const paths: string[] = [];
      setStepUpHandler(() => {
        prompts++;
        return new Promise<boolean>(resolve => { finish = resolve; });
      });
      globalThis.fetch = (async (url: string) => {
        paths.push(url);
        return passed ? Response.json({}) : Response.json({
          status: 403, code: "step_up_required", title: "Step-up required", detail: "confirm first",
        }, { status: 403 });
      }) as unknown as typeof fetch;
      const results = Promise.allSettled([post("/one"), post("/two")]);
      await new Promise(resolve => setTimeout(resolve, 0));
      expect(prompts).toBe(1);
      passed = accepted;
      finish(accepted);
      expect((await results).map(result => result.status)).toEqual(Array(2).fill(accepted ? "fulfilled" : "rejected"));
      expect(paths).toEqual(accepted ? ["/api/v1/one", "/api/v1/two", "/api/v1/one", "/api/v1/two"] : ["/api/v1/one", "/api/v1/two"]);
    });
  }

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
