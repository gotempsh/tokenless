// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// Launcher keys: what an agent machine starts its sessions with instead of a
// person's sign-in. A key only starts sessions from one bundle.

import type { LauncherKey } from "./api";
import { shellQuote } from "./bundleConnect";

export type KeyState = "active" | "expired" | "revoked";

export function keyState(key: LauncherKey, now: Date): KeyState {
  if (key.revoked_at) return "revoked";
  if (new Date(key.expires_at) <= now) return "expired";
  return "active";
}

/** `900` as "15 min", `3600` as "1 h", `5400` as "90 min". */
export function sessionLength(secs: number): string {
  if (secs % 3600 === 0) return `${secs / 3600} h`;
  if (secs % 60 === 0) return `${secs / 60} min`;
  return `${secs} s`;
}

/** The session lengths offered when creating a key, within what Settings allow. */
export function lengthChoices(maxSecs: number): number[] {
  return [5 * 60, 15 * 60, 60 * 60, 8 * 60 * 60].filter((s) => s <= maxSecs);
}

/** The command for the agent machine, with the key in a file only its owner reads. */
export function keyRunCommand(bundle: string, command: string, vault?: string): string {
  const vaultFlag = vault ? ` --vault ${shellQuote(vault)}` : "";
  return `tokenless run --api-key-file ~/.config/tokenless/launcher.key${vaultFlag} --bundle ${shellQuote(bundle)} -- ${command}`;
}

/**
 * Saves the key to that file, readable only by its owner. It reads the key
 * from the terminal (paste it, then Ctrl-D), so it stays out of the shell's
 * history.
 */
export const KEY_SAVE_COMMAND =
  "(umask 077 && mkdir -p ~/.config/tokenless && cat > ~/.config/tokenless/launcher.key)";
