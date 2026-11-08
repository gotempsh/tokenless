// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// Copying to the clipboard, which a browser may refuse: there is no
// clipboard outside a secure context (a console served over plain HTTP),
// and a write can be denied by policy, focus or an extension.

/** The part of `navigator.clipboard` used here. */
export interface ClipboardLike {
  writeText(text: string): Promise<void>;
}

function browserClipboard(): ClipboardLike | undefined {
  return typeof navigator === "undefined" ? undefined : navigator.clipboard;
}

/** Copies `value`; whether it worked, never a thrown error. */
export async function copyText(value: string, clipboard: ClipboardLike | undefined = browserClipboard()): Promise<boolean> {
  if (!clipboard) return false;
  try {
    await clipboard.writeText(value);
    return true;
  } catch {
    return false;
  }
}
