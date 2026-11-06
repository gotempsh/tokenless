// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// Whether the desktop sidebar shows only icons. A per-browser display
// choice, like the theme, so it lives in localStorage.

import { useCallback, useEffect, useState } from "react";

const KEY = "tokenless.sidebar";

function stored(): boolean {
  return window.localStorage.getItem(KEY) === "collapsed";
}

/** True when `target` takes typed text, where shortcuts must not fire. */
function isTyping(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  return target.isContentEditable || ["INPUT", "TEXTAREA", "SELECT"].includes(target.tagName);
}

type Keys = Pick<KeyboardEvent, "key" | "metaKey" | "ctrlKey" | "altKey" | "shiftKey">;

/** ⌘B on a Mac, Ctrl+B elsewhere, with no other modifier. */
export function isToggleShortcut(e: Keys): boolean {
  return e.key.toLowerCase() === "b" && (e.metaKey || e.ctrlKey) && !e.altKey && !e.shiftKey;
}

/** The collapsed state and its toggle; ⌘B / Ctrl+B toggles it too. */
export function useSidebarCollapsed(): [boolean, () => void] {
  const [collapsed, setCollapsed] = useState(stored);
  const toggle = useCallback(() => setCollapsed((c) => !c), []);
  useEffect(() => {
    if (collapsed) window.localStorage.setItem(KEY, "collapsed");
    else window.localStorage.removeItem(KEY);
  }, [collapsed]);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (!isToggleShortcut(e) || isTyping(e.target)) return;
      e.preventDefault();
      toggle();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [toggle]);
  return [collapsed, toggle];
}
