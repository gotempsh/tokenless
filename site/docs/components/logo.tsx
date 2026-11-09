// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

/** The tokenless mark, as in the favicon: a key whose teeth are only outlines. */
export function Logo() {
  return (
    <svg viewBox="0 0 32 32" className="size-6" aria-hidden="true">
      <rect x="1" y="1" width="30" height="30" rx="7" className="fill-fd-foreground" />
      <circle cx="10" cy="14" r="4.3" fill="none" strokeWidth={3} strokeLinecap="round" className="stroke-fd-background" />
      <path d="M14.3 14H26.5" fill="none" strokeWidth={3} strokeLinecap="round" className="stroke-fd-background" />
      <path d="M18.6 17.2h3v3.6h-3zM23.4 17.2h3v5.4h-3z" className="fill-fd-background" fillOpacity={0.38} />
    </svg>
  );
}
