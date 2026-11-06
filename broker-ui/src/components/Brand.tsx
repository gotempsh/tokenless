// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// The tokenless mark: a key without teeth. The agent holds the blank and
// the proxy adds the cuts, so the teeth are only ghosts. It takes the
// theme's primary colours, so it inverts in dark mode.

export function BrandMark({ className = "size-8" }: { className?: string }) {
  return (
    <svg viewBox="0 0 32 32" className={`shrink-0 ${className}`} role="img" aria-label="tokenless">
      <rect x="1" y="1" width="30" height="30" rx="7" className="fill-primary" />
      <circle cx="10" cy="14" r="4.3" fill="none" strokeWidth={3} className="stroke-primary-foreground" />
      <path d="M14.3 14H26.5" fill="none" strokeWidth={3} strokeLinecap="round" className="stroke-primary-foreground" />
      <path d="M18.6 17.2h3v3.6h-3zM23.4 17.2h3v5.4h-3z" fillOpacity={0.38} className="fill-primary-foreground" />
    </svg>
  );
}
