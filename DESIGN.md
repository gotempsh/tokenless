---
# SPDX-FileCopyrightText: 2026 tokenless contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
name: tokenless console
description: The Temps design system, laid out for a credential broker's records, sessions and settings.
colors:
  background: "oklch(1 0 0)"
  foreground: "oklch(0.145 0 0)"
  card: "oklch(1 0 0)"
  muted-foreground: "oklch(0.52 0 0)"
  accent: "oklch(0.955 0 0)"
  border: "oklch(0.922 0 0)"
  primary: "oklch(0.145 0 0)"
  primary-foreground: "oklch(0.985 0 0)"
  background-dark: "oklch(0.145 0 0)"
  foreground-dark: "oklch(0.985 0 0)"
  card-dark: "oklch(0.205 0 0)"
  muted-foreground-dark: "oklch(0.708 0 0)"
  accent-dark: "oklch(0.322 0 0)"
  border-dark: "oklch(0.322 0 0)"
  primary-dark: "oklch(0.985 0 0)"
  primary-foreground-dark: "oklch(0.145 0 0)"
  success: "oklch(0.627 0.1684 150.31)"
  warning: "oklch(0.773 0.1776 69.61)"
  warning-strong: "oklch(0.5 0.13 55)"
  destructive: "oklch(0.54 0.22 25)"
  ring: "oklch(0.59 0.2032 256.82)"
typography:
  headline:
    fontFamily: "Geist Variable, -apple-system, BlinkMacSystemFont, Segoe UI, sans-serif"
    fontSize: "1.5rem"
    fontWeight: 600
    letterSpacing: "-0.025em"
  title:
    fontFamily: "Geist Variable, -apple-system, BlinkMacSystemFont, Segoe UI, sans-serif"
    fontSize: "1.125rem"
    fontWeight: 600
  body:
    fontFamily: "Geist Variable, -apple-system, BlinkMacSystemFont, Segoe UI, sans-serif"
    fontSize: "0.875rem"
    fontWeight: 400
  label:
    fontFamily: "Geist Variable, -apple-system, BlinkMacSystemFont, Segoe UI, sans-serif"
    fontSize: "0.75rem"
    fontWeight: 400
  data:
    fontFamily: "Geist Mono Variable, ui-monospace, SF Mono, Consolas, monospace"
    fontSize: "0.75rem"
    fontWeight: 400
rounded:
  sm: "4px"
  md: "6px"
  lg: "8px"
  xl: "12px"
spacing:
  page-x-phone: "16px"
  page-x-tablet: "24px"
  page-x-desktop: "32px"
  grid-gap: "16px"
  column-gap: "32px"
  section-y: "24px"
components:
  button-primary:
    backgroundColor: "{colors.primary}"
    textColor: "{colors.primary-foreground}"
    rounded: "{rounded.md}"
    height: "40px"
    padding: "8px 16px"
  button-outline:
    backgroundColor: "{colors.background}"
    textColor: "{colors.foreground}"
    rounded: "{rounded.md}"
    height: "40px"
    padding: "8px 16px"
  record-panel:
    backgroundColor: "{colors.card}"
    textColor: "{colors.foreground}"
    rounded: "{rounded.lg}"
    width: "320px"
  facts-column:
    backgroundColor: "{colors.card}"
    rounded: "{rounded.lg}"
    width: "320px"
---

# Design System: tokenless console

## Overview

The console is the Temps design system, unchanged in look and specific in layout. Geist type, neutral greys and 1px borders carry everything; colour is reserved for service logos and for state. What this system adds is structure: a page never stretches across a wide screen, a few records show what they hold instead of two columns of metadata, a record's facts sit beside its work, and settings read as calm label-left forms.

Key characteristics:

- Content capped and centred beside the sidebar: 1440px for lists and records, 1040px for settings and admin lists, 640px for long forms.
- Few records are panels led by service logos; long lists stay tables within the cap.
- A record without tabs splits into a main column and a 320px facts column. A record with tabs gives its tabs the full width: status goes in the header, and its own facts, edits and Delete go in a Settings tab.
- No paragraph under a page title; at most one short line where it is needed to act.

## Colors

All tokens live in `broker-ui/src/index.css` as OKLCH custom properties, ported from the Temps console, with a light and a dark (`.dark`) set; the theme follows the system unless the person picks one.

### Primary

Near-black on light, near-white on dark (`primary`, `primary-dark`): the one filled button per view and the selected state. There is no brand accent colour.

### Neutral

Greys with zero chroma for everything else: `background`, `card` (one step off the background in dark mode), `accent` for hover and selected rows, `border` for every 1px line, `muted-foreground` for secondary text.

### Named Rules

**The Logo Is the Colour Rule.** In lists, colour comes from service logos on neutral tiles. Nothing else is decorated with hue.

**The State-Only Rule.** `success`, `warning`/`warning-strong` and `destructive` mark state (live, idle, turned off, revoked, a problem to act on) and never decorate. A problem is written in `warning-strong` together with the action that fixes it ("No services yet. Add one").

## Typography

Geist Variable for all interface text and Geist Mono Variable for data, both bundled locally (the console's content security policy allows only its own origin).

### Hierarchy

- **Headline** (1.5rem, 600, tight tracking): the page title, one per page.
- **Title** (1.125rem, 600): a section heading in a main column. Inside a tab, the tab already names the section, so the heading is visually hidden.
- **Body** (0.875rem, 400): table cells, panel rows, form controls, settings labels (600).
- **Label** (0.75rem, 400, muted): fact labels, footers, hints, counts.
- **Data** (Geist Mono, 0.75rem): hosts, IDs, commands, bundle names. Never as a "technical" costume for prose.

## Layout

- **Page container**: `PageContainer` in `components/ui/page-header.tsx`, padded 16 / 24 / 32px by breakpoint, centred with `mx-auto`, width `default` 1440px, `settings` 1040px, `form` 640px.
- **Page header**: title (and a verdict badge on records) at left, actions at right. The title keeps at least 12rem, so one action stays beside it on a phone and more move to their own line.
- **Panel grid**: `PANEL_GRID` in `components/layout.tsx`, as many 320px-or-wider columns as fit, 16px gap, panels sized to their own content.
- **Detail layout**: `DetailLayout`, a main column and a 320px facts column from `lg`, 32px apart; on a phone the facts follow the content. Only for records without tabs (a service, a session).
- **Tabbed records** (a vault, an access bundle): no facts column. The header carries the state badge and one line of status (last request, or the description and vault); the last tab, Settings, holds the record's ID, history, edit and Delete as settings sections, capped at 1040px.
- **Settings sections**: `SettingsSection`, a 240px label column (title, one hint line) and the controls beside it, sections divided by a top border and 24px of padding.
- **Catalogue**: a 200px category rail with counts beside a tile grid; three tiles across, four from 80rem of catalogue. Below 48rem the rail becomes a picker and the tiles a list.
- **Tables**: columns appear by priority with the container's width (`fromWidth`); hidden columns fold under the first cell. Nothing scrolls sideways.

## Elevation & Depth

Flat. Surfaces separate by a 1px border and, in dark mode, one step of lightness on cards. No shadows on panels, rows or tiles; overlays (menus, dialogs) carry the Temps overlay shadow only.

## Shapes

8px radius (`lg`) for panels, tables, tiles and the facts column; 6px (`md`) for buttons and inputs; 4px (`sm`) for badges and code chips. Service logos sit on 32px rounded tiles.

## Components

### Buttons

One filled `primary` button per view for the main action; everything else is `outline`. Repeated save buttons inside a settings page are outline.

### Record panel

`VaultPanel`, `BundlePanel`: name (the link covers the whole panel), a state badge or a "…" menu at the top right, up to four services with logo, name and host, "+N more", and one footer line: the last activity or a problem in `warning-strong`.

### Facts column

`FactList` / `Fact`: a bordered panel of label-over-value facts (12px label, 14px value, long values wrap anywhere), with an optional title and Edit action. Used beside a record that has no tabs; a tabbed record puts these facts in its Settings tab instead.

### Tables

Few columns, compact relative times, one "…" menu per row for its actions, shown only when an action applies. A row opens the record's page.

### Inputs and forms

Labels above controls with a hint line below. Short forms (one to three fields) are dialogs; anything longer, or a list to pick from, is a 640px page with Cancel and the action at the bottom right.

## Do's and Don'ts

### Do:

- Cap the page and centre it; check every page at 2560, 1440 and 390px.
- Give each record the facts a person acts on: state, what it reaches, its last activity, its problem.
- Put a problem's fix next to it.
- Use the settings layout for settings and admin pages, and a full page for long forms.

### Don't:

- Don't stretch a two- or three-column table across a wide screen.
- Don't write a paragraph under a page or section title.
- Don't repeat the same value in two columns, or show `*` and `/*` on every row: name only what a rule narrows.
- Don't put a long form or a scrolling checklist inside a dialog.
- Don't show a stored secret anywhere; a minted token appears once.
- Don't add a kicker or eyebrow above a heading, gradient text or decorative colour.
