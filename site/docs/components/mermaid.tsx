// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

'use client';
import { useTheme } from 'next-themes';
import { useEffect, useId, useRef, useState } from 'react';

// A sideways chart shrunk below this share of its size is drawn top-down instead.
const SMALLEST_SCALE = 0.7;
const SIDEWAYS = /^(\s*(?:flowchart|graph)\s+)(?:LR|RL)\b/m;

/**
 * A ```mermaid block, drawn in the browser in the site's light or dark
 * colours. Mermaid is loaded only on pages that have a diagram. Until it is
 * drawn, and if drawing fails, the diagram's source shows instead, so the
 * page never loses what it says. Its accTitle and accDescr become the
 * drawing's accessible name and description. A left-to-right chart too
 * wide for the column, on a phone, is drawn top to bottom so its text stays
 * readable.
 */
export function Mermaid({ chart }: { chart: string }) {
  const id = `mermaid-${useId().replace(/[^a-zA-Z0-9]/g, '')}`;
  const { resolvedTheme } = useTheme();
  const [svg, setSvg] = useState<string | null>(null);
  // Mermaid removes any element with the id it draws under, so each drawing
  // gets its own: a superseded one must not delete the diagram on screen.
  const drawings = useRef(0);
  const box = useRef<HTMLDivElement>(null);
  const [room, setRoom] = useState(0);
  // The chart's width as written, from its first drawing.
  const [wide, setWide] = useState(0);
  const upright = SIDEWAYS.test(chart) && room > 0 && wide > 0 && room < wide * SMALLEST_SCALE;

  useEffect(() => {
    const el = box.current;
    if (!el) return;
    const observer = new ResizeObserver(([entry]) => setRoom(entry.contentRect.width));
    observer.observe(el);
    return () => observer.disconnect();
  }, []);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      const { default: mermaid } = await import('mermaid');
      const dark = resolvedTheme === 'dark';
      mermaid.initialize({
        startOnLoad: false,
        securityLevel: 'strict',
        theme: 'base',
        // The flat look, without the default's shadows and gradient borders.
        look: 'classic',
        fontFamily: 'inherit',
        flowchart: { rankSpacing: 36, wrappingWidth: 240 },
        themeVariables: {
          darkMode: dark,
          fontSize: '14px',
          background: 'transparent',
          primaryColor: dark ? '#1c1c1c' : '#ffffff',
          primaryBorderColor: dark ? '#3f3f3f' : '#d4d4d4',
          primaryTextColor: dark ? '#fafafa' : '#171717',
          lineColor: dark ? '#737373' : '#a3a3a3',
          edgeLabelBackground: dark ? '#111111' : '#fafafa',
          tertiaryColor: 'transparent',
          clusterBkg: dark ? '#141414' : '#f5f5f5',
          clusterBorder: dark ? '#3f3f3f' : '#d4d4d4',
          titleColor: dark ? '#a3a3a3' : '#525252',
        },
      });
      try {
        const { svg } = await mermaid.render(`${id}-${++drawings.current}`, upright ? chart.replace(SIDEWAYS, '$1TD') : chart);
        if (cancelled) return;
        setSvg(svg);
        if (!upright) setWide(Number(svg.match(/viewBox="[-\d.]+ [-\d.]+ ([\d.]+)/)?.[1] ?? 0));
      } catch {
        if (!cancelled) setSvg(null);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [chart, id, resolvedTheme, upright]);

  return (
    <div ref={box} className="not-prose my-6">
      {svg ? (
        <div
          className="flex justify-center rounded-xl border bg-fd-card p-4 [&_svg]:h-auto [&_svg]:max-w-full"
          dangerouslySetInnerHTML={{ __html: svg }}
        />
      ) : (
        <pre className="overflow-x-auto rounded-xl border bg-fd-card p-4 font-mono text-xs text-fd-muted-foreground">
          {chart}
        </pre>
      )}
    </div>
  );
}
