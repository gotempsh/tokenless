// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// What a person sees right after creating a session: the token, once, and
// the commands that start an agent with it, ready to paste.

import { useEffect, useMemo, useState, type KeyboardEvent } from "react";
import { Braces, KeyRound, SquareTerminal } from "lucide-react";
import type { DiscoveredService, MintedSession } from "../api";
import { AGENTS } from "../bundleConnect";
import { CopyButton, DialogActions, ErrorBanner, Exact, Mono } from "../components/common";
import { Button } from "../components/ui/button-components";
import { Input } from "../components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "../components/ui/tabs";
import { cn } from "../lib/utils";
import { claudeMcpCommand, mcpClientJson, mcpEndpoints, tokenServices } from "../mcpConnect";
import { agentEnv, agentScript, gatewayFor, handoffMayClose, INSTALL_COMMAND, shortToken, suggestedProxy } from "../sessionForm";

/** The proxy address last used in this browser, so the next session's commands start with it. */
const PROXY_KEY = "tokenless.agentProxy";

function rememberedProxy(): string | null {
  try {
    return window.localStorage.getItem(PROXY_KEY);
  } catch {
    return null;
  }
}

function rememberProxy(value: string) {
  try {
    window.localStorage.setItem(PROXY_KEY, value.trim());
  } catch {
    // A browser that refuses storage just suggests the default next time.
  }
}

/** A multi-line block with one Copy button; shows `display`, copies `copy`. */
function Snippet({
  title,
  copy,
  display,
  onCopied,
  onFailed,
}: {
  title: string;
  copy: string;
  display?: string;
  onCopied?: () => void;
  onFailed?: () => void;
}) {
  return (
    <div className="rounded-md border">
      <div className="flex items-center justify-between gap-2 border-b px-3 py-1.5">
        <span className="text-xs font-medium text-muted-foreground">{title}</span>
        <CopyButton value={copy} label="Copy" onCopied={onCopied} onFailed={onFailed} />
      </div>
      <pre className="whitespace-pre-wrap px-3 py-2 font-mono text-xs [overflow-wrap:anywhere]">{display ?? copy}</pre>
    </div>
  );
}

/** Arrow keys move the choice in a radio group, as they do in a native one. */
function arrowChoice(e: KeyboardEvent<HTMLElement>, ids: string[], current: string, choose: (id: string) => void) {
  const step = e.key === "ArrowRight" || e.key === "ArrowDown" ? 1 : e.key === "ArrowLeft" || e.key === "ArrowUp" ? -1 : 0;
  if (step === 0) return;
  e.preventDefault();
  const next = ids[(ids.indexOf(current) + step + ids.length) % ids.length];
  if (next === undefined) return;
  choose(next);
  e.currentTarget.querySelector<HTMLElement>(`[data-choice="${next}"]`)?.focus();
}

/**
 * Whether anything from the handoff was copied, shared with the dialog that
 * shows it: Escape, the close button and an outside click go through the
 * dialog, so the dialog asks {@link HandoffGuard.mayClose} before closing.
 */
export interface HandoffGuard {
  copied: boolean;
  warned: boolean;
  markCopied: () => void;
  /** True when closing may go ahead; the first try before copying warns instead. */
  mayClose: () => boolean;
  reset: () => void;
}

export function useHandoffGuard(): HandoffGuard {
  const [copied, setCopied] = useState(false);
  const [warned, setWarned] = useState(false);
  return {
    copied,
    warned,
    markCopied: () => setCopied(true),
    mayClose: () => {
      if (handoffMayClose(copied, warned)) return true;
      setWarned(true);
      return false;
    },
    reset: () => {
      setCopied(false);
      setWarned(false);
    },
  };
}

export function SessionHandoff({
  minted,
  reaches,
  guard,
  onDone,
}: {
  minted: MintedSession;
  /** What the session reaches, for the hint under the token ("code-review's services"). */
  reaches: string;
  guard: HandoffGuard;
  onDone: () => void;
}) {
  const [agent, setAgent] = useState(AGENTS[0]?.id ?? "claude");
  const [other, setOther] = useState("");
  const [proxy, setProxy] = useState(() => suggestedProxy(window.location.hostname, rememberedProxy()));
  const [services, setServices] = useState<DiscoveredService[] | null>(null);
  const { copied, warned, markCopied, mayClose } = guard;
  const [failed, setFailed] = useState(false);
  const copyFailed = () => setFailed(true);
  const leave = (e?: { preventDefault: () => void }) => {
    if (!mayClose()) {
      e?.preventDefault();
      return;
    }
    onDone();
  };
  const [lookupError, setLookupError] = useState<string | null>(null);
  useEffect(() => {
    let live = true;
    tokenServices(minted.token).then(
      (s) => live && setServices(s),
      (e: unknown) => live && setLookupError(e instanceof Error ? e.message : String(e)),
    );
    return () => {
      live = false;
    };
  }, [minted.token]);

  const target = { url: window.location.origin, proxy: proxy.trim() || "127.0.0.1:3128", token: minted.token };
  const command = agent === "other" ? other.trim() || "<your-command>" : (AGENTS.find((a) => a.id === agent)?.command ?? "claude");
  const script = agentScript(target, command);
  const env = agentEnv(target);
  const endpoints = useMemo(() => mcpEndpoints(services ?? [], gatewayFor(target.proxy)), [services, target.proxy]);
  const short = shortToken(minted.token);

  return (
    <div className="space-y-5">
      <p className="text-sm">
        It reaches {reaches} until <Exact at={minted.session.expires_at} />
        {minted.session.request_limit ? `, for ${minted.session.request_limit} requests,` : ""} or until you revoke it.
        Its token is shown only now, inside the commands below.
      </p>

      <div className="space-y-3">
        <div className="space-y-1.5">
          <label htmlFor="handoff-proxy" className="text-sm font-medium">
            Proxy the agent's machine reaches
          </label>
          <div className="flex items-center gap-3">
            <Input
              id="handoff-proxy"
              className="h-8 max-w-sm font-mono text-xs"
              value={proxy}
              onChange={(e) => setProxy(e.target.value)}
              onBlur={() => rememberProxy(proxy)}
            />
            <a href="#/proxies" className="text-xs text-muted-foreground underline" onClick={(e) => leave(e)}>
              Proxies
            </a>
          </div>
        </div>

        <Tabs defaultValue="terminal">
          <TabsList>
            <TabsTrigger value="terminal">Terminal</TabsTrigger>
            <TabsTrigger value="mcp" count={services && !lookupError && endpoints.length > 0 ? endpoints.length : undefined}>
              MCP client
            </TabsTrigger>
            <TabsTrigger value="env">CI or container</TabsTrigger>
          </TabsList>

          <TabsContent value="terminal" className="space-y-3 pt-4">
            <div
              className="flex flex-wrap gap-2"
              role="radiogroup"
              aria-label="Agent"
              onKeyDown={(e) =>
                arrowChoice(
                  e,
                  AGENTS.map((a) => a.id),
                  agent,
                  setAgent,
                )
              }
            >
              {AGENTS.map((a) => (
                <Button
                  key={a.id}
                  type="button"
                  size="sm"
                  variant="outline"
                  role="radio"
                  data-choice={a.id}
                  aria-checked={agent === a.id}
                  tabIndex={agent === a.id ? 0 : -1}
                  className={cn(agent === a.id && "border-foreground/50 bg-accent")}
                  onClick={() => setAgent(a.id)}
                >
                  {a.id === "other" && <SquareTerminal />}
                  {a.label}
                </Button>
              ))}
            </div>
            {agent === "other" && (
              <Input
                aria-label="Command to run"
                className="h-8 max-w-64 font-mono text-xs"
                placeholder="./my-agent"
                value={other}
                onChange={(e) => setOther(e.target.value)}
              />
            )}
            <Snippet title="Paste in the agent's terminal" copy={script.copy} display={script.display} onCopied={markCopied} onFailed={copyFailed} />
          </TabsContent>

          <TabsContent value="mcp" className="space-y-3 pt-4">
            {lookupError ? (
              <ErrorBanner error={lookupError} title="Couldn't look up the session's MCP servers" />
            ) : services === null ? (
              <p className="text-sm text-muted-foreground">Looking up the session's MCP servers…</p>
            ) : endpoints.length === 0 ? (
              <p className="text-sm text-muted-foreground">
                This session reaches no MCP server. Add one (GitHub MCP, a custom MCP server) to{" "}
                {minted.session.bundle ? (
                  <a
                    href={`#/bundles/${minted.session.bundle.id}/services`}
                    className="underline"
                    onClick={(e) => leave(e)}
                  >
                    {minted.session.bundle.name}
                  </a>
                ) : (
                  "an access bundle"
                )}
                , and MCP clients can use its tools with a new session.
              </p>
            ) : (
              <>
                <Snippet
                  title="Claude Code: paste in a terminal"
                  copy={endpoints.map((e) => claudeMcpCommand(e, minted.token)).join("\n")}
                  display={endpoints.map((e) => claudeMcpCommand(e, short)).join("\n")}
                  onCopied={markCopied} onFailed={copyFailed}
                />
                <details className="group rounded-md border">
                  <summary className="flex cursor-pointer items-center gap-2 px-3 py-2 text-sm">
                    <Braces className="size-4 text-muted-foreground" />
                    Another client: an <Mono>mcpServers</Mono> block
                  </summary>
                  <div className="border-t p-3">
                    <Snippet
                      title="mcpServers"
                      copy={mcpClientJson(endpoints, minted.token)}
                      display={mcpClientJson(endpoints, short)}
                      onCopied={markCopied} onFailed={copyFailed}
                    />
                  </div>
                </details>
              </>
            )}
          </TabsContent>

          <TabsContent value="env" className="space-y-3 pt-4">
            <Snippet
              title="Environment variables (store them as secrets)"
              copy={env.copy}
              display={env.display}
              onCopied={markCopied} onFailed={copyFailed}
            />
            <p className="text-sm text-muted-foreground">
              Then start the job's command with <Mono>tokenless run -- ./your-command</Mono>.
            </p>
          </TabsContent>
        </Tabs>
      </div>

      <div className="flex items-start gap-2 rounded-md border px-3 py-1.5 text-sm">
        <KeyRound className="mt-1.5 size-4 shrink-0 text-muted-foreground" />
        <span className="mt-1 shrink-0 text-muted-foreground">Token</span>
        {/* The whole token, selectable: the way out when copying fails. */}
        <code
          className="min-w-0 flex-1 select-all break-all py-1 font-mono text-xs"
          onCopy={markCopied}
        >
          {minted.token}
        </code>
        <CopyButton value={minted.token} label="Copy token" iconOnly onCopied={markCopied} onFailed={copyFailed} />
      </div>
      {failed && (
        <p role="alert" className="text-sm text-warning-strong">
          This browser didn't allow copying. Select the token above and copy it by hand.
        </p>
      )}

      <details className="rounded-md border">
        <summary className="cursor-pointer px-3 py-2 text-sm">First time on that machine?</summary>
        <div className="space-y-2 border-t p-3">
          <Snippet title="Install tokenless (Linux, macOS)" copy={INSTALL_COMMAND} />
          <Snippet title="Teach Claude Code how the broker works (optional)" copy="tokenless skill --install" />
        </div>
      </details>

      {warned && !copied && (
        <p role="alert" className="text-sm text-warning-strong">
          Nothing copied yet. The token is shown only now; copy a command or the token first.
        </p>
      )}
      <DialogActions>
        <Button type="button" variant="outline" asChild>
          <a href={`#/sessions/${minted.session.id}`} onClick={(e) => leave(e)}>
            Open session
          </a>
        </Button>
        <Button type="button" onClick={() => leave()}>
          {warned && !copied ? "Close anyway" : "Done"}
        </Button>
      </DialogActions>
    </div>
  );
}
