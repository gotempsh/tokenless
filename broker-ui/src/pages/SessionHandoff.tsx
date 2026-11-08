// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// What a person sees right after creating a session: the token, once, and
// the commands that start an agent with it, ready to paste.

import { useEffect, useMemo, useState } from "react";
import { Braces, SquareTerminal } from "lucide-react";
import type { DiscoveredService, MintedSession } from "../api";
import { AGENTS } from "../bundleConnect";
import { CopyButton, DialogActions, Exact, Mono, OneTimeSecret } from "../components/common";
import { Button } from "../components/ui/button-components";
import { Input } from "../components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "../components/ui/tabs";
import { cn } from "../lib/utils";
import { claudeMcpCommand, mcpClientJson, mcpEndpoints, tokenServices } from "../mcpConnect";
import { agentEnv, agentScript, gatewayFor, INSTALL_COMMAND, shortToken, suggestedProxy } from "../sessionForm";

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
function Snippet({ title, copy, display }: { title: string; copy: string; display?: string }) {
  return (
    <div className="rounded-md border">
      <div className="flex items-center justify-between gap-2 border-b px-3 py-1.5">
        <span className="text-xs font-medium text-muted-foreground">{title}</span>
        <CopyButton value={copy} label="Copy" />
      </div>
      <pre className="overflow-x-auto whitespace-pre-wrap break-all px-3 py-2 font-mono text-xs">{display ?? copy}</pre>
    </div>
  );
}

export function SessionHandoff({
  minted,
  reaches,
  onDone,
}: {
  minted: MintedSession;
  /** What the session reaches, for the hint under the token ("code-review's services"). */
  reaches: string;
  onDone: () => void;
}) {
  const [agent, setAgent] = useState(AGENTS[0]?.id ?? "claude");
  const [other, setOther] = useState("");
  const [proxy, setProxy] = useState(() => suggestedProxy(window.location.hostname, rememberedProxy()));
  const [services, setServices] = useState<DiscoveredService[] | null>(null);
  useEffect(() => {
    let live = true;
    tokenServices(minted.token)
      .catch(() => [])
      .then((s) => live && setServices(s));
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
      <OneTimeSecret
        label="Session token"
        value={minted.token}
        display={short}
        hint={
          <>
            It reaches {reaches} until <Exact at={minted.session.expires_at} />
            {minted.session.request_limit ? `, for ${minted.session.request_limit} requests,` : ""} or until you revoke it.
            The commands below include it.
          </>
        }
      />

      <div className="space-y-2">
        <h3 className="text-sm font-semibold">Start the agent</h3>
        <Tabs defaultValue="terminal">
          <TabsList>
            <TabsTrigger value="terminal">Terminal</TabsTrigger>
            <TabsTrigger value="mcp" count={services ? endpoints.length : undefined}>
              MCP client
            </TabsTrigger>
            <TabsTrigger value="env">CI or container</TabsTrigger>
          </TabsList>

          <TabsContent value="terminal" className="space-y-3 pt-4">
            <div className="flex flex-wrap gap-2" role="radiogroup" aria-label="Agent">
              {AGENTS.map((a) => (
                <Button
                  key={a.id}
                  type="button"
                  size="sm"
                  variant="outline"
                  role="radio"
                  aria-checked={agent === a.id}
                  className={cn(agent === a.id && "border-foreground/50 bg-accent")}
                  onClick={() => setAgent(a.id)}
                >
                  {a.id === "other" && <SquareTerminal />}
                  {a.label}
                </Button>
              ))}
              {agent === "other" && (
                <Input
                  aria-label="Command to run"
                  className="h-8 w-48 font-mono text-xs"
                  placeholder="./my-agent"
                  value={other}
                  autoFocus
                  onChange={(e) => setOther(e.target.value)}
                />
              )}
            </div>
            <Snippet title="Paste in the agent's terminal" copy={script.copy} display={script.display} />
          </TabsContent>

          <TabsContent value="mcp" className="space-y-3 pt-4">
            {services === null ? (
              <p className="text-sm text-muted-foreground">Looking up the session's MCP servers…</p>
            ) : endpoints.length === 0 ? (
              <p className="text-sm text-muted-foreground">
                This session reaches no MCP server. Add one (GitHub MCP, a custom MCP server) to{" "}
                {minted.session.bundle ? (
                  <a href={`#/bundles/${minted.session.bundle.id}/services`} className="underline" onClick={onDone}>
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
                    />
                  </div>
                </details>
              </>
            )}
          </TabsContent>

          <TabsContent value="env" className="space-y-3 pt-4">
            <Snippet title="Environment variables (store them as secrets)" copy={env.copy} display={env.display} />
            <p className="text-sm text-muted-foreground">
              Then start the job's command with <Mono>tokenless run -- ./your-command</Mono>.
            </p>
          </TabsContent>
        </Tabs>

        <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
          <label htmlFor="handoff-proxy">Proxy the agent's machine reaches</label>
          <Input
            id="handoff-proxy"
            className="h-7 w-56 font-mono text-xs"
            value={proxy}
            onChange={(e) => setProxy(e.target.value)}
            onBlur={() => rememberProxy(proxy)}
          />
          <a href="#/proxies" className="underline" onClick={onDone}>
            Proxies
          </a>
        </div>
      </div>

      <div className="space-y-2 rounded-md border border-dashed p-3">
        <p className="text-sm font-medium">First time on that machine?</p>
        <Snippet title="Install tokenless (Linux, macOS)" copy={INSTALL_COMMAND} />
        <Snippet title="Teach Claude Code how the broker works (optional)" copy="tokenless skill --install" />
      </div>

      <DialogActions>
        <Button type="button" variant="outline" asChild>
          <a href={`#/sessions/${minted.session.id}`} onClick={onDone}>
            Open session
          </a>
        </Button>
        <Button type="button" onClick={onDone}>
          Done
        </Button>
      </DialogActions>
    </div>
  );
}
