// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// A credential test's result, and the checklist from "service added" to
// "an agent is using it". Colour marks state only; a problem carries the
// link that fixes it.

import { CheckCircle2, Circle, CircleHelp, FlaskConical, Info } from "lucide-react";
import type { CredentialTest } from "../api";
import { testAdvice, testFix, testTitle, testTone, type Step } from "../serviceTest";
import { cn } from "../lib/utils";
import { CopyButton, Relative } from "./common";
import { Alert, AlertDescription, AlertTitle } from "./ui/alert";
import { Button } from "./ui/button-components";

/**
 * One test's result: a headline naming the host and status, what to do,
 * and the actions that fit it (test again, the page that fixes it).
 */
export function TestResult({
  test,
  serviceHref,
  onRetest,
  busy = false,
  showWhen = false,
  onReplaceKey,
}: {
  test: CredentialTest;
  serviceHref: string;
  /** On the service's own page: replacing the key opens its editor there. */
  onReplaceKey?: () => void;
  /** Offered when testing again could change the answer. */
  onRetest?: () => void;
  busy?: boolean;
  /** Say when it ran, for a result kept from earlier. */
  showWhen?: boolean;
}) {
  const tone = testTone(test);
  const fix = testFix(test, serviceHref);
  const retest = onRetest && test.outcome !== "no_probe" && test.outcome !== "unavailable";
  const Icon = tone === "success" ? CheckCircle2 : tone === "neutral" ? Info : FlaskConical;
  return (
    <Alert variant={tone === "warning" ? "warning" : "default"} data-outcome={test.outcome}>
      <Icon className={cn("size-4", tone === "success" && "text-success")} />
      <AlertTitle>{testTitle(test)}</AlertTitle>
      <AlertDescription className="space-y-2">
        <p>
          {testAdvice(test)}
          {showWhen && (
            <span className="text-muted-foreground">
              {" "}
              Tested <Relative at={test.tested_at} />.
            </span>
          )}
        </p>
        {(retest || fix) && (
          <div className="flex flex-wrap gap-2">
            {fix &&
              (onReplaceKey && test.outcome === "rejected" ? (
                <Button type="button" variant="outline" size="sm" onClick={onReplaceKey}>
                  {fix.label}
                </Button>
              ) : (
                <Button type="button" variant="outline" size="sm" asChild>
                  <a href={fix.href}>{fix.label}</a>
                </Button>
              ))}
            {retest && (
              <Button type="button" variant="outline" size="sm" onClick={onRetest} disabled={busy}>
                Test again
              </Button>
            )}
          </div>
        )}
      </AlertDescription>
    </Alert>
  );
}

function StepIcon({ state }: { state: Step["state"] }) {
  if (state === "done") return <CheckCircle2 className="size-4 shrink-0 text-success" aria-label="Done" />;
  if (state === "unknown") return <CircleHelp className="size-4 shrink-0 text-muted-foreground" aria-label="Unknown" />;
  return <Circle className="size-4 shrink-0 text-muted-foreground" aria-label="To do" />;
}

/**
 * The next steps as a compact list: each done or not, the link that does
 * it beside it, and for the last one the command to start an agent.
 */
export function NextSteps({
  steps,
  agentCommand,
  runCommand,
  keyHint,
}: {
  steps: Step[];
  /** `tokenless run … -- claude`, once the service is in a bundle. */
  agentCommand?: string;
  /** `tokenless run … -- <command>`. */
  runCommand?: string;
  keyHint?: string | null;
}) {
  return (
    <section aria-label="Next steps" className="space-y-2">
      <h2 className="text-sm font-medium">Next steps</h2>
      <ol className="divide-y rounded-lg border">
        {steps.map((s) => (
          <li key={s.id} data-step={s.id} data-state={s.state} className="space-y-2 px-4 py-3">
            <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
              <StepIcon state={s.state} />
              <span className={cn("font-medium", s.state === "done" && "text-muted-foreground")}>{s.label}</span>
              <span className="min-w-0 flex-1 text-xs text-muted-foreground [overflow-wrap:anywhere]">{s.detail}</span>
              {s.action && s.state !== "done" && (
                <Button type="button" variant="outline" size="sm" asChild>
                  <a href={s.action.href}>{s.action.label}</a>
                </Button>
              )}
            </div>
            {s.id === "use" && agentCommand && (
              <div className="space-y-1 pl-7">
                <div className="flex items-center gap-2">
                  <code className="min-w-0 flex-1 rounded-md border bg-muted/40 px-3 py-2 font-mono text-xs [overflow-wrap:anywhere]">
                    {agentCommand}
                  </code>
                  <CopyButton value={agentCommand} label="Copy command" iconOnly />
                </div>
                {runCommand && (
                  <p className="text-xs text-muted-foreground">
                    Any other command: <code className="font-mono">{runCommand}</code>
                  </p>
                )}
                {keyHint && <p className="text-xs text-muted-foreground">{keyHint}</p>}
              </div>
            )}
          </li>
        ))}
      </ol>
    </section>
  );
}
