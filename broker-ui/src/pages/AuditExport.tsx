// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// Audit export: webhooks the audit log is sent to, how far each has got,
// and the destination form, which is a page of its own.

import { useState, type FormEvent } from "react";
import { FastForward, Pause, Pencil, Play, Plus, RotateCw, Send, Trash2, Webhook } from "lucide-react";
import {
  del,
  get,
  post,
  put,
  type AuditDestination,
  type AuditOutcome,
  type CreatedAuditDestination,
  type DeliveryTest,
  type PayloadFormat,
} from "../api";
import {
  behindText,
  deliveryStatus,
  destinationForm,
  destinationFormProblem,
  destinationInput,
  NAME_MAX,
  newDestinationForm,
  type DestinationForm,
  type StartAt,
} from "../auditExport";
import { useBreadcrumbs } from "../breadcrumbs";
import { useAction, useLoad, usePolling } from "../hooks";
import {
  CheckField,
  ChoiceCards,
  ConfirmDialog,
  Empty,
  ErrorBanner,
  FactRow,
  FactRows,
  Field,
  fromWidth,
  Loading,
  Mono,
  OneTimeSecret,
  Panel,
  Relative,
  rowLink,
  RowMenu,
  Status,
  useConfirm,
} from "../components/common";
import { SettingsSection } from "../components/layout";
import { Alert, AlertDescription, AlertTitle } from "../components/ui/alert";
import { Button } from "../components/ui/button-components";
import { Input } from "../components/ui/input";
import { PageContainer, PageHeader } from "../components/ui/page-header";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "../components/ui/table";
import { Textarea } from "../components/ui/textarea";

export const NEW_DESTINATION_HREF = "#/settings/audit-export/new";
export const destinationHref = (id: string) => `#/settings/audit-export/${id}`;

const OUTCOMES: { value: AuditOutcome; label: string }[] = [
  { value: "success", label: "Success" },
  { value: "denied", label: "Denied" },
  { value: "failure", label: "Failure" },
];

const VERIFY_HINT = (
  <>
    Receivers check each request's <Mono>webhook-signature</Mono> header with it, as in the Standard Webhooks
    specification.
  </>
);

function host(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return url;
  }
}

function testMessage(t: DeliveryTest): string {
  if (t.delivered) return `The receiver answered ${t.status ?? "OK"}.`;
  return t.error ?? (t.status ? `The receiver answered ${t.status}.` : "The test was not delivered.");
}

/** The Settings section for audit export. */
export function AuditExportSettings() {
  const destinations = useLoad(() => get<AuditDestination[]>("/audit-export/destinations"), []);
  const list = destinations.data;
  // Delivery moves on its own; keep the status current while someone watches.
  usePolling(destinations.reload, 5000, (list?.length ?? 0) > 0);
  const action = useAction();
  const remove = useConfirm<AuditDestination>();
  const skip = useConfirm<AuditDestination>();
  const rotate = useConfirm<AuditDestination>();
  const [notice, setNotice] = useState<{ name: string; text: string; ok: boolean } | null>(null);
  const [secret, setSecret] = useState<{ name: string; value: string } | null>(null);

  const call = async (fn: () => Promise<unknown>) => {
    setNotice(null);
    const done = await action.run(async () => {
      await fn();
      return true;
    });
    destinations.reload();
    return done;
  };
  const sendTest = async (d: AuditDestination) => {
    setNotice(null);
    const result = await action.run(() => post<DeliveryTest>(`/audit-export/destinations/${d.id}/test`, {}));
    if (result) setNotice({ name: d.name, text: testMessage(result), ok: result.delivered });
  };
  const confirmSkip = async () => {
    const d = skip.target;
    if (!d) return;
    await call(() => post(`/audit-export/destinations/${d.id}/skip`, {}));
    skip.close();
  };
  const confirmRotate = async () => {
    const d = rotate.target;
    if (!d) return;
    const result = await action.run(() =>
      post<{ signing_secret: string }>(`/audit-export/destinations/${d.id}/rotate-secret`, {}),
    );
    rotate.close();
    if (result) setSecret({ name: d.name, value: result.signing_secret });
  };
  const confirmDelete = async () => {
    const d = remove.target;
    if (!d) return;
    await call(() => del(`/audit-export/destinations/${d.id}`));
    remove.close();
  };

  const addButton = (
    <Button asChild variant="outline" size="sm">
      <a href={NEW_DESTINATION_HREF}>
        <Plus />
        Add a webhook
      </a>
    </Button>
  );

  return (
    <>
      <SettingsSection
        title="Audit export"
        hint="Send the audit log to your own system as it is written: a SIEM, a log pipeline or any HTTPS endpoint."
      >
        <ErrorBanner error={destinations.error ?? action.error} />
        {notice && (
          <Alert variant={notice.ok ? "default" : "destructive"}>
            <Send className="size-4" />
            <AlertTitle>Test to {notice.name}</AlertTitle>
            <AlertDescription>{notice.text}</AlertDescription>
          </Alert>
        )}
        {secret && <OneTimeSecret label={`New signing secret for ${secret.name}`} value={secret.value} hint={VERIFY_HINT} />}
        <Panel>
          {!list ? (
            <Loading rows={2} />
          ) : list.length === 0 ? (
            <Empty
              icon={Webhook}
              title="The audit log stays here"
              description="Add a webhook and every audit event is sent to it in signed batches, in order, retried until it arrives. Filter by action, outcome or vault to send only what matters."
              action={addButton}
            />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Webhook</TableHead>
                  <TableHead className={fromWidth.md}>Status</TableHead>
                  <TableHead className={fromWidth.xl}>Last delivered</TableHead>
                  <TableHead className="w-10">
                    <span className="sr-only">Actions</span>
                  </TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {list.map((d) => {
                  const status = deliveryStatus(d);
                  return (
                    <TableRow key={d.id} {...rowLink(destinationHref(d.id))}>
                      <TableCell>
                        <div className="font-medium">{d.name}</div>
                        <div className="text-xs text-muted-foreground">
                          <Mono>{host(d.url)}</Mono>
                        </div>
                        {d.last_error && d.status !== "up_to_date" && (
                          <div className="mt-1 text-xs text-destructive [overflow-wrap:anywhere]">{d.last_error}</div>
                        )}
                      </TableCell>
                      <TableCell className={fromWidth.md}>
                        <Status tone={status.tone}>{status.label}</Status>
                      </TableCell>
                      <TableCell className={fromWidth.xl}>
                        <Relative at={d.last_success_at} />
                      </TableCell>
                      <TableCell className="text-right">
                        <RowMenu
                          label={d.name}
                          items={[
                            { label: "Edit", icon: Pencil, onSelect: () => (window.location.hash = destinationHref(d.id)) },
                            { label: "Send a test", icon: Send, onSelect: () => void sendTest(d) },
                            d.paused
                              ? {
                                  label: "Resume",
                                  icon: Play,
                                  onSelect: () => void call(() => post(`/audit-export/destinations/${d.id}/resume`, {})),
                                }
                              : {
                                  label: "Pause",
                                  icon: Pause,
                                  onSelect: () => void call(() => post(`/audit-export/destinations/${d.id}/pause`, {})),
                                },
                            { label: "Skip to now", icon: FastForward, onSelect: () => skip.ask(d), disabled: d.behind === 0, reason: "Nothing is waiting to be sent" },
                            { label: "New signing secret", icon: RotateCw, onSelect: () => rotate.ask(d) },
                            { label: "Delete", icon: Trash2, onSelect: () => remove.ask(d), destructive: true },
                          ]}
                        />
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          )}
        </Panel>
        {list && list.length > 0 && addButton}
      </SettingsSection>
      <ConfirmDialog
        open={skip.open}
        onOpenChange={skip.onOpenChange}
        title={`Skip ${skip.target ? behindText(skip.target.behind) : "the events not yet sent"}?`}
        description="They stay in this instance's audit log but are never sent to this webhook. The skip itself is recorded in the audit log."
        confirmLabel="Skip to now"
        busy={action.busy}
        onConfirm={() => void confirmSkip()}
      />
      <ConfirmDialog
        open={rotate.open}
        onOpenChange={rotate.onOpenChange}
        title={`New signing secret for ${rotate.target?.name ?? "the webhook"}?`}
        description="The old secret stops working at once: requests are signed with the new one from the next batch. Update the receiver right after."
        confirmLabel="Make a new secret"
        busy={action.busy}
        onConfirm={() => void confirmRotate()}
      />
      <ConfirmDialog
        open={remove.open}
        onOpenChange={remove.onOpenChange}
        title={`Delete ${remove.target?.name ?? "the webhook"}?`}
        description="Nothing more is sent to it. Pause it instead to stop for a while and carry on later from where it stopped."
        confirmLabel="Delete webhook"
        busy={action.busy}
        onConfirm={() => void confirmDelete()}
      />
    </>
  );
}

/** Adding (`destinationId` absent) or editing an audit webhook. */
export function DestinationFormPage({ destinationId }: { destinationId?: string }) {
  const destination = useLoad(
    () =>
      destinationId ? get<AuditDestination>(`/audit-export/destinations/${destinationId}`) : Promise.resolve(undefined),
    [destinationId],
  );
  const d = destination.data;
  const [created, setCreated] = useState<CreatedAuditDestination | null>(null);
  useBreadcrumbs([
    { label: "Settings", href: "#/settings" },
    { label: destinationId ? (d?.name ?? null) : "Add an audit webhook" },
  ]);
  const leave = () => {
    window.location.hash = "#/settings";
  };

  if (created) {
    return (
      <PageContainer width="form">
        <PageHeader title={`${created.destination.name} is added`} />
        <OneTimeSecret label="Signing secret" value={created.signing_secret} hint={VERIFY_HINT} />
        <p className="text-sm text-muted-foreground">
          Events start arriving within a few seconds. Its status in Settings shows how far it has got.
        </p>
        <div className="flex justify-end">
          <Button onClick={leave}>Done</Button>
        </div>
      </PageContainer>
    );
  }

  return (
    <PageContainer width="form">
      <PageHeader title={destinationId ? (d ? `Edit ${d.name}` : "Edit webhook") : "Add an audit webhook"} />
      <ErrorBanner error={destination.error} />
      {destinationId && !d ? (
        destination.loading && (
          <Panel>
            <Loading />
          </Panel>
        )
      ) : (
        <>
          {d && <Delivery destination={d} />}
          <DestinationFormBody key={d?.id ?? "new"} destination={d ?? null} onCreated={setCreated} onDone={leave} />
        </>
      )}
    </PageContainer>
  );
}

function Delivery({ destination: d }: { destination: AuditDestination }) {
  const status = deliveryStatus(d);
  return (
    <FactRows>
      <FactRow label="Status">
        <Status tone={status.tone}>{status.label}</Status>
      </FactRow>
      <FactRow label="Last delivered">
        <Relative at={d.last_success_at} />
      </FactRow>
      {d.last_error && (
        <FactRow label="Last error">
          <span className="text-destructive">{d.last_error}</span>
          {d.failing_since && (
            <div className="text-xs text-muted-foreground">
              Since <Relative at={d.failing_since} />,{" "}
              {d.consecutive_failures === 1 ? "1 failed attempt" : `${d.consecutive_failures} failed attempts`}
            </div>
          )}
        </FactRow>
      )}
    </FactRows>
  );
}

function DestinationFormBody({
  destination,
  onCreated,
  onDone,
}: {
  destination: AuditDestination | null;
  onCreated: (created: CreatedAuditDestination) => void;
  onDone: () => void;
}) {
  const [form, setForm] = useState<DestinationForm>(() =>
    destination ? destinationForm(destination) : newDestinationForm(),
  );
  const action = useAction();
  const problem = destinationFormProblem(form, destination);
  const set = (patch: Partial<DestinationForm>) => setForm((f) => ({ ...f, ...patch }));
  const toggleOutcome = (o: AuditOutcome, on: boolean) =>
    set({ outcomes: on ? [...form.outcomes, o] : form.outcomes.filter((x) => x !== o) });
  const storedHeader = destination?.has_auth_header && destination.auth_header_name === form.auth_header_name.trim();

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (problem) return;
    const body = destinationInput(form, destination);
    if (destination) {
      const saved = await action.run(() => put<AuditDestination>(`/audit-export/destinations/${destination.id}`, body));
      if (saved) onDone();
    } else {
      const created = await action.run(() =>
        post<CreatedAuditDestination>("/audit-export/destinations", { ...body, start_at: form.start_at }),
      );
      if (created) onCreated(created);
    }
  };

  return (
    <form className="space-y-6" onSubmit={submit}>
      <ErrorBanner error={action.error} />
      <fieldset className="space-y-4">
        <legend className="mb-2 text-sm font-semibold">Receiver</legend>
        <Field label="Name" htmlFor="ae-name">
          <Input
            id="ae-name"
            maxLength={NAME_MAX}
            value={form.name}
            onChange={(e) => set({ name: e.target.value })}
            placeholder="Security SIEM"
            required
          />
        </Field>
        <Field label="URL" htmlFor="ae-url" hint="Events are sent here with POST. https, or http to localhost.">
          <Input
            id="ae-url"
            type="url"
            className="font-mono"
            value={form.url}
            onChange={(e) => set({ url: e.target.value })}
            placeholder="https://siem.example.com/ingest/tokenless"
            required
          />
        </Field>
        <ChoiceCards<PayloadFormat>
          name="ae-format"
          value={form.format}
          onChange={(format) => set({ format })}
          columns={2}
          choices={[
            { value: "json", title: "JSON", description: "One object per request, with the batch's events in a list." },
            { value: "ndjson", title: "NDJSON", description: "One event per line, for log pipelines such as Vector or Fluent Bit." },
          ]}
        />
      </fieldset>

      <fieldset className="space-y-4 border-t pt-6">
        <legend className="mb-2 text-sm font-semibold">Authentication at the receiver</legend>
        <p className="text-xs text-muted-foreground">
          Every request is signed. If the receiver also wants a token, it is sent in a header of its choosing.
        </p>
        <div className="grid gap-4 sm:grid-cols-[minmax(0,12rem)_minmax(0,1fr)]">
          <Field label="Header" htmlFor="ae-header-name">
            <Input
              id="ae-header-name"
              className="font-mono"
              value={form.auth_header_name}
              onChange={(e) => set({ auth_header_name: e.target.value })}
              placeholder="Authorization"
              autoComplete="off"
              disabled={form.clear_auth_header}
            />
          </Field>
          <Field
            label="Value"
            htmlFor="ae-header-value"
            hint={storedHeader ? "A value is stored and never shown. Leave this empty to keep it." : undefined}
          >
            <Input
              id="ae-header-value"
              type="password"
              value={form.auth_header_value}
              onChange={(e) => set({ auth_header_value: e.target.value })}
              autoComplete="new-password"
              placeholder={storedHeader ? "••••••••  (stored)" : "Bearer …"}
              disabled={form.clear_auth_header}
            />
          </Field>
        </div>
        {destination?.has_auth_header && (
          <CheckField
            id="ae-clear-header"
            checked={form.clear_auth_header}
            onChange={(v) => set({ clear_auth_header: v, auth_header_value: "" })}
          >
            Remove the stored header
          </CheckField>
        )}
      </fieldset>

      <fieldset className="space-y-4 border-t pt-6">
        <legend className="mb-2 text-sm font-semibold">Which events</legend>
        <p className="text-xs text-muted-foreground">Leave a filter empty to send everything it covers.</p>
        <Field
          label="Actions"
          htmlFor="ae-actions"
          hint={
            <>
              One per line. A prefix matches every action that starts with it: <Mono>credential.</Mono> sends every
              credential change.
            </>
          }
        >
          <Textarea
            id="ae-actions"
            rows={3}
            className="font-mono"
            value={form.action_prefixes}
            onChange={(e) => set({ action_prefixes: e.target.value })}
            placeholder={"credential.\nproxy.inject"}
          />
        </Field>
        <div className="space-y-2">
          <p className="text-sm font-medium">Outcomes</p>
          <div className="flex flex-wrap gap-x-6 gap-y-2">
            {OUTCOMES.map((o) => (
              <CheckField
                key={o.value}
                id={`ae-outcome-${o.value}`}
                checked={form.outcomes.includes(o.value)}
                onChange={(on) => toggleOutcome(o.value, on)}
              >
                {o.label}
              </CheckField>
            ))}
          </div>
        </div>
        <Field label="Vaults" htmlFor="ae-vaults" hint="Vault IDs, one per line. Events about no vault are sent only when this is empty.">
          <Textarea
            id="ae-vaults"
            rows={2}
            className="font-mono"
            value={form.vault_ids}
            onChange={(e) => set({ vault_ids: e.target.value })}
          />
        </Field>
      </fieldset>

      {!destination && (
        <fieldset className="space-y-4 border-t pt-6">
          <legend className="mb-2 text-sm font-semibold">Start from</legend>
          <ChoiceCards<StartAt>
            name="ae-start-at"
            value={form.start_at}
            onChange={(start_at) => set({ start_at })}
            choices={[
              { value: "now", title: "Now", description: "Send events written from now on." },
              {
                value: "oldest",
                title: "The oldest event",
                description: "Send the whole audit log this instance holds first, then carry on.",
              },
            ]}
          />
        </fieldset>
      )}

      <div className="flex items-center justify-end gap-2 border-t pt-4">
        {problem && <p className="mr-auto text-xs text-muted-foreground">{problem}</p>}
        <Button type="button" variant="outline" onClick={onDone}>
          Cancel
        </Button>
        <Button type="submit" disabled={action.busy || problem !== null}>
          {destination ? "Save webhook" : "Add webhook"}
        </Button>
      </div>
    </form>
  );
}
