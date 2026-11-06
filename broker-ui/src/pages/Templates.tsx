// SPDX-FileCopyrightText: 2026 credential-broker contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import { useState, type FormEvent, type ReactNode } from "react";
import { FileCode2, ShieldAlert, Upload } from "lucide-react";
import { get, post, type StoredTemplate } from "../api";
import { useAction, useLoad } from "../hooks";
import { DialogActions, Empty, ErrorBanner, Field, FormDialog, Mono, Panel, Status, Tags } from "../components/common";
import { Alert, AlertDescription, AlertTitle } from "../components/ui/alert";
import { Button } from "../components/ui/button-components";
import { PageContainer, PageHeader } from "../components/ui/page-header";
import { Skeleton } from "../components/ui/skeleton";
import { Textarea } from "../components/ui/textarea";

function injectionSummary(t: StoredTemplate["template"]): string {
  switch (t.injection.method) {
    case "bearer":
      return `Authorization: Bearer <${t.injection.field}>`;
    case "basic":
      return `Authorization: Basic <${t.injection.username_field}:${t.injection.password_field}>`;
    case "header":
      return `${t.injection.name}: ${t.injection.prefix ?? ""}<${t.injection.field}>`;
  }
}

function Fact({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="grid grid-cols-[5.5rem_1fr] items-start gap-2 text-sm">
      <dt className="pt-0.5 text-xs font-medium text-muted-foreground">{label}</dt>
      <dd className="min-w-0">{children}</dd>
    </div>
  );
}

function TemplateCard({ t, onReview }: { t: StoredTemplate; onReview?: () => void }) {
  return (
    <Panel className="flex flex-col gap-4 p-5">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <h3 className="font-semibold">{t.template.name}</h3>
          <p className="mt-1 text-xs text-muted-foreground">
            <Mono>
              {t.template.id}@{t.template.version}
            </Mono>{" "}
            · {t.source}
          </p>
        </div>
        <Status tone={t.status === "approved" ? "success" : "warning"}>
          {t.status === "approved" ? "approved" : "pending approval"}
        </Status>
      </div>
      {t.template.description && <p className="text-sm text-muted-foreground">{t.template.description}</p>}
      <dl className="space-y-2">
        <Fact label="Hosts">
          {t.template.hosts.length ? (
            <Tags values={t.template.hosts} />
          ) : (
            <span className="text-muted-foreground">set per credential (admin)</span>
          )}
        </Fact>
        <Fact label="Paths">
          <Tags values={t.template.allow.paths} />
        </Fact>
        <Fact label="Methods">
          <Tags values={t.template.allow.methods} />
        </Fact>
        <Fact label="Injects">
          <Mono className="break-all">{injectionSummary(t.template)}</Mono>
        </Fact>
        {t.template.host_override.allowed && (
          <Fact label="Override">
            Admins may set a custom host{t.template.host_override.required ? " (required)" : ""}
          </Fact>
        )}
      </dl>
      {onReview && (
        <div className="mt-auto">
          <Button type="button" variant="outline" size="sm" onClick={onReview}>
            Review and approve
          </Button>
        </div>
      )}
    </Panel>
  );
}

export function Templates({ isAdmin }: { isAdmin: boolean }) {
  const templates = useLoad(() => get<StoredTemplate[]>("/templates"), []);
  const [importing, setImporting] = useState(false);
  const [yaml, setYaml] = useState("");
  const [reviewing, setReviewing] = useState<StoredTemplate | null>(null);
  const importAction = useAction();
  const approveAction = useAction();

  const importTemplate = async (e: FormEvent) => {
    e.preventDefault();
    const t = await importAction.run(() => post<StoredTemplate>("/templates/import", { yaml }));
    if (t) {
      setYaml("");
      setImporting(false);
      setReviewing(t);
      templates.reload();
    }
  };

  const approve = async (t: StoredTemplate) => {
    const ok = await approveAction.run(() =>
      post<StoredTemplate>(`/templates/${t.template.id}/${t.template.version}/approve`),
    );
    if (ok) {
      setReviewing(null);
      templates.reload();
    }
  };

  return (
    <PageContainer>
      <PageHeader
        title="Templates"
        description="Templates describe a service: which hosts, paths and methods a credential may ever be used for, and how it is injected. They set the maximum scope; credentials and rules can only narrow it."
        actions={
          <Button
            type="button"
            variant="outline"
            onClick={() => setImporting(true)}
            disabled={!isAdmin}
            title={isAdmin ? undefined : "Only admins can import templates"}
          >
            <Upload />
            Import template
          </Button>
        }
      />
      <ErrorBanner error={templates.error} />
      {templates.loading && !templates.data ? (
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
          {Array.from({ length: 3 }, (_, i) => (
            <Skeleton key={i} className="h-64 w-full rounded-lg" />
          ))}
        </div>
      ) : templates.data?.length === 0 ? (
        <Panel>
          <Empty icon={FileCode2} title="No templates" description="Import a template YAML to describe a service." />
        </Panel>
      ) : (
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
          {templates.data?.map((t) => (
            <TemplateCard
              key={`${t.template.id}@${t.template.version}`}
              t={t}
              onReview={t.status !== "approved" && isAdmin ? () => setReviewing(t) : undefined}
            />
          ))}
        </div>
      )}
      <FormDialog
        open={importing}
        onOpenChange={(o) => {
          setImporting(o);
          if (!o) importAction.clearError();
        }}
        wide
        title="Import a template"
        description="An imported template stays pending until an admin approves the hosts it binds credentials to."
      >
        <form className="space-y-4" onSubmit={importTemplate}>
          <ErrorBanner error={importAction.error} />
          <Field label="Template YAML" htmlFor="template-yaml">
            <Textarea
              id="template-yaml"
              rows={14}
              className="font-mono text-xs"
              value={yaml}
              onChange={(e) => setYaml(e.target.value)}
              required
              spellCheck={false}
            />
          </Field>
          <DialogActions>
            <Button type="button" variant="outline" onClick={() => setImporting(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={importAction.busy}>
              Import for review
            </Button>
          </DialogActions>
        </form>
      </FormDialog>
      <FormDialog
        open={reviewing !== null && reviewing.status !== "approved"}
        onOpenChange={(o) => {
          if (!o) {
            setReviewing(null);
            approveAction.clearError();
          }
        }}
        wide
        title={reviewing ? `Approve "${reviewing.template.name}"?` : "Approve template"}
      >
        {reviewing && (
          <div className="space-y-4">
            <ErrorBanner error={approveAction.error} />
            <Alert variant="warning">
              <ShieldAlert className="size-4" />
              <AlertTitle>Approving binds credentials to these hosts</AlertTitle>
              <AlertDescription className="space-y-2">
                <p>Credentials created from this template may be injected into requests to:</p>
                {reviewing.template.hosts.length ? (
                  <Tags values={reviewing.template.hosts} />
                ) : (
                  <p>a host chosen by an admin on each credential.</p>
                )}
                <div className="flex flex-wrap items-center gap-2">
                  Paths <Tags values={reviewing.template.allow.paths} /> · methods{" "}
                  <Tags values={reviewing.template.allow.methods} /> · header{" "}
                  <Mono>{injectionSummary(reviewing.template)}</Mono>
                </div>
              </AlertDescription>
            </Alert>
            <pre className="max-h-80 overflow-auto rounded-md border bg-muted/40 p-4 font-mono text-xs">{reviewing.yaml}</pre>
            <DialogActions>
              <Button type="button" variant="outline" onClick={() => setReviewing(null)}>
                Not now
              </Button>
              <Button type="button" disabled={approveAction.busy} onClick={() => void approve(reviewing)}>
                Approve host binding
              </Button>
            </DialogActions>
          </div>
        )}
      </FormDialog>
    </PageContainer>
  );
}
