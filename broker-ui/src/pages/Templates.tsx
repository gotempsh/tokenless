// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import { useState, type FormEvent, type ReactNode } from "react";
import { Info, Plus, ShieldAlert, Upload } from "lucide-react";
import { get, post, type ServiceTemplate, type StoredTemplate, type UserSummary } from "../api";
import { CATEGORY_LABEL, injectionSummary, KIND_LABEL } from "../catalog";
import { useAction, useLoad } from "../hooks";
import { DialogActions, ErrorBanner, Field, FormDialog, Mono, Tags } from "../components/common";
import { addServiceHref } from "../addService";
import { ServiceLogo } from "../components/ServiceLogo";
import { TemplateCatalog } from "../components/TemplateCatalog";
import { Alert, AlertDescription, AlertTitle } from "../components/ui/alert";
import { Button } from "../components/ui/button-components";
import { PageContainer, PageHeader } from "../components/ui/page-header";
import { Textarea } from "../components/ui/textarea";

function Fact({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="grid grid-cols-[6.5rem_1fr] items-start gap-2 text-sm">
      <dt className="pt-0.5 text-xs font-medium text-muted-foreground">{label}</dt>
      <dd className="min-w-0">{children}</dd>
    </div>
  );
}

function TemplateFacts({ t }: { t: ServiceTemplate }) {
  return (
    <dl className="space-y-2">
      <Fact label="Hosts">
        {t.hosts.length ? <Tags values={t.hosts} /> : <span className="text-muted-foreground">set per credential (admin)</span>}
      </Fact>
      <Fact label="Paths">
        <Tags values={t.allow.paths} />
      </Fact>
      <Fact label="Methods">
        <Tags values={t.allow.methods} />
      </Fact>
      <Fact label="Injects">
        <Mono className="break-all">{injectionSummary(t)}</Mono>
      </Fact>
      {(t.default_headers ?? []).length > 0 && (
        <Fact label="Default headers">
          <div className="space-y-1">
            {(t.default_headers ?? []).map((h) => (
              <Mono key={h.name} className="block break-all">
                {h.name}: {h.value}
              </Mono>
            ))}
          </div>
        </Fact>
      )}
      {t.suggested_variable && (
        <Fact label="Variable">
          <Mono>{`{{${t.suggested_variable}}}`}</Mono>
        </Fact>
      )}
      {t.validation && (
        <Fact label="Test request">
          <Mono>
            {t.validation.method} {t.validation.path}
          </Mono>
        </Fact>
      )}
      {t.host_override.allowed && (
        <Fact label="Override">Admins may set a custom host{t.host_override.required ? " (required)" : ""}</Fact>
      )}
    </dl>
  );
}

export function Templates({ user }: { user: UserSummary }) {
  const isAdmin = user.role === "admin";
  const templates = useLoad(() => get<StoredTemplate[]>("/templates"), []);
  const [importing, setImporting] = useState(false);
  const [yaml, setYaml] = useState("");
  const [reviewing, setReviewing] = useState<StoredTemplate | null>(null);
  const [viewing, setViewing] = useState<StoredTemplate | null>(null);
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

  const addTo = (t: StoredTemplate) => {
    setViewing(null);
    window.location.hash = addServiceHref({ template: t.template.id, back: "templates" });
  };
  // A card's main action: admins add an approved service and review a
  // pending one; everyone else reads its details.
  const open = (t: StoredTemplate) => {
    if (!isAdmin) setViewing(t);
    else if (t.status !== "approved") setReviewing(t);
    else addTo(t);
  };
  const openLabel = (t: StoredTemplate) =>
    !isAdmin ? `Details for ${t.template.name}` : t.status !== "approved" ? `Review ${t.template.name}` : `Add ${t.template.name}`;

  const cardAction = (t: StoredTemplate) => (
    <Button
      type="button"
      size="icon"
      variant="ghost"
      className="size-7 text-muted-foreground"
      aria-label={`Details for ${t.template.name}`}
      title="Details"
      onClick={() => setViewing(t)}
    >
      <Info />
    </Button>
  );

  return (
    <PageContainer>
      <PageHeader
        title="Templates"
        description="The service catalogue. Click a service to add its credential to a vault and put it in an access bundle in one step. A template knows the service's hosts, paths and methods and how its credential is sent; rules can only narrow that."
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
      <TemplateCatalog
        templates={templates.data ?? []}
        loading={templates.loading && !templates.data}
        includePending={isAdmin}
        onOpen={open}
        openLabel={openLabel}
        cardAction={cardAction}
      />
      <FormDialog
        open={viewing !== null}
        onOpenChange={(o) => {
          if (!o) setViewing(null);
        }}
        wide
        title={viewing?.template.name ?? "Template"}
      >
        {viewing && (
          <div className="space-y-4">
            <div className="flex items-start gap-3">
              <ServiceLogo template={viewing.template} size="lg" />
              <div className="min-w-0 space-y-1">
                <p className="text-sm text-muted-foreground">{viewing.template.description}</p>
                <p className="text-xs text-muted-foreground">
                  <Mono>
                    {viewing.template.id}@{viewing.template.version}
                  </Mono>{" "}
                  · {KIND_LABEL[viewing.template.kind]} · {CATEGORY_LABEL[viewing.template.category]} · {viewing.source}
                </p>
              </div>
            </div>
            <TemplateFacts t={viewing.template} />
            <details className="rounded-md border">
              <summary className="cursor-pointer px-4 py-2 text-sm font-medium">Template YAML</summary>
              <pre className="max-h-80 overflow-auto border-t bg-muted/40 p-4 font-mono text-xs">{viewing.yaml}</pre>
            </details>
            <DialogActions>
              <Button type="button" variant="outline" onClick={() => setViewing(null)}>
                Close
              </Button>
              {viewing.status === "approved" && (
                <Button
                  type="button"
                  disabled={!isAdmin}
                  title={isAdmin ? undefined : "Only admins can add services"}
                  onClick={() => addTo(viewing)}
                >
                  <Plus />
                  Add to a vault
                </Button>
              )}
            </DialogActions>
          </div>
        )}
      </FormDialog>
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
