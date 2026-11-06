// SPDX-FileCopyrightText: 2026 credential-broker contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import { useMemo, useState, type FormEvent, type ReactNode } from "react";
import { FileCode2, Search, ShieldAlert, Upload } from "lucide-react";
import { get, post, type ServiceKind, type ServiceTemplate, type StoredTemplate, type TemplateCategory } from "../api";
import { CATEGORIES, CATEGORY_LABEL, injectionSummary, KIND_LABEL, latestTemplates, matchesSearch } from "../catalog";
import { useAction, useLoad } from "../hooks";
import {
  DialogActions,
  Empty,
  ErrorBanner,
  Field,
  FormDialog,
  Mono,
  Panel,
  SelectField,
  Status,
  Tags,
} from "../components/common";
import { ServiceLogo } from "../components/ServiceLogo";
import { Input } from "../components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "../components/ui/table";
import { Alert, AlertDescription, AlertTitle } from "../components/ui/alert";
import { Button } from "../components/ui/button-components";
import { PageContainer, PageHeader } from "../components/ui/page-header";
import { Skeleton } from "../components/ui/skeleton";
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

type KindFilter = "all" | ServiceKind;

export function Templates({ isAdmin }: { isAdmin: boolean }) {
  const templates = useLoad(() => get<StoredTemplate[]>("/templates"), []);
  const [importing, setImporting] = useState(false);
  const [yaml, setYaml] = useState("");
  const [reviewing, setReviewing] = useState<StoredTemplate | null>(null);
  const [viewing, setViewing] = useState<StoredTemplate | null>(null);
  const [query, setQuery] = useState("");
  const [kind, setKind] = useState<KindFilter>("all");
  const [category, setCategory] = useState<"all" | TemplateCategory>("all");
  const importAction = useAction();
  const rows = useMemo(
    () =>
      latestTemplates(templates.data ?? []).filter(
        (t) =>
          (kind === "all" || t.template.kind === kind) &&
          (category === "all" || t.template.category === category) &&
          matchesSearch(t.template, query),
      ),
    [templates.data, kind, category, query],
  )
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
        description="The service catalogue. A template knows a service's hosts, paths and methods and how its credential is sent; it sets the maximum scope, which services and rules can only narrow."
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
      <div className="flex flex-col gap-2 sm:flex-row sm:flex-wrap">
        <div className="relative w-full sm:w-72">
          <Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search services or hosts…"
            className="pl-9"
            aria-label="Search templates"
          />
        </div>
        <div className="w-full sm:w-[160px]">
          <SelectField
            value={kind}
            onChange={(v) => setKind(v as KindFilter)}
            options={[
              { value: "all", label: "All types" },
              { value: "http", label: "HTTP APIs" },
              { value: "mcp", label: "MCP servers" },
            ]}
          />
        </div>
        <div className="w-full sm:w-[200px]">
          <SelectField
            value={category}
            onChange={(v) => setCategory(v as "all" | TemplateCategory)}
            options={[{ value: "all", label: "All categories" }, ...CATEGORIES]}
          />
        </div>
      </div>
      <Panel>
        {templates.loading && !templates.data ? (
          <div className="space-y-3 p-4">
            {Array.from({ length: 6 }, (_, i) => (
              <Skeleton key={i} className="h-10 w-full" />
            ))}
          </div>
        ) : rows.length === 0 ? (
          <Empty
            icon={FileCode2}
            title={templates.data?.length ? "No template matches" : "No templates"}
            description={
              templates.data?.length
                ? "Try another search or filter, or use a Custom HTTP API template for any service."
                : "Import a template YAML to describe a service."
            }
          />
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Service</TableHead>
                <TableHead>Type</TableHead>
                <TableHead className="hidden md:table-cell">Category</TableHead>
                <TableHead className="hidden lg:table-cell">Hosts</TableHead>
                <TableHead className="hidden xl:table-cell">Injects</TableHead>
                <TableHead>Status</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.map((t) => (
                <TableRow
                  key={`${t.template.id}@${t.template.version}`}
                  className="cursor-pointer"
                  onClick={() => (t.status !== "approved" && isAdmin ? setReviewing(t) : setViewing(t))}
                >
                  <TableCell>
                    <div className="flex min-w-56 items-center gap-3">
                      <ServiceLogo template={t.template} size="sm" />
                      <div className="min-w-0">
                        <div className="truncate font-medium">{t.template.name}</div>
                        <div className="line-clamp-1 text-xs text-muted-foreground">{t.template.description}</div>
                      </div>
                    </div>
                  </TableCell>
                  <TableCell className="whitespace-nowrap text-muted-foreground">{KIND_LABEL[t.template.kind]}</TableCell>
                  <TableCell className="hidden whitespace-nowrap text-muted-foreground md:table-cell">
                    {CATEGORY_LABEL[t.template.category]}
                  </TableCell>
                  <TableCell className="hidden lg:table-cell">
                    {t.template.hosts.length ? (
                      <Tags values={t.template.hosts.slice(0, 2).concat(t.template.hosts.length > 2 ? [`+${t.template.hosts.length - 2}`] : [])} />
                    ) : (
                      <span className="text-xs text-muted-foreground">per credential</span>
                    )}
                  </TableCell>
                  <TableCell className="hidden max-w-72 xl:table-cell">
                    <Mono className="block truncate">{injectionSummary(t.template)}</Mono>
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center gap-2 whitespace-nowrap">
                      <Status tone={t.status === "approved" ? "success" : "warning"}>
                        {t.status === "approved" ? "approved" : "pending approval"}
                      </Status>
                      <span className="text-xs text-muted-foreground">v{t.template.version}</span>
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </Panel>
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
