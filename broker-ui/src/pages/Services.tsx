// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// A vault's services: credentials created from a template, each with its
// secret fields (a value or a variable reference) and custom headers.

import { useMemo, useState } from "react";
import { Braces, KeyRound, Lock, Plus } from "lucide-react";
import { get, type CredentialMeta, type Page, type StoredTemplate } from "../api";
import { can, type Me } from "../access";
import { KIND_LABEL, targetHosts } from "../catalog";
import { useLoad } from "../hooks";
import { fromWidth, Empty, ErrorBanner, Loading, Pager, Panel, rowLink, Section, Tags, When } from "../components/common";
import { cn } from "../lib/utils";
import { ServiceLogo } from "../components/ServiceLogo";
import { addServiceHref } from "../addService";
import { templateOf } from "../bundleServices";
import { Button } from "../components/ui/button-components";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "../components/ui/table";

export { templateOf };

/** A vault's services. A row opens the service, where it is tested and changed. */
export function Services({ vaultId, user }: { vaultId: string; user: Me }) {
  const isAdmin = can(user, vaultId, "manage");
  const [page, setPage] = useState(1);
  const creds = useLoad(() => get<Page<CredentialMeta>>(`/vaults/${vaultId}/credentials?page=${page}`), [vaultId, page]);
  const templates = useLoad(() => get<StoredTemplate[]>("/templates"), []);
  const all = useMemo(() => templates.data ?? [], [templates.data]);

  const addButton = (
    <Button
      type="button"
      onClick={() => {
        window.location.hash = addServiceHref({ vault: vaultId, back: `vaults/${vaultId}` });
      }}
      disabled={!isAdmin}
      title={isAdmin ? undefined : "Only a vault's admins can add services"}
    >
      <Plus />
      Add service
    </Button>
  );

  return (
    <Section title="Services" actions={addButton}>
      <ErrorBanner error={creds.error ?? templates.error} />
      <Panel>
        {creds.loading && !creds.data ? (
          <Loading />
        ) : creds.data?.items.length === 0 ? (
          <Empty
            icon={KeyRound}
            title="No services in this vault"
            description="Add a service from the catalogue, for example a GitHub token or an OpenAI key. Agents never see the secret; the proxy adds it to their requests."
            action={addButton}
          />
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Service</TableHead>
                <TableHead className={fromWidth["4xl"]}>Type</TableHead>
                <TableHead className={fromWidth["2xl"]}>Target</TableHead>
                <TableHead className={fromWidth.xl}>Secret</TableHead>
                <TableHead className={cn(fromWidth.md, "text-right")}>Updated</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {creds.data?.items.map((c) => {
                const tpl = templateOf(all, c);
                return (
                  <TableRow key={c.id} {...rowLink(serviceHref(vaultId, c.id))}>
                    <TableCell>
                      <div className="flex min-w-0 items-center gap-3">
                        <ServiceLogo template={tpl ?? { id: c.template_id, kind: "http" }} size="sm" />
                        <div className="min-w-0">
                          <div className="truncate font-medium">{c.name}</div>
                          <div className="truncate text-xs text-muted-foreground">
                            {tpl?.name ?? c.template_id} · v{c.template_version}
                          </div>
                        </div>
                      </div>
                    </TableCell>
                    <TableCell className={cn(fromWidth["4xl"], "text-muted-foreground")}>{KIND_LABEL[tpl?.kind ?? "http"]}</TableCell>
                    <TableCell className={fromWidth["2xl"]}>
                      <Tags values={targetHosts(tpl, c.host_override)} />
                    </TableCell>
                    <TableCell className={fromWidth.xl}>
                      <SecretSummary credential={c} />
                    </TableCell>
                    <TableCell className={cn(fromWidth.md, "text-right text-muted-foreground")}>
                      <When at={c.updated_at} />
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        )}
        <Pager page={creds.data} onPage={setPage} />
      </Panel>
    </Section>
  );
}

/** A service's own page, under its vault. */
export function serviceHref(vaultId: string, credentialId: string): string {
  return `#/vaults/${vaultId}/services/${credentialId}`;
}

export function SecretSummary({ credential }: { credential: CredentialMeta }) {
  const refs = credential.variable_refs;
  const headers = credential.custom_headers.length;
  const placeholders = credential.substitutions.length;
  return (
    <div className="flex flex-wrap items-center gap-1.5 text-xs">
      {refs.length > 0 ? (
        refs.map((k) => (
          <span key={k} className="inline-flex items-center gap-1 rounded border bg-muted/40 px-1.5 py-0.5 font-mono">
            <Braces className="size-3 text-muted-foreground" />
            {k}
          </span>
        ))
      ) : (
        <span className="inline-flex items-center gap-1 text-muted-foreground">
          <Lock className="size-3" />
          stored value
        </span>
      )}
      {headers > 0 && (
        <span className="text-muted-foreground">
          · {headers} header{headers === 1 ? "" : "s"}
        </span>
      )}
      {placeholders > 0 && (
        <span className="text-muted-foreground">
          · {placeholders} placeholder{placeholders === 1 ? "" : "s"}
        </span>
      )}
    </div>
  );
}
