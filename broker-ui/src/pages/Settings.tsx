// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import { useState } from "react";
import { get, put, type Settings as SettingsModel } from "../api";
import { useAction, useLoad } from "../hooks";
import { ChoiceCards, ErrorBanner, Field, lines, SelectField } from "../components/common";
import { Button } from "../components/ui/button-components";
import { Label } from "../components/ui/label";
import { SettingsSection } from "../components/layout";
import { PageContainer, PageHeader } from "../components/ui/page-header";
import { Skeleton } from "../components/ui/skeleton";
import { Switch } from "../components/ui/switch";
import { Textarea } from "../components/ui/textarea";
import { DEFAULT_QUARANTINE, parseQuarantineKey, quarantineKey, quarantineOptions } from "../quarantine";
import { AuditExportSettings } from "./AuditExport";
import { SingleSignOnSettings } from "./SingleSignOn";

type Unmatched = SettingsModel["unmatched_host_policy"];

const LIFETIMES = [
  { value: String(15 * 60), label: "15 minutes" },
  { value: String(60 * 60), label: "1 hour" },
  { value: String(8 * 3600), label: "8 hours" },
  { value: String(24 * 3600), label: "1 day" },
  { value: String(7 * 24 * 3600), label: "7 days (default)" },
  { value: String(30 * 24 * 3600), label: "30 days" },
  { value: String(90 * 24 * 3600), label: "90 days" },
];

function lifetimeOptions(current: number) {
  if (LIFETIMES.some((o) => o.value === String(current))) return LIFETIMES;
  return [...LIFETIMES, { value: String(current), label: `${Math.round(current / 60)} minutes` }];
}

export function Settings() {
  const settings = useLoad(() => get<SettingsModel>("/settings"), []);
  const action = useAction();
  const [allowText, setAllowText] = useState<string | null>(null);
  const [hostsText, setHostsText] = useState<string | null>(null);
  const current = settings.data;

  const save = async (next: SettingsModel) => {
    const saved = await action.run(() => put<SettingsModel>("/settings", next));
    if (saved) {
      setAllowText(null);
      setHostsText(null);
      settings.reload();
    }
  };

  return (
    <PageContainer width="settings">
      <PageHeader title="Settings" />
      <ErrorBanner error={settings.error ?? action.error} />
      {!current ? (
        <div className="space-y-6">
          <Skeleton className="h-32 w-full rounded-lg" />
          <Skeleton className="h-48 w-full rounded-lg" />
        </div>
      ) : (
        <div>
          <SettingsSection title="Other hosts" hint="Hosts that aren't one of a session's services.">
            <ChoiceCards<Unmatched>
              name="unmatched"
              columns={1}
              value={current.unmatched_host_policy}
              onChange={(v) => void save({ ...current, unmatched_host_policy: v })}
              choices={[
                {
                  value: "passthrough",
                  title: "Allow",
                  description: "Agents reach any other host. The proxy passes it through without reading it or adding a credential.",
                },
                {
                  value: "deny",
                  title: "Block",
                  description: "Agents reach only their session's services and the always-reachable hosts.",
                },
              ]}
            />
          </SettingsSection>
          <SettingsSection
            title="Session lifetime"
            hint="The longest session anyone may create. Sessions started by tokenless run renew while the command runs."
          >
            <Label htmlFor="max-ttl" className="sr-only">
              Longest session
            </Label>
            <SelectField
              id="max-ttl"
              className="w-full sm:w-[220px]"
              value={String(current.max_session_ttl_secs)}
              onChange={(v) => void save({ ...current, max_session_ttl_secs: Number(v) })}
              options={lifetimeOptions(current.max_session_ttl_secs)}
            />
          </SettingsSection>
          <SettingsSection title="Always reachable" hint="Reachable from every session while other hosts are blocked. Never given a credential.">
            <form
              className="space-y-3"
              onSubmit={(e) => {
                e.preventDefault();
                void save({ ...current, passthrough_hosts: lines(hostsText ?? "") });
              }}
            >
              <Field
                label="Hosts"
                htmlFor="passthrough-hosts"
                hint={
                  current.unmatched_host_policy === "deny"
                    ? "One per line, e.g. registry.npmjs.org or *.pythonhosted.org (one label), with :port for ports other than 443."
                    : "Only used while other hosts are blocked; with Allow every host is reachable already."
                }
              >
                <Textarea
                  id="passthrough-hosts"
                  rows={4}
                  className="font-mono"
                  value={hostsText ?? current.passthrough_hosts.join("\n")}
                  onChange={(e) => setHostsText(e.target.value)}
                  placeholder={"registry.npmjs.org\npypi.org\n*.pythonhosted.org"}
                />
              </Field>
              <Button type="submit" variant="outline" disabled={action.busy || hostsText === null}>
                Save hosts
              </Button>
            </form>
          </SettingsSection>
          <SettingsSection
            title="Private addresses"
            hint="Applies to other hosts and credential tests. A session's own services are always reachable."
          >
            <div className="flex items-start justify-between gap-4">
              <div className="space-y-1">
                <Label htmlFor="block-private">Block non-public addresses</Label>
                <p className="text-sm text-muted-foreground">
                  Loopback, private (RFC 1918), link-local, cloud metadata and other non-public ranges.
                </p>
              </div>
              <Switch
                id="block-private"
                checked={current.egress.block_private}
                disabled={action.busy}
                onCheckedChange={(v) => void save({ ...current, egress: { ...current.egress, block_private: v } })}
              />
            </div>
            <form
              className="space-y-3 pt-2"
              onSubmit={(e) => {
                e.preventDefault();
                void save({ ...current, egress: { ...current.egress, allow: lines(allowText ?? "") } });
              }}
            >
              <Field
                label="Allowed ranges"
                htmlFor="egress-allow"
                hint="CIDR, one per line. These stay reachable while non-public addresses are blocked."
              >
                <Textarea
                  id="egress-allow"
                  rows={3}
                  className="font-mono"
                  value={allowText ?? current.egress.allow.join("\n")}
                  onChange={(e) => setAllowText(e.target.value)}
                  placeholder={"10.20.0.0/16\nfd00:1234::/32"}
                />
              </Field>
              <Button type="submit" variant="outline" disabled={action.busy || allowText === null}>
                Save allowed ranges
              </Button>
            </form>
          </SettingsSection>
          <SettingsSection
            title="Cut off probing sessions"
            hint="A session refused again and again is more likely someone on the agent's machine than an agent at work."
          >
            <div className="flex items-start justify-between gap-4">
              <div className="space-y-1">
                <Label htmlFor="quarantine">Cut off a session that keeps being refused</Label>
                <p className="text-sm text-muted-foreground">
                  The proxy stops serving it at once and it is revoked everywhere. Someone reviews its requests and
                  starts a new session.
                </p>
              </div>
              <Switch
                id="quarantine"
                checked={current.quarantine !== null}
                disabled={action.busy}
                onCheckedChange={(on) => void save({ ...current, quarantine: on ? DEFAULT_QUARANTINE : null })}
              />
            </div>
            {current.quarantine && (
              <div className="pt-2">
                <Label htmlFor="quarantine-threshold" className="sr-only">
                  Cut off after
                </Label>
                <SelectField
                  id="quarantine-threshold"
                  className="w-full sm:w-[260px]"
                  value={quarantineKey(current.quarantine)}
                  onChange={(v) => void save({ ...current, quarantine: parseQuarantineKey(v) })}
                  options={quarantineOptions(current.quarantine)}
                />
              </div>
            )}
          </SettingsSection>
          <SingleSignOnSettings />
          <AuditExportSettings />
        </div>
      )}
    </PageContainer>
  );
}
