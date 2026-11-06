// SPDX-FileCopyrightText: 2026 credential-broker contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import { useState } from "react";
import { get, put, type Settings as SettingsModel } from "../api";
import { useAction, useLoad } from "../hooks";
import { ChoiceCards, ErrorBanner, Field, lines, Panel, Section } from "../components/common";
import { Button } from "../components/ui/button-components";
import { Label } from "../components/ui/label";
import { PageContainer, PageHeader } from "../components/ui/page-header";
import { Skeleton } from "../components/ui/skeleton";
import { Switch } from "../components/ui/switch";
import { Textarea } from "../components/ui/textarea";

type Unmatched = SettingsModel["unmatched_host_policy"];

export function Settings() {
  const settings = useLoad(() => get<SettingsModel>("/settings"), []);
  const action = useAction();
  const [allowText, setAllowText] = useState<string | null>(null);
  const current = settings.data;

  const save = async (next: SettingsModel) => {
    const saved = await action.run(() => put<SettingsModel>("/settings", next));
    if (saved) {
      setAllowText(null);
      settings.reload();
    }
  };

  return (
    <PageContainer>
      <PageHeader
        title="Settings"
        description="Instance-wide proxy behaviour. Changes reach every proxy at its next policy refresh."
      />
      <ErrorBanner error={settings.error ?? action.error} />
      {!current ? (
        <div className="space-y-6">
          <Skeleton className="h-32 w-full rounded-lg" />
          <Skeleton className="h-48 w-full rounded-lg" />
        </div>
      ) : (
        <>
          <Section
            title="Hosts without a rule"
            description="What a proxy session does when an agent connects to a host none of its rules cover."
          >
            <ChoiceCards<Unmatched>
              name="unmatched"
              value={current.unmatched_host_policy}
              onChange={(v) => void save({ ...current, unmatched_host_policy: v })}
              choices={[
                {
                  value: "passthrough",
                  title: "Tunnel untouched",
                  description: "Agents can reach other HTTPS hosts; nothing is injected or decrypted.",
                },
                {
                  value: "deny",
                  title: "Deny",
                  description: "Only hosts covered by one of the session's rules are reachable.",
                },
              ]}
            />
          </Section>
          <Section
            title="Egress to private addresses"
            description="Applies to tunnels opened for hosts without a rule and to credential tests. Hosts covered by a rule are always reachable, because an admin chose them."
          >
            <Panel className="divide-y">
              <div className="flex items-start justify-between gap-4 p-4">
                <div className="space-y-1">
                  <Label htmlFor="block-private">Block non-public addresses</Label>
                  <p className="text-sm text-muted-foreground">
                    Loopback, private (RFC 1918), link-local / cloud metadata and other non-public ranges.
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
                className="space-y-4 p-4"
                onSubmit={(e) => {
                  e.preventDefault();
                  void save({ ...current, egress: { ...current.egress, allow: lines(allowText ?? "") } });
                }}
              >
                <Field
                  label="Allowed ranges"
                  htmlFor="egress-allow"
                  hint="CIDR, one per line. These stay reachable even while non-public addresses are blocked."
                >
                  <Textarea
                    id="egress-allow"
                    rows={4}
                    className="font-mono"
                    value={allowText ?? current.egress.allow.join("\n")}
                    onChange={(e) => setAllowText(e.target.value)}
                    placeholder={"10.20.0.0/16\nfd00:1234::/32"}
                  />
                </Field>
                <div className="flex justify-end">
                  <Button type="submit" disabled={action.busy || allowText === null}>
                    Save allowed ranges
                  </Button>
                </div>
              </form>
            </Panel>
          </Section>
        </>
      )}
    </PageContainer>
  );
}
