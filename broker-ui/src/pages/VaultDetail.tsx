// SPDX-FileCopyrightText: 2026 credential-broker contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import { useMemo, useState, type FormEvent } from "react";
import {
  del,
  get,
  patch,
  post,
  put,
  type CredentialMeta,
  type Page,
  type ProxySession,
  type Rule,
  type StoredTemplate,
  type UserSummary,
  type Vault,
} from "../api";
import { useAction, useLoad } from "../hooks";
import { Empty, ErrorBanner, lines, Loading, OneTimeSecret, Pager, Section, Tags, When } from "../components/ui";

type Tab = "credentials" | "rules" | "sessions";

export function VaultDetail({ vaultId, tab, user }: { vaultId: string; tab: Tab; user: UserSummary }) {
  const vault = useLoad(() => get<Vault>(`/vaults/${vaultId}`), [vaultId]);
  return (
    <div>
      <nav className="breadcrumbs">
        <a href="#/vaults">Vaults</a> / <strong>{vault.data?.name ?? "…"}</strong>
      </nav>
      <ErrorBanner error={vault.error} />
      <nav className="tabs">
        {(["credentials", "rules", "sessions"] as Tab[]).map((t) => (
          <a key={t} href={`#/vaults/${vaultId}/${t}`} className={t === tab ? "active" : ""}>
            {t[0]?.toUpperCase()}
            {t.slice(1)}
          </a>
        ))}
      </nav>
      {tab === "credentials" && <Credentials vaultId={vaultId} user={user} />}
      {tab === "rules" && <Rules vaultId={vaultId} />}
      {tab === "sessions" && <Sessions vaultId={vaultId} />}
    </div>
  );
}

// ----- credentials -----------------------------------------------------------

function Credentials({ vaultId, user }: { vaultId: string; user: UserSummary }) {
  const [page, setPage] = useState(1);
  const creds = useLoad(() => get<Page<CredentialMeta>>(`/vaults/${vaultId}/credentials?page=${page}`), [vaultId, page]);
  const templates = useLoad(() => get<StoredTemplate[]>("/templates"), []);
  const approved = useMemo(
    () => (templates.data ?? []).filter((t) => t.status === "approved"),
    [templates.data],
  );
  const [rotating, setRotating] = useState<CredentialMeta | null>(null);
  const action = useAction();

  const remove = async (c: CredentialMeta) => {
    if (!window.confirm(`Delete credential "${c.name}"? Rules using it must be deleted first.`)) return;
    await action.run(() => del(`/credentials/${c.id}`));
    creds.reload();
  };

  return (
    <>
      <Section title="Add a credential">
        <p className="muted">
          Secrets are write-only: once saved, nobody (admins included) can read them back. They are only ever
          delivered, encrypted, to enrolled data plane nodes.
        </p>
        <CredentialForm
          templates={approved}
          isAdmin={user.role === "admin"}
          onSubmit={(body) => post<CredentialMeta>(`/vaults/${vaultId}/credentials`, body)}
          onSaved={creds.reload}
        />
      </Section>
      {rotating && (
        <Section title={`Replace secret for "${rotating.name}"`}>
          <RotateForm
            credential={rotating}
            template={approved.find((t) => t.template.id === rotating.template_id)}
            onDone={() => {
              setRotating(null);
              creds.reload();
            }}
          />
        </Section>
      )}
      <Section title="Credentials">
        <ErrorBanner error={creds.error ?? action.error} />
        {creds.loading && !creds.data ? (
          <Loading />
        ) : creds.data?.items.length === 0 ? (
          <Empty>No credentials in this vault yet.</Empty>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Template</th>
                <th>Fields</th>
                <th>Host override</th>
                <th>Updated</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {creds.data?.items.map((c) => (
                <tr key={c.id}>
                  <td>{c.name}</td>
                  <td>
                    <code>
                      {c.template_id}@{c.template_version}
                    </code>
                  </td>
                  <td>
                    <Tags values={c.field_names.map((f) => `${f}: ••••••`)} />
                  </td>
                  <td>{c.host_override.length ? <Tags values={c.host_override} /> : <span className="muted">template hosts</span>}</td>
                  <td>
                    <When at={c.updated_at} />
                  </td>
                  <td className="row-actions">
                    <button type="button" className="secondary" onClick={() => setRotating(c)}>
                      Replace secret
                    </button>
                    <button type="button" className="danger" onClick={() => void remove(c)}>
                      Delete
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        <Pager page={creds.data} onPage={setPage} />
      </Section>
    </>
  );
}

interface CredentialBody {
  name: string;
  template_id: string;
  template_version: number;
  host_override: string[];
  fields: Record<string, string>;
}

function CredentialForm({
  templates,
  isAdmin,
  onSubmit,
  onSaved,
}: {
  templates: StoredTemplate[];
  isAdmin: boolean;
  onSubmit: (body: CredentialBody) => Promise<CredentialMeta>;
  onSaved: () => void;
}) {
  const [templateKey, setTemplateKey] = useState("");
  const [name, setName] = useState("");
  const [hostOverride, setHostOverride] = useState("");
  const [fields, setFields] = useState<Record<string, string>>({});
  const action = useAction();
  const selected = templates.find((t) => `${t.template.id}@${t.template.version}` === templateKey)?.template;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!selected) return;
    const saved = await action.run(() =>
      onSubmit({
        name,
        template_id: selected.id,
        template_version: selected.version,
        host_override: lines(hostOverride),
        fields,
      }),
    );
    // Clear secret values from memory as soon as they are saved.
    setFields({});
    if (saved) {
      setName("");
      setHostOverride("");
      onSaved();
    }
  };

  return (
    <form className="form" onSubmit={submit} autoComplete="off">
      <ErrorBanner error={action.error} />
      <label>
        Template
        <select value={templateKey} onChange={(e) => setTemplateKey(e.target.value)} required>
          <option value="">Choose a service…</option>
          {templates.map((t) => (
            <option key={`${t.template.id}@${t.template.version}`} value={`${t.template.id}@${t.template.version}`}>
              {t.template.name} (v{t.template.version})
            </option>
          ))}
        </select>
      </label>
      {selected && (
        <>
          <p className="muted small">
            {selected.description} Hosts: {selected.hosts.length ? <Tags values={selected.hosts} /> : "chosen below"}
          </p>
          <label>
            Name
            <input value={name} onChange={(e) => setName(e.target.value)} required />
          </label>
          {selected.credential_fields.map((f) => (
            <label key={f.name}>
              {f.label}
              {!f.required && <span className="muted"> (optional)</span>}
              <input
                type="password"
                autoComplete="new-password"
                spellCheck={false}
                value={fields[f.name] ?? ""}
                onChange={(e) => setFields({ ...fields, [f.name]: e.target.value })}
                required={f.required}
              />
              {f.description && <span className="muted small">{f.description}</span>}
            </label>
          ))}
          {selected.host_override.allowed && (
            <fieldset className="admin-only">
              <legend>Admin only: host override {selected.host_override.required ? "(required)" : "(optional)"}</legend>
              <p className="muted small">
                Replaces the template's hosts (for example a self-hosted base URL). This widens the template's scope,
                so it needs an admin and is recorded in the audit log.
              </p>
              <label>
                {selected.host_override.label ?? "Base URL"}
                <input
                  placeholder="https://api.internal.example:8443"
                  value={hostOverride}
                  onChange={(e) => setHostOverride(e.target.value)}
                  disabled={!isAdmin}
                  required={selected.host_override.required && isAdmin}
                />
              </label>
              {!isAdmin && <p className="muted small">Ask an admin to create this credential.</p>}
            </fieldset>
          )}
          <button type="submit" disabled={action.busy || (selected.host_override.required && !isAdmin)}>
            Save credential
          </button>
        </>
      )}
    </form>
  );
}

function RotateForm({
  credential,
  template,
  onDone,
}: {
  credential: CredentialMeta;
  template: StoredTemplate | undefined;
  onDone: () => void;
}) {
  const [fields, setFields] = useState<Record<string, string>>({});
  const action = useAction();
  const names = template?.template.credential_fields ?? credential.field_names.map((n) => ({ name: n, label: n, required: true, description: "" }));
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const ok = await action.run(() => put<CredentialMeta>(`/credentials/${credential.id}/secret`, { fields }));
    setFields({});
    if (ok) onDone();
  };
  return (
    <form className="form" onSubmit={submit} autoComplete="off">
      <ErrorBanner error={action.error} />
      {names.map((f) => (
        <label key={f.name}>
          New {f.label}
          <input
            type="password"
            autoComplete="new-password"
            value={fields[f.name] ?? ""}
            onChange={(e) => setFields({ ...fields, [f.name]: e.target.value })}
            required={f.required}
          />
        </label>
      ))}
      <div className="actions">
        <button type="button" className="secondary" onClick={onDone}>
          Cancel
        </button>
        <button type="submit" disabled={action.busy}>
          Replace secret
        </button>
      </div>
    </form>
  );
}

// ----- rules ---------------------------------------------------------------

function Rules({ vaultId }: { vaultId: string }) {
  const [page, setPage] = useState(1);
  const rules = useLoad(() => get<Page<Rule>>(`/vaults/${vaultId}/rules?page=${page}`), [vaultId, page]);
  const creds = useLoad(() => get<Page<CredentialMeta>>(`/vaults/${vaultId}/credentials?page_size=100`), [vaultId]);
  const [form, setForm] = useState({ name: "", credential_id: "", hosts: "", paths: "", methods: "" });
  const action = useAction();
  const credName = (id: string) => creds.data?.items.find((c) => c.id === id)?.name ?? id;

  const create = async (e: FormEvent) => {
    e.preventDefault();
    const opt = (v: string) => (lines(v).length ? lines(v) : undefined);
    const created = await action.run(() =>
      post<Rule>(`/vaults/${vaultId}/rules`, {
        name: form.name,
        credential_id: form.credential_id,
        hosts: opt(form.hosts),
        paths: opt(form.paths),
        methods: opt(form.methods),
      }),
    );
    if (created) {
      setForm({ name: "", credential_id: "", hosts: "", paths: "", methods: "" });
      rules.reload();
    }
  };

  const toggle = async (r: Rule) => {
    await action.run(() => patch<Rule>(`/rules/${r.id}`, { enabled: !r.enabled }));
    rules.reload();
  };

  const remove = async (r: Rule) => {
    if (!window.confirm(`Delete rule "${r.name}"?`)) return;
    await action.run(() => del(`/rules/${r.id}`));
    rules.reload();
  };

  return (
    <>
      <Section title="Add a rule">
        <p className="muted">
          A rule lets a credential be injected for matching requests. Leave hosts, paths and methods empty to use the
          template's maximum scope; anything you enter can only narrow it.
        </p>
        <form className="form" onSubmit={create}>
          <ErrorBanner error={action.error} />
          <label>
            Name
            <input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} required />
          </label>
          <label>
            Credential
            <select value={form.credential_id} onChange={(e) => setForm({ ...form, credential_id: e.target.value })} required>
              <option value="">Choose…</option>
              {creds.data?.items.map((c) => (
                <option key={c.id} value={c.id}>
                  {c.name} ({c.template_id})
                </option>
              ))}
            </select>
          </label>
          <label>
            Hosts (optional, one per line)
            <textarea rows={2} value={form.hosts} onChange={(e) => setForm({ ...form, hosts: e.target.value })} placeholder="api.example.com" />
          </label>
          <label>
            Paths (optional)
            <textarea rows={2} value={form.paths} onChange={(e) => setForm({ ...form, paths: e.target.value })} placeholder="/v1/*" />
          </label>
          <label>
            Methods (optional)
            <input value={form.methods} onChange={(e) => setForm({ ...form, methods: e.target.value })} placeholder="GET, POST" />
          </label>
          <button type="submit" disabled={action.busy}>
            Create rule
          </button>
        </form>
      </Section>
      <Section title="Rules">
        <ErrorBanner error={rules.error} />
        {rules.loading && !rules.data ? (
          <Loading />
        ) : rules.data?.items.length === 0 ? (
          <Empty>No rules yet. Without a rule, a credential is never injected.</Empty>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Credential</th>
                <th>Hosts</th>
                <th>Paths</th>
                <th>Methods</th>
                <th>Status</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {rules.data?.items.map((r) => (
                <tr key={r.id}>
                  <td>{r.name}</td>
                  <td>{credName(r.credential_id)}</td>
                  <td>
                    <Tags values={r.allow.hosts} />
                  </td>
                  <td>
                    <Tags values={r.allow.paths} />
                  </td>
                  <td>
                    <Tags values={r.allow.methods} />
                  </td>
                  <td>{r.enabled ? <span className="pill ok">enabled</span> : <span className="pill">disabled</span>}</td>
                  <td className="row-actions">
                    <button type="button" className="secondary" onClick={() => void toggle(r)}>
                      {r.enabled ? "Disable" : "Enable"}
                    </button>
                    <button type="button" className="danger" onClick={() => void remove(r)}>
                      Delete
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        <Pager page={rules.data} onPage={setPage} />
      </Section>
    </>
  );
}

// ----- sessions ------------------------------------------------------------

interface Minted {
  token: string;
  session: ProxySession;
}

function Sessions({ vaultId }: { vaultId: string }) {
  const [page, setPage] = useState(1);
  const sessions = useLoad(() => get<Page<ProxySession>>(`/vaults/${vaultId}/sessions?page=${page}`), [vaultId, page]);
  const rules = useLoad(() => get<Page<Rule>>(`/vaults/${vaultId}/rules?page_size=100`), [vaultId]);
  const [selected, setSelected] = useState<string[]>([]);
  const [ttlMinutes, setTtlMinutes] = useState(15);
  const [limit, setLimit] = useState("");
  const [labels, setLabels] = useState("");
  const [minted, setMinted] = useState<Minted | null>(null);
  const action = useAction();

  const mint = async (e: FormEvent) => {
    e.preventDefault();
    const labelMap: Record<string, string> = {};
    for (const line of lines(labels)) {
      const [k, ...rest] = line.split("=");
      if (k) labelMap[k.trim()] = rest.join("=").trim();
    }
    const result = await action.run(() =>
      post<Minted>(`/vaults/${vaultId}/sessions`, {
        rule_ids: selected,
        ttl_secs: ttlMinutes * 60,
        request_limit: limit ? Number(limit) : undefined,
        labels: labelMap,
      }),
    );
    if (result) {
      setMinted(result);
      sessions.reload();
    }
  };

  const revoke = async (s: ProxySession) => {
    await action.run(() => post<ProxySession>(`/sessions/${s.id}/revoke`));
    sessions.reload();
  };

  const status = (s: ProxySession) => {
    if (s.revoked_at) return <span className="pill bad">revoked</span>;
    if (new Date(s.expires_at) <= new Date()) return <span className="pill">expired</span>;
    return <span className="pill ok">active</span>;
  };

  return (
    <>
      <Section title="Mint a proxy session">
        <p className="muted">
          A session lets an agent use selected rules through the data plane for a limited time. The agent never sees
          the credentials.
        </p>
        {minted && (
          <OneTimeSecret
            label="Proxy session token"
            value={minted.token}
            hint={
              <>
                <p>Point the agent at the data plane:</p>
                <code className="block">HTTPS_PROXY=http://{minted.token.slice(0, 18)}…@&lt;data-plane-host&gt;:3128</code>
                <p>
                  and trust the <a href="/api/v1/ca/interception.pem">interception CA certificate</a>.
                </p>
              </>
            }
          />
        )}
        <form className="form" onSubmit={mint}>
          <ErrorBanner error={action.error} />
          <fieldset>
            <legend>Rules</legend>
            {rules.data?.items.filter((r) => r.enabled).length === 0 && <p className="muted">No enabled rules in this vault.</p>}
            {rules.data?.items
              .filter((r) => r.enabled)
              .map((r) => (
                <label key={r.id} className="check">
                  <input
                    type="checkbox"
                    checked={selected.includes(r.id)}
                    onChange={(e) =>
                      setSelected(e.target.checked ? [...selected, r.id] : selected.filter((id) => id !== r.id))
                    }
                  />
                  {r.name} <Tags values={r.allow.hosts} />
                </label>
              ))}
          </fieldset>
          <label>
            Lifetime (minutes, max 60)
            <input type="number" min={1} max={60} value={ttlMinutes} onChange={(e) => setTtlMinutes(Number(e.target.value))} />
          </label>
          <label>
            Request limit (optional)
            <input type="number" min={1} value={limit} onChange={(e) => setLimit(e.target.value)} />
          </label>
          <label>
            Audit labels (key=value, one per line)
            <textarea rows={2} value={labels} onChange={(e) => setLabels(e.target.value)} placeholder="agent=build-bot" />
          </label>
          <button type="submit" disabled={action.busy || selected.length === 0}>
            Mint session
          </button>
        </form>
      </Section>
      <Section title="Sessions">
        <ErrorBanner error={sessions.error} />
        {sessions.loading && !sessions.data ? (
          <Loading />
        ) : sessions.data?.items.length === 0 ? (
          <Empty>No sessions yet.</Empty>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Session</th>
                <th>Labels</th>
                <th>Limit</th>
                <th>Created by</th>
                <th>Expires</th>
                <th>Status</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {sessions.data?.items.map((s) => (
                <tr key={s.id}>
                  <td>
                    <code>{s.id.slice(0, 8)}</code>
                  </td>
                  <td>
                    <Tags values={Object.entries(s.labels).map(([k, v]) => `${k}=${v}`)} />
                  </td>
                  <td>{s.request_limit ?? "—"}</td>
                  <td>
                    <code>{s.created_by}</code>
                  </td>
                  <td>
                    <When at={s.expires_at} />
                  </td>
                  <td>{status(s)}</td>
                  <td className="row-actions">
                    {!s.revoked_at && (
                      <button type="button" className="danger" onClick={() => void revoke(s)}>
                        Revoke
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        <Pager page={sessions.data} onPage={setPage} />
      </Section>
    </>
  );
}
