// SPDX-FileCopyrightText: 2026 credential-broker contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import { useState, type FormEvent } from "react";
import {
  del,
  get,
  patch,
  post,
  put,
  type ApiKey,
  type AuditEvent,
  type Invite,
  type NodeInfo,
  type Page,
  type Role,
  type Settings as SettingsModel,
  type StoredTemplate,
  type UserSummary,
  type Vault,
} from "../api";
import { useAction, useLoad } from "../hooks";
import { Empty, ErrorBanner, lines, Loading, OneTimeSecret, Pager, Section, Tags, When } from "../components/ui";

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

// ----- templates -------------------------------------------------------------

export function Templates({ isAdmin }: { isAdmin: boolean }) {
  const templates = useLoad(() => get<StoredTemplate[]>("/templates"), []);
  const [yaml, setYaml] = useState("");
  const [reviewing, setReviewing] = useState<StoredTemplate | null>(null);
  const action = useAction();

  const importTemplate = async (e: FormEvent) => {
    e.preventDefault();
    const t = await action.run(() => post<StoredTemplate>("/templates/import", { yaml }));
    if (t) {
      setYaml("");
      setReviewing(t);
      templates.reload();
    }
  };

  const approve = async (t: StoredTemplate) => {
    const ok = await action.run(() => post<StoredTemplate>(`/templates/${t.template.id}/${t.template.version}/approve`));
    if (ok) {
      setReviewing(null);
      templates.reload();
    }
  };

  return (
    <>
      <Section title="Template catalog">
        <p className="muted">
          Templates describe a service: which hosts, paths and methods a credential may ever be used for, and how it is
          injected. They set the maximum scope; credentials and rules can only narrow it.
        </p>
        <ErrorBanner error={templates.error ?? action.error} />
        {templates.loading && !templates.data ? (
          <Loading />
        ) : (
          <div className="cards">
            {templates.data?.map((t) => (
              <article key={`${t.template.id}@${t.template.version}`} className="card">
                <header>
                  <h3>{t.template.name}</h3>
                  <span className={`pill ${t.status === "approved" ? "ok" : "warn"}`}>
                    {t.status === "approved" ? "approved" : "pending approval"}
                  </span>
                </header>
                <p className="muted small">
                  <code>
                    {t.template.id}@{t.template.version}
                  </code>{" "}
                  · {t.source}
                </p>
                <p>{t.template.description}</p>
                <dl>
                  <dt>Hosts</dt>
                  <dd>{t.template.hosts.length ? <Tags values={t.template.hosts} /> : <span className="muted">set per credential (admin)</span>}</dd>
                  <dt>Paths</dt>
                  <dd>
                    <Tags values={t.template.allow.paths} />
                  </dd>
                  <dt>Methods</dt>
                  <dd>
                    <Tags values={t.template.allow.methods} />
                  </dd>
                  <dt>Injects</dt>
                  <dd>
                    <code>{injectionSummary(t.template)}</code>
                  </dd>
                  {t.template.host_override.allowed && (
                    <>
                      <dt>Override</dt>
                      <dd>Admins may set a custom host{t.template.host_override.required ? " (required)" : ""}</dd>
                    </>
                  )}
                </dl>
                {t.status !== "approved" && isAdmin && (
                  <button type="button" onClick={() => setReviewing(t)}>
                    Review and approve
                  </button>
                )}
              </article>
            ))}
          </div>
        )}
      </Section>
      {reviewing && reviewing.status !== "approved" && (
        <Section title={`Approve "${reviewing.template.name}"?`}>
          <div className="banner warn">
            <p>Approving lets credentials created from this template be injected into requests to:</p>
            {reviewing.template.hosts.length ? (
              <Tags values={reviewing.template.hosts} />
            ) : (
              <p>a host chosen by an admin on each credential.</p>
            )}
            <p>
              Paths <Tags values={reviewing.template.allow.paths} /> · methods <Tags values={reviewing.template.allow.methods} /> ·
              header <code>{injectionSummary(reviewing.template)}</code>
            </p>
          </div>
          <pre className="yaml">{reviewing.yaml}</pre>
          <div className="actions">
            <button type="button" className="secondary" onClick={() => setReviewing(null)}>
              Not now
            </button>
            {isAdmin && (
              <button type="button" disabled={action.busy} onClick={() => void approve(reviewing)}>
                Approve host binding
              </button>
            )}
          </div>
        </Section>
      )}
      {isAdmin && (
        <Section title="Import a template">
          <form className="form" onSubmit={importTemplate}>
            <label>
              Template YAML
              <textarea rows={12} className="mono" value={yaml} onChange={(e) => setYaml(e.target.value)} required spellCheck={false} />
            </label>
            <button type="submit" disabled={action.busy}>
              Import (requires approval)
            </button>
          </form>
        </Section>
      )}
    </>
  );
}

// ----- API keys ----------------------------------------------------------------

const KEY_ROLES: Role[] = ["session_issuer", "viewer", "editor"];

export function ApiKeys() {
  const [page, setPage] = useState(1);
  const keys = useLoad(() => get<Page<ApiKey>>(`/api-keys?page=${page}`), [page]);
  const vaults = useLoad(() => get<Page<Vault>>("/vaults?page_size=100"), []);
  const [form, setForm] = useState({ name: "", vault_id: "", role: "session_issuer" as Role, expires_in_days: 30 });
  const [created, setCreated] = useState<string | null>(null);
  const action = useAction();
  const vaultName = (id: string) => vaults.data?.items.find((v) => v.id === id)?.name ?? id;

  const create = async (e: FormEvent) => {
    e.preventDefault();
    const result = await action.run(() => post<{ api_key: string; key: ApiKey }>("/api-keys", form));
    if (result) {
      setCreated(result.api_key);
      keys.reload();
    }
  };

  const revoke = async (k: ApiKey) => {
    if (!window.confirm(`Revoke API key "${k.name}"?`)) return;
    await action.run(() => del(`/api-keys/${k.id}`));
    keys.reload();
  };

  return (
    <>
      <Section title="Create an API key">
        <p className="muted">Keys belong to exactly one vault and role, and expire. Only a hash is stored.</p>
        {created && <OneTimeSecret label="API key" value={created} hint={<code className="block">Authorization: Bearer {created.slice(0, 16)}…</code>} />}
        <form className="form" onSubmit={create}>
          <ErrorBanner error={action.error} />
          <label>
            Name
            <input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} required />
          </label>
          <label>
            Vault
            <select value={form.vault_id} onChange={(e) => setForm({ ...form, vault_id: e.target.value })} required>
              <option value="">Choose…</option>
              {vaults.data?.items.map((v) => (
                <option key={v.id} value={v.id}>
                  {v.name}
                </option>
              ))}
            </select>
          </label>
          <div className="choice-cards">
            {KEY_ROLES.map((r) => (
              <label key={r} className={`choice ${form.role === r ? "selected" : ""}`}>
                <input type="radio" name="role" value={r} checked={form.role === r} onChange={() => setForm({ ...form, role: r })} />
                <strong>{r.replace("_", " ")}</strong>
                <span className="muted small">
                  {r === "session_issuer" ? "Mint proxy sessions only" : r === "viewer" ? "Read the vault" : "Manage rules and sessions"}
                </span>
              </label>
            ))}
          </div>
          <label>
            Expires in (days)
            <input type="number" min={1} max={365} value={form.expires_in_days} onChange={(e) => setForm({ ...form, expires_in_days: Number(e.target.value) })} />
          </label>
          <button type="submit" disabled={action.busy}>
            Create API key
          </button>
        </form>
      </Section>
      <Section title="API keys">
        <ErrorBanner error={keys.error} />
        {keys.loading && !keys.data ? (
          <Loading />
        ) : keys.data?.items.length === 0 ? (
          <Empty>No API keys.</Empty>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Prefix</th>
                <th>Vault</th>
                <th>Role</th>
                <th>Expires</th>
                <th>Last used</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {keys.data?.items.map((k) => (
                <tr key={k.id}>
                  <td>{k.name}</td>
                  <td>
                    <code>{k.prefix}</code>
                  </td>
                  <td>{vaultName(k.vault_id)}</td>
                  <td>{k.role}</td>
                  <td>
                    <When at={k.expires_at} />
                  </td>
                  <td>
                    <When at={k.last_used_at} />
                  </td>
                  <td className="row-actions">
                    {k.revoked_at ? (
                      <span className="pill bad">revoked</span>
                    ) : (
                      <button type="button" className="danger" onClick={() => void revoke(k)}>
                        Revoke
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        <Pager page={keys.data} onPage={setPage} />
      </Section>
    </>
  );
}

// ----- nodes -------------------------------------------------------------------

export function Nodes() {
  const [page, setPage] = useState(1);
  const nodes = useLoad(() => get<Page<NodeInfo>>(`/nodes?page=${page}`), [page]);
  const [joinToken, setJoinToken] = useState<string | null>(null);
  const action = useAction();

  const createToken = async () => {
    const r = await action.run(() => post<{ token: string; expires_at: string }>("/nodes/join-tokens", {}));
    if (r) setJoinToken(r.token);
  };

  const revoke = async (n: NodeInfo) => {
    if (!window.confirm(`Revoke node "${n.name}"? It stops receiving policy and fails closed when its lease lapses.`)) return;
    await action.run(() => post<void>(`/nodes/${n.id}/revoke`));
    nodes.reload();
  };

  return (
    <Section
      title="Data plane nodes"
      actions={
        <button type="button" onClick={() => void createToken()} disabled={action.busy}>
          Create join token
        </button>
      }
    >
      <ErrorBanner error={nodes.error ?? action.error} />
      {joinToken && (
        <OneTimeSecret
          label="Join token (single use)"
          value={joinToken}
          hint={<code className="block">credential-broker node join --control-url https://&lt;this-host&gt;:8443 --token {joinToken.slice(0, 12)}…</code>}
        />
      )}
      {nodes.loading && !nodes.data ? (
        <Loading />
      ) : nodes.data?.items.length === 0 ? (
        <Empty>No nodes enrolled. Create a join token and run `credential-broker node join` on the data plane host.</Empty>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Node</th>
              <th>Certificate until</th>
              <th>Last seen</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {nodes.data?.items.map((n) => (
              <tr key={n.id}>
                <td>{n.name}</td>
                <td>
                  <code>{n.id.slice(0, 8)}</code>
                </td>
                <td>
                  <When at={n.cert_not_after} />
                </td>
                <td>
                  <When at={n.last_seen_at} />
                </td>
                <td className="row-actions">
                  {n.revoked_at ? (
                    <span className="pill bad">revoked</span>
                  ) : (
                    <button type="button" className="danger" onClick={() => void revoke(n)}>
                      Revoke
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <Pager page={nodes.data} onPage={setPage} />
    </Section>
  );
}

// ----- audit -------------------------------------------------------------------

export function Audit() {
  const [page, setPage] = useState(1);
  const [prefix, setPrefix] = useState("");
  const [applied, setApplied] = useState("");
  const events = useLoad(
    () => get<Page<AuditEvent>>(`/audit?page=${page}&page_size=50&action_prefix=${encodeURIComponent(applied)}`),
    [page, applied],
  );
  return (
    <Section title="Audit log">
      <form
        className="inline-form"
        onSubmit={(e) => {
          e.preventDefault();
          setPage(1);
          setApplied(prefix);
        }}
      >
        <input placeholder="Action prefix, e.g. proxy. or credential." value={prefix} onChange={(e) => setPrefix(e.target.value)} />
        <button type="submit">Filter</button>
      </form>
      <ErrorBanner error={events.error} />
      {events.loading && !events.data ? (
        <Loading rows={6} />
      ) : events.data?.items.length === 0 ? (
        <Empty>No matching events.</Empty>
      ) : (
        <table className="audit">
          <thead>
            <tr>
              <th>When</th>
              <th>Actor</th>
              <th>Action</th>
              <th>Outcome</th>
              <th>Target</th>
              <th>Detail</th>
            </tr>
          </thead>
          <tbody>
            {events.data?.items.map((e) => (
              <tr key={e.id}>
                <td>
                  <When at={e.at} />
                </td>
                <td>
                  <code>{e.actor}</code>
                </td>
                <td>
                  <code>{e.action}</code>
                </td>
                <td>
                  <span className={`pill ${e.outcome === "success" ? "ok" : "bad"}`}>{e.outcome}</span>
                </td>
                <td>{e.target && <code>{e.target}</code>}</td>
                <td>
                  <Tags values={Object.entries(e.detail).map(([k, v]) => `${k}=${v}`)} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <Pager page={events.data} onPage={setPage} />
    </Section>
  );
}

// ----- settings ----------------------------------------------------------------

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
  if (!current) {
    return (
      <Section title="Settings">
        <ErrorBanner error={settings.error} />
        <Loading />
      </Section>
    );
  }
  const allowValue = allowText ?? current.egress.allow.join("\n");
  return (
    <>
      <Section title="Hosts without a rule">
        <ErrorBanner error={settings.error ?? action.error} />
        <div className="choice-cards">
          <button
            type="button"
            className={`choice ${current.unmatched_host_policy === "passthrough" ? "selected" : ""}`}
            onClick={() => void save({ ...current, unmatched_host_policy: "passthrough" })}
          >
            <strong>Tunnel untouched</strong>
            <span className="muted small">Agents can reach other HTTPS hosts; nothing is injected or decrypted.</span>
          </button>
          <button
            type="button"
            className={`choice ${current.unmatched_host_policy === "deny" ? "selected" : ""}`}
            onClick={() => void save({ ...current, unmatched_host_policy: "deny" })}
          >
            <strong>Deny</strong>
            <span className="muted small">Only hosts covered by one of the session's rules are reachable.</span>
          </button>
        </div>
      </Section>
      <Section title="Egress to private addresses">
        <p className="muted">
          Applies to tunnels opened for hosts without a rule and to credential tests. Hosts covered by a rule are
          always reachable, because an admin chose them.
        </p>
        <label className="check">
          <input
            type="checkbox"
            checked={current.egress.block_private}
            onChange={(e) => void save({ ...current, egress: { ...current.egress, block_private: e.target.checked } })}
          />
          Block loopback, private (RFC 1918), link-local / cloud metadata and other non-public addresses
        </label>
        <form
          className="form"
          onSubmit={(e) => {
            e.preventDefault();
            void save({ ...current, egress: { ...current.egress, allow: lines(allowValue) } });
          }}
        >
          <label>
            Allowed ranges (CIDR, one per line)
            <textarea
              rows={4}
              className="mono"
              value={allowValue}
              onChange={(e) => setAllowText(e.target.value)}
              placeholder={"10.20.0.0/16\nfd00:1234::/32"}
            />
          </label>
          <button type="submit" disabled={action.busy}>
            Save allowed ranges
          </button>
        </form>
      </Section>
    </>
  );
}

const PERSON_ROLES: { role: Role; summary: string }[] = [
  { role: "viewer", summary: "Read vaults, rules, sessions and the audit log" },
  { role: "editor", summary: "Also manage rules and mint or revoke sessions" },
  { role: "admin", summary: "Full control, including credentials and people" },
];

function inviteStatus(i: Invite): { label: string; tone: string } {
  if (i.accepted_at) return { label: "accepted", tone: "ok" };
  if (i.revoked_at) return { label: "revoked", tone: "bad" };
  if (new Date(i.expires_at) <= new Date()) return { label: "expired", tone: "bad" };
  return { label: "pending", tone: "" };
}

/** People: invite with a role, change roles, disable accounts. */
export function People({ me }: { me: UserSummary }) {
  const isAdmin = me.role === "admin";
  const [userPage, setUserPage] = useState(1);
  const [invitePage, setInvitePage] = useState(1);
  const users = useLoad(
    () => (isAdmin ? get<Page<UserSummary>>(`/users?page=${userPage}`) : Promise.resolve(undefined)),
    [isAdmin, userPage],
  );
  const invites = useLoad(
    () => (isAdmin ? get<Page<Invite>>(`/invites?page=${invitePage}`) : Promise.resolve(undefined)),
    [isAdmin, invitePage],
  );
  const [form, setForm] = useState({ role: "editor" as Role, expires_in_hours: 72 });
  const [link, setLink] = useState<string | null>(null);
  const action = useAction();

  if (!isAdmin) {
    return (
      <Section title="People">
        <div className="banner info">
          Only admins can invite people or change their roles. You are signed in as <strong>{me.username}</strong> with
          the <strong>{me.role}</strong> role; ask an admin if you need more access.
        </div>
      </Section>
    );
  }

  const invite = async (e: FormEvent) => {
    e.preventDefault();
    const result = await action.run(() => post<{ token: string; invite: Invite }>("/invites", form));
    if (result) {
      setLink(`${window.location.origin}${window.location.pathname}#/invite/${result.token}`);
      invites.reload();
    }
  };

  const update = async (u: UserSummary, change: { role?: Role; disabled?: boolean }, question: string) => {
    if (!window.confirm(question)) return;
    await action.run(() => patch<UserSummary>(`/users/${u.id}`, change));
    users.reload();
  };

  const revoke = async (i: Invite) => {
    if (!window.confirm(`Revoke the pending ${i.role} invite?`)) return;
    await action.run(() => del(`/invites/${i.id}`));
    invites.reload();
  };

  return (
    <>
      <Section title="Invite someone">
        <p className="muted">
          Send the link to the person you are inviting. They choose a username and password and enrol an authenticator.
          The link works once.
        </p>
        {link && (
          <OneTimeSecret
            label="Invite link"
            value={link}
            hint="Shown once. Anyone holding it can create the account until it is accepted, revoked or expires."
          />
        )}
        <form className="form" onSubmit={invite}>
          <ErrorBanner error={action.error} />
          <div className="choice-cards">
            {PERSON_ROLES.map(({ role, summary }) => (
              <label key={role} className={`choice ${form.role === role ? "selected" : ""}`}>
                <input type="radio" name="invite-role" value={role} checked={form.role === role} onChange={() => setForm({ ...form, role })} />
                <strong>{role}</strong>
                <span className="muted small">{summary}</span>
              </label>
            ))}
          </div>
          <label>
            Link expires in (hours, at most 168)
            <input
              type="number"
              min={1}
              max={168}
              value={form.expires_in_hours}
              onChange={(e) => setForm({ ...form, expires_in_hours: Number(e.target.value) })}
            />
          </label>
          <button type="submit" disabled={action.busy}>
            Create invite link
          </button>
        </form>
      </Section>
      <Section title="People">
        <ErrorBanner error={users.error} />
        {users.loading && !users.data ? (
          <Loading />
        ) : (
          <table>
            <thead>
              <tr>
                <th>Username</th>
                <th>Role</th>
                <th>Since</th>
                <th>Status</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {users.data?.items.map((u) => (
                <tr key={u.id}>
                  <td>
                    {u.username} {u.id === me.id && <span className="muted">(you)</span>}
                  </td>
                  <td>
                    <select
                      aria-label={`Role for ${u.username}`}
                      value={u.role}
                      disabled={action.busy}
                      onChange={(e) => void update(u, { role: e.target.value as Role }, `Make ${u.username} ${e.target.value}?`)}
                    >
                      {PERSON_ROLES.map(({ role }) => (
                        <option key={role} value={role}>
                          {role}
                        </option>
                      ))}
                    </select>
                  </td>
                  <td>
                    <When at={u.created_at} />
                  </td>
                  <td>{u.disabled_at ? <span className="pill bad">disabled</span> : <span className="pill ok">active</span>}</td>
                  <td className="row-actions">
                    {u.disabled_at ? (
                      <button type="button" className="secondary" onClick={() => void update(u, { disabled: false }, `Re-enable ${u.username}?`)}>
                        Enable
                      </button>
                    ) : (
                      u.id !== me.id && (
                        <button
                          type="button"
                          className="danger"
                          onClick={() => void update(u, { disabled: true }, `Disable ${u.username}? They are signed out immediately.`)}
                        >
                          Disable
                        </button>
                      )
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        <Pager page={users.data} onPage={setUserPage} />
      </Section>
      <Section title="Invites">
        <ErrorBanner error={invites.error} />
        {invites.loading && !invites.data ? (
          <Loading />
        ) : invites.data?.items.length === 0 ? (
          <Empty>No invites yet. Create one above to add a person.</Empty>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Role</th>
                <th>Created by</th>
                <th>Expires</th>
                <th>Status</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {invites.data?.items.map((i) => {
                const status = inviteStatus(i);
                return (
                  <tr key={i.id}>
                    <td>{i.role}</td>
                    <td>
                      <code>{i.created_by}</code>
                    </td>
                    <td>
                      <When at={i.expires_at} />
                    </td>
                    <td>
                      <span className={`pill ${status.tone}`}>{status.label}</span>
                    </td>
                    <td className="row-actions">
                      {status.label === "pending" && (
                        <button type="button" className="danger" onClick={() => void revoke(i)}>
                          Revoke
                        </button>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
        <Pager page={invites.data} onPage={setInvitePage} />
      </Section>
    </>
  );
}
