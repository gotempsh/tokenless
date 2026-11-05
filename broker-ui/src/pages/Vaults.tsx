// SPDX-FileCopyrightText: 2026 credential-broker contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import { useState, type FormEvent } from "react";
import { get, post, type Page, type Vault } from "../api";
import { useAction, useLoad } from "../hooks";
import { Empty, ErrorBanner, Loading, Pager, Section, When } from "../components/ui";

export function Vaults({ canCreate }: { canCreate: boolean }) {
  const [page, setPage] = useState(1);
  const vaults = useLoad(() => get<Page<Vault>>(`/vaults?page=${page}`), [page]);
  const [name, setName] = useState("");
  const action = useAction();

  const create = async (e: FormEvent) => {
    e.preventDefault();
    const v = await action.run(() => post<Vault>("/vaults", { name }));
    if (v) {
      setName("");
      window.location.hash = `#/vaults/${v.id}/credentials`;
    }
  };

  return (
    <Section title="Vaults">
      <p className="muted">
        A vault groups credentials, the rules that let them be injected, and the proxy sessions that may use those rules.
      </p>
      <ErrorBanner error={vaults.error ?? action.error} />
      {canCreate && (
        <form className="inline-form" onSubmit={create}>
          <input placeholder="New vault name" value={name} onChange={(e) => setName(e.target.value)} required />
          <button type="submit" disabled={action.busy}>
            Create vault
          </button>
        </form>
      )}
      {vaults.loading && !vaults.data ? (
        <Loading />
      ) : vaults.data && vaults.data.items.length === 0 ? (
        <Empty>No vaults yet. Create one to start adding credentials.</Empty>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Scope</th>
              <th>Created</th>
            </tr>
          </thead>
          <tbody>
            {vaults.data?.items.map((v) => (
              <tr key={v.id}>
                <td>
                  <a href={`#/vaults/${v.id}/credentials`}>{v.name}</a>
                </td>
                <td>
                  <code>{v.scope}</code>
                </td>
                <td>
                  <When at={v.created_at} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <Pager page={vaults.data} onPage={setPage} />
    </Section>
  );
}
