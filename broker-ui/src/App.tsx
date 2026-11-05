// SPDX-FileCopyrightText: 2026 credential-broker contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import { useCallback, useEffect, useRef, useState } from "react";
import { ApiError, get, post, setCsrfToken, setStepUpHandler, type SessionInfo } from "./api";
import { useHashRoute } from "./hooks";
import { ErrorBanner, Loading } from "./components/ui";
import { Login, Setup, StepUpDialog } from "./pages/Auth";
import { Vaults } from "./pages/Vaults";
import { VaultDetail } from "./pages/VaultDetail";
import { ApiKeys, Audit, Nodes, Settings, Templates } from "./pages/Admin";

type Boot = { state: "loading" } | { state: "setup" } | { state: "login" } | { state: "ready"; session: SessionInfo } | { state: "error"; message: string };

const NAV = [
  ["vaults", "Vaults"],
  ["templates", "Templates"],
  ["api-keys", "API keys"],
  ["nodes", "Nodes"],
  ["audit", "Audit log"],
  ["settings", "Settings"],
] as const;

export function App() {
  const [boot, setBoot] = useState<Boot>({ state: "loading" });
  const [stepUpOpen, setStepUpOpen] = useState(false);
  const pending = useRef<((ok: boolean) => void) | null>(null);
  const route = useHashRoute();

  const load = useCallback(async () => {
    try {
      const status = await get<{ setup_required: boolean }>("/setup/status");
      if (status.setup_required) {
        setBoot({ state: "setup" });
        return;
      }
      const session = await get<SessionInfo>("/auth/me");
      setCsrfToken(session.csrf_token);
      setBoot({ state: "ready", session });
    } catch (e) {
      if (e instanceof ApiError && e.problem.status === 401) setBoot({ state: "login" });
      else setBoot({ state: "error", message: e instanceof Error ? e.message : String(e) });
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  useEffect(() => {
    setStepUpHandler(
      () =>
        new Promise<boolean>((resolve) => {
          pending.current = resolve;
          setStepUpOpen(true);
        }),
    );
    return () => setStepUpHandler(null);
  }, []);

  const finishStepUp = (ok: boolean) => {
    setStepUpOpen(false);
    pending.current?.(ok);
    pending.current = null;
  };

  const logout = async () => {
    try {
      await post<void>("/auth/logout");
    } finally {
      setCsrfToken(null);
      setBoot({ state: "login" });
    }
  };

  if (boot.state === "loading") return <main className="auth"><Loading /></main>;
  if (boot.state === "error") return <main className="auth"><ErrorBanner error={boot.message} /></main>;
  if (boot.state === "setup") return <main><Setup onDone={() => setBoot({ state: "login" })} /></main>;
  if (boot.state === "login")
    return (
      <main>
        <Login
          onLogin={(session) => {
            setCsrfToken(session.csrf_token);
            setBoot({ state: "ready", session });
          }}
        />
      </main>
    );

  const { user } = boot.session;
  const [section = "vaults", id, tab] = route;
  const isAdmin = user.role === "admin";

  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand">Credential Broker</div>
        <nav>
          {NAV.map(([key, label]) => (
            <a key={key} href={`#/${key}`} className={section === key ? "active" : ""}>
              {label}
            </a>
          ))}
        </nav>
        <div className="whoami">
          <span>
            {user.username} <span className="muted">({user.role})</span>
          </span>
          <button type="button" className="secondary" onClick={() => void logout()}>
            Sign out
          </button>
        </div>
      </aside>
      <main className="content">
        {section === "vaults" && !id && <Vaults canCreate={isAdmin} />}
        {section === "vaults" && id && (
          <VaultDetail vaultId={id} tab={tab === "rules" || tab === "sessions" ? tab : "credentials"} user={user} />
        )}
        {section === "templates" && <Templates isAdmin={isAdmin} />}
        {section === "api-keys" && <ApiKeys />}
        {section === "nodes" && <Nodes />}
        {section === "audit" && <Audit />}
        {section === "settings" && <Settings />}
      </main>
      <StepUpDialog open={stepUpOpen} onResult={finishStepUp} />
    </div>
  );
}
