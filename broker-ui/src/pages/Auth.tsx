// SPDX-FileCopyrightText: 2026 credential-broker contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import { useState, type FormEvent } from "react";
import { post, type SessionInfo, type UserSummary } from "../api";
import { useAction } from "../hooks";
import { ErrorBanner } from "../components/ui";

interface TotpEnrollment {
  secret: string;
  otpauth_url: string;
}

/** First-run: create the admin with the one-time setup token from the server log. */
export function Setup({ onDone }: { onDone: () => void }) {
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [setupToken, setSetupToken] = useState("");
  const [code, setCode] = useState("");
  const [enrollment, setEnrollment] = useState<TotpEnrollment | null>(null);
  const action = useAction();

  const begin = async (e: FormEvent) => {
    e.preventDefault();
    const result = await action.run(() => post<TotpEnrollment>("/setup/totp", { username }));
    if (result) setEnrollment(result);
  };

  const finish = async (e: FormEvent) => {
    e.preventDefault();
    if (!enrollment) return;
    const user = await action.run(() =>
      post<UserSummary>("/setup", {
        setup_token: setupToken.trim(),
        username,
        password,
        totp_secret: enrollment.secret,
        totp_code: code.trim(),
      }),
    );
    if (user) onDone();
  };

  return (
    <div className="auth">
      <h1>Create the first admin</h1>
      <p className="muted">
        The server printed a single-use setup token on its terminal when it started. It works once.
      </p>
      <ErrorBanner error={action.error} />
      {!enrollment ? (
        <form onSubmit={begin} className="form">
          <label>
            Username
            <input value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" required />
          </label>
          <button type="submit" disabled={action.busy}>
            Set up two-factor authentication
          </button>
        </form>
      ) : (
        <form onSubmit={finish} className="form">
          <div className="banner info">
            <p>Add this account to your authenticator app, then enter the 6-digit code.</p>
            <code className="secret">{enrollment.secret}</code>
            <p className="muted small">
              <a href={enrollment.otpauth_url}>Open in authenticator</a>
            </p>
          </div>
          <label>
            Setup token
            <input value={setupToken} onChange={(e) => setSetupToken(e.target.value)} autoComplete="off" required />
          </label>
          <label>
            Password (12+ characters)
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="new-password"
              minLength={12}
              required
            />
          </label>
          <label>
            Authenticator code
            <input value={code} onChange={(e) => setCode(e.target.value)} inputMode="numeric" autoComplete="one-time-code" required />
          </label>
          <button type="submit" disabled={action.busy}>
            Create admin
          </button>
        </form>
      )}
    </div>
  );
}

export function Login({ onLogin }: { onLogin: (s: SessionInfo) => void }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const action = useAction();

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const session = await action.run(() =>
      post<SessionInfo>("/auth/login", { username, password, totp_code: code.trim() }),
    );
    if (session) onLogin(session);
  };

  return (
    <div className="auth">
      <h1>Sign in</h1>
      <ErrorBanner error={action.error} />
      <form onSubmit={submit} className="form">
        <label>
          Username
          <input value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" required />
        </label>
        <label>
          Password
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" required />
        </label>
        <label>
          Authenticator code
          <input value={code} onChange={(e) => setCode(e.target.value)} inputMode="numeric" autoComplete="one-time-code" required />
        </label>
        <button type="submit" disabled={action.busy}>
          Sign in
        </button>
      </form>
    </div>
  );
}

/** Asks for a fresh TOTP code before a sensitive action is retried. */
export function StepUpDialog({ open, onResult }: { open: boolean; onResult: (ok: boolean) => void }) {
  const [code, setCode] = useState("");
  const action = useAction();
  if (!open) return null;
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const ok = await action.run(() => post<{ step_up_at: string }>("/auth/step-up", { code: code.trim() }));
    if (ok) {
      setCode("");
      onResult(true);
    }
  };
  return (
    <div className="modal-backdrop" role="dialog" aria-modal="true" aria-labelledby="stepup-title">
      <form className="modal form" onSubmit={submit}>
        <h2 id="stepup-title">Confirm with your second factor</h2>
        <p className="muted">
          Adding credentials, widening rules, managing API keys, templates and nodes needs a code from the last 5 minutes.
        </p>
        <ErrorBanner error={action.error} />
        <label>
          Authenticator code
          <input autoFocus value={code} onChange={(e) => setCode(e.target.value)} inputMode="numeric" autoComplete="one-time-code" required />
        </label>
        <div className="actions">
          <button type="button" className="secondary" onClick={() => onResult(false)}>
            Cancel
          </button>
          <button type="submit" disabled={action.busy}>
            Confirm
          </button>
        </div>
      </form>
    </div>
  );
}
