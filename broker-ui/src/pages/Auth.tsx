// SPDX-FileCopyrightText: 2026 credential-broker contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import { useState, type FormEvent } from "react";
import { post, type InviteInfo, type SessionInfo, type UserSummary } from "../api";
import { useAction, useLoad } from "../hooks";
import { ErrorBanner, Loading, When } from "../components/ui";

interface TotpEnrollment {
  secret: string;
  otpauth_url: string;
}

/** The TOTP fields to send: both when enrolling, neither for password only. */
function totpFields(enrollment: TotpEnrollment | null, code: string) {
  return enrollment ? { totp_secret: enrollment.secret, totp_code: code.trim() } : {};
}

function AuthenticatorChoice({ checked, onChange }: { checked: boolean; onChange: (v: boolean) => void }) {
  return (
    <label className="check">
      <input type="checkbox" checked={checked} onChange={(e) => onChange(e.target.checked)} />
      Also require a code from an authenticator app at sign-in (recommended)
    </label>
  );
}

function EnrollmentBox({ enrollment }: { enrollment: TotpEnrollment }) {
  return (
    <div className="banner info">
      <p>Add this account to your authenticator app, then enter the 6-digit code.</p>
      <code className="secret">{enrollment.secret}</code>
      <p className="muted small">
        <a href={enrollment.otpauth_url}>Open in authenticator</a>
      </p>
    </div>
  );
}

/** First-run: create the admin with the one-time setup token from the server log. */
export function Setup({ onDone }: { onDone: () => void }) {
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [setupToken, setSetupToken] = useState("");
  const [code, setCode] = useState("");
  const [useTotp, setUseTotp] = useState(true);
  const [stage, setStage] = useState<"name" | "details">("name");
  const [enrollment, setEnrollment] = useState<TotpEnrollment | null>(null);
  const action = useAction();

  const begin = async (e: FormEvent) => {
    e.preventDefault();
    if (!useTotp) {
      setEnrollment(null);
      setStage("details");
      return;
    }
    const result = await action.run(() => post<TotpEnrollment>("/setup/totp", { username }));
    if (result) {
      setEnrollment(result);
      setStage("details");
    }
  };

  const finish = async (e: FormEvent) => {
    e.preventDefault();
    const user = await action.run(() =>
      post<UserSummary>("/setup", {
        setup_token: setupToken.trim(),
        username,
        password,
        ...totpFields(enrollment, code),
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
      {stage === "name" ? (
        <form onSubmit={begin} className="form">
          <label>
            Username
            <input value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" required />
          </label>
          <AuthenticatorChoice checked={useTotp} onChange={setUseTotp} />
          <button type="submit" disabled={action.busy}>
            Continue
          </button>
        </form>
      ) : (
        <form onSubmit={finish} className="form">
          {enrollment && <EnrollmentBox enrollment={enrollment} />}
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
          {enrollment && (
            <label>
              Authenticator code
              <input value={code} onChange={(e) => setCode(e.target.value)} inputMode="numeric" autoComplete="one-time-code" required />
            </label>
          )}
          <div className="actions">
            <button type="button" className="secondary" onClick={() => setStage("name")}>
              Back
            </button>
            <button type="submit" disabled={action.busy}>
              Create admin
            </button>
          </div>
        </form>
      )}
    </div>
  );
}

/** Opened from an invite link: create an account with the offered role. */
export function AcceptInvite({ token, onDone }: { token: string; onDone: () => void }) {
  const info = useLoad(() => post<InviteInfo>("/invites/inspect", { invite_token: token }), [token]);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [useTotp, setUseTotp] = useState(true);
  const [stage, setStage] = useState<"name" | "details">("name");
  const [enrollment, setEnrollment] = useState<TotpEnrollment | null>(null);
  const [created, setCreated] = useState<UserSummary | null>(null);
  const action = useAction();

  const begin = async (e: FormEvent) => {
    e.preventDefault();
    if (!useTotp) {
      setEnrollment(null);
      setStage("details");
      return;
    }
    const result = await action.run(() => post<TotpEnrollment>("/invites/totp", { invite_token: token, username }));
    if (result) {
      setEnrollment(result);
      setStage("details");
    }
  };

  const finish = async (e: FormEvent) => {
    e.preventDefault();
    const user = await action.run(() =>
      post<UserSummary>("/invites/accept", {
        invite_token: token,
        username,
        password,
        ...totpFields(enrollment, code),
      }),
    );
    if (user) setCreated(user);
  };

  if (info.loading) return <div className="auth"><Loading /></div>;
  if (created)
    return (
      <div className="auth">
        <h1>Account created</h1>
        <p>
          You can now sign in as <strong>{created.username}</strong> with the <strong>{created.role}</strong> role
          {created.totp_enrolled ? ", using the next code from your authenticator." : "."}
        </p>
        <button type="button" onClick={onDone}>
          Go to sign in
        </button>
      </div>
    );
  if (info.error || !info.data)
    return (
      <div className="auth">
        <h1>This invite cannot be used</h1>
        <ErrorBanner error={info.error ?? "The invite could not be read."} />
        <p className="muted">Invites work once and expire. Ask the admin who invited you for a new link.</p>
        <button type="button" className="secondary" onClick={onDone}>
          Go to sign in
        </button>
      </div>
    );

  return (
    <div className="auth">
      <h1>Join as {info.data.role}</h1>
      <p className="muted">
        This invite expires <When at={info.data.expires_at} />. Choose a username and password.
      </p>
      <ErrorBanner error={action.error} />
      {stage === "name" ? (
        <form onSubmit={begin} className="form">
          <label>
            Username (a-z, 0-9, '_', '-', '.')
            <input value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" required />
          </label>
          <AuthenticatorChoice checked={useTotp} onChange={setUseTotp} />
          <button type="submit" disabled={action.busy}>
            Continue
          </button>
        </form>
      ) : (
        <form onSubmit={finish} className="form">
          {enrollment && <EnrollmentBox enrollment={enrollment} />}
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
          {enrollment && (
            <label>
              Authenticator code
              <input value={code} onChange={(e) => setCode(e.target.value)} inputMode="numeric" autoComplete="one-time-code" required />
            </label>
          )}
          <div className="actions">
            <button type="button" className="secondary" onClick={() => setStage("name")}>
              Back
            </button>
            <button type="submit" disabled={action.busy}>
              Create account
            </button>
          </div>
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
    const trimmed = code.trim();
    const session = await action.run(() =>
      post<SessionInfo>("/auth/login", { username, password, ...(trimmed ? { totp_code: trimmed } : {}) }),
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
          Authenticator code <span className="muted small">(only if your account has one)</span>
          <input value={code} onChange={(e) => setCode(e.target.value)} inputMode="numeric" autoComplete="one-time-code" />
        </label>
        <button type="submit" disabled={action.busy}>
          Sign in
        </button>
      </form>
    </div>
  );
}

/** Asks the person to prove themselves again before a sensitive action is retried. */
export function StepUpDialog({
  open,
  totpEnrolled,
  onResult,
}: {
  open: boolean;
  totpEnrolled: boolean;
  onResult: (ok: boolean) => void;
}) {
  const [value, setValue] = useState("");
  const action = useAction();
  if (!open) return null;
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const proof = totpEnrolled ? { code: value.trim() } : { password: value };
    const ok = await action.run(() => post<{ step_up_at: string }>("/auth/step-up", proof));
    if (ok) {
      setValue("");
      onResult(true);
    }
  };
  return (
    <div className="modal-backdrop" role="dialog" aria-modal="true" aria-labelledby="stepup-title">
      <form className="modal form" onSubmit={submit}>
        <h2 id="stepup-title">{totpEnrolled ? "Confirm with your second factor" : "Confirm your password"}</h2>
        <p className="muted">
          Adding credentials, widening rules, managing people, API keys, templates and nodes needs a confirmation from the
          last 5 minutes.
        </p>
        <ErrorBanner error={action.error} />
        {totpEnrolled ? (
          <label>
            Authenticator code
            <input autoFocus value={value} onChange={(e) => setValue(e.target.value)} inputMode="numeric" autoComplete="one-time-code" required />
          </label>
        ) : (
          <label>
            Password
            <input autoFocus type="password" value={value} onChange={(e) => setValue(e.target.value)} autoComplete="current-password" required />
          </label>
        )}
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
