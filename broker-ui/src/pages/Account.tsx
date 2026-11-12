// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import { useState, type FormEvent } from "react";
import { CheckCircle2 } from "lucide-react";
import { post, type SsoSignIn, type UserSummary } from "../api";
import { useAction } from "../hooks";
import { ErrorBanner, Field, Status } from "../components/common";
import { SettingsSection } from "../components/layout";
import { Alert, AlertDescription } from "../components/ui/alert";
import { Button } from "../components/ui/button-components";
import { Input } from "../components/ui/input";
import { PageContainer, PageHeader } from "../components/ui/page-header";
import { CodeField, EnrollmentBox, type TotpEnrollment } from "./Auth";
import { SignIns } from "./SignIns";

/**
 * The signed-in person's own sign-in: password and authenticator app, or
 * the identity provider that handles both for them.
 */
export function Account({ user, sso, onChanged }: { user: UserSummary; sso?: SsoSignIn; onChanged: () => void }) {
  if (sso)
    return (
      <PageContainer width="settings">
        <PageHeader title="Account" verdict={<span className="text-sm text-muted-foreground">{user.username}</span>} />
        <SettingsSection title="Sign-in">
          <p className="text-sm">
            You sign in with <strong>{sso.name}</strong>. Your password, second factor and groups are managed there; your{" "}
            <strong>{user.role}</strong> role follows your groups at each sign-in.
          </p>
        </SettingsSection>
        <SettingsSection title="Where you're signed in" hint="A browser or CLI login you don't recognise: sign it out.">
          <SignIns />
        </SettingsSection>
      </PageContainer>
    );
  return (
    <PageContainer width="settings">
      <PageHeader title="Account" verdict={<span className="text-sm text-muted-foreground">{user.username}</span>} />
      <div>
        <SettingsSection title="Password">
          <PasswordForm />
        </SettingsSection>
        <SettingsSection
          title="Authenticator app"
          hint={<Status tone={user.totp_enrolled ? "success" : "neutral"}>{user.totp_enrolled ? "On" : "Off"}</Status>}
        >
          {user.totp_enrolled ? <RemoveAuthenticator onDone={onChanged} /> : <AddAuthenticator onDone={onChanged} />}
        </SettingsSection>
        <SettingsSection title="Where you're signed in" hint="A browser or CLI login you don't recognise: sign it out.">
          <SignIns />
        </SettingsSection>
      </div>
    </PageContainer>
  );
}

function PasswordInput({ id, label, value, onChange, hint, autoComplete }: {
  id: string;
  label: string;
  value: string;
  onChange: (v: string) => void;
  hint?: string;
  autoComplete: "current-password" | "new-password";
}) {
  return (
    <Field label={label} htmlFor={id} hint={hint}>
      <Input
        id={id}
        type="password"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        autoComplete={autoComplete}
        minLength={autoComplete === "new-password" ? 12 : undefined}
        required
      />
    </Field>
  );
}

function PasswordForm() {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [done, setDone] = useState(false);
  const action = useAction();

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setDone(false);
    const ok = await action.run(async () => {
      await post<void>("/auth/password", { current_password: current, new_password: next });
      return true;
    });
    if (ok) {
      setCurrent("");
      setNext("");
      setDone(true);
    }
  };

  return (
    <form onSubmit={submit} className="max-w-md space-y-5">
      <ErrorBanner error={action.error} />
      {done && (
        <Alert>
          <CheckCircle2 className="size-4 text-success" />
          <AlertDescription>Password changed. Your other sessions were signed out.</AlertDescription>
        </Alert>
      )}
      <PasswordInput id="current-password" label="Current password" value={current} onChange={setCurrent} autoComplete="current-password" />
      <PasswordInput
        id="new-password"
        label="New password"
        value={next}
        onChange={setNext}
        hint="At least 12 characters."
        autoComplete="new-password"
      />
      <Button type="submit" disabled={action.busy}>
        Change password
      </Button>
    </form>
  );
}

function AddAuthenticator({ onDone }: { onDone: () => void }) {
  const [enrollment, setEnrollment] = useState<TotpEnrollment | null>(null);
  const [code, setCode] = useState("");
  const [password, setPassword] = useState("");
  const action = useAction();

  const begin = async () => {
    const result = await action.run(() => post<TotpEnrollment>("/auth/authenticator/enrollment", {}));
    if (result) setEnrollment(result);
  };

  const finish = async (e: FormEvent) => {
    e.preventDefault();
    if (!enrollment) return;
    const user = await action.run(() =>
      post<UserSummary>("/auth/authenticator", { secret: enrollment.secret, code: code.trim(), password }),
    );
    if (user) onDone();
  };

  if (!enrollment)
    return (
      <div className="max-w-md space-y-3">
        <p className="text-sm">Sign in with a code from an app such as 1Password or Google Authenticator, as well as your password.</p>
        <ErrorBanner error={action.error} />
        <Button type="button" variant="outline" onClick={() => void begin()} disabled={action.busy}>
          Set up
        </Button>
      </div>
    );

  return (
    <form onSubmit={finish} className="max-w-md space-y-5">
      <ErrorBanner error={action.error} />
      <EnrollmentBox enrollment={enrollment} />
      <Field label="Code from the app" htmlFor="totp-code">
        <CodeField value={code} onChange={setCode} required />
      </Field>
      <PasswordInput id="confirm-password" label="Your password" value={password} onChange={setPassword} autoComplete="current-password" />
      <div className="flex gap-2">
        <Button type="button" variant="outline" onClick={() => setEnrollment(null)}>
          Cancel
        </Button>
        <Button type="submit" disabled={action.busy}>
          Turn on
        </Button>
      </div>
    </form>
  );
}

function RemoveAuthenticator({ onDone }: { onDone: () => void }) {
  const [open, setOpen] = useState(false);
  const [code, setCode] = useState("");
  const [password, setPassword] = useState("");
  const action = useAction();

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const user = await action.run(() => post<UserSummary>("/auth/authenticator/remove", { code: code.trim(), password }));
    if (user) onDone();
  };

  if (!open)
    return (
      <div className="max-w-md space-y-3">
        <p className="text-sm">Signing in asks for a code from your authenticator app.</p>
        <Button type="button" variant="outline" onClick={() => setOpen(true)}>
          Remove
        </Button>
      </div>
    );

  return (
    <form onSubmit={submit} className="max-w-md space-y-5">
      <ErrorBanner error={action.error} />
      <Field label="Code from the app" htmlFor="totp-code">
        <CodeField value={code} onChange={setCode} required autoFocus />
      </Field>
      <PasswordInput id="confirm-password" label="Your password" value={password} onChange={setPassword} autoComplete="current-password" />
      <div className="flex gap-2">
        <Button type="button" variant="outline" onClick={() => setOpen(false)}>
          Cancel
        </Button>
        <Button type="submit" variant="destructive" disabled={action.busy}>
          Remove authenticator
        </Button>
      </div>
    </form>
  );
}
