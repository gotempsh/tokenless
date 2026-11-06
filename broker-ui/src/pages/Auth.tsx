// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import { useState, type FormEvent, type ReactNode } from "react";
import { ChevronLeft, Smartphone } from "lucide-react";
import { ApiError, post, type InviteInfo, type SessionInfo, type UserSummary } from "../api";
import { useAction, useLoad } from "../hooks";
import { CheckField, CopyButton, DialogActions, ErrorBanner, Field, When } from "../components/common";
import { BrandMark } from "../components/Brand";
import { Alert, AlertDescription, AlertTitle } from "../components/ui/alert";
import { Button } from "../components/ui/button-components";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "../components/ui/dialog";
import { Input } from "../components/ui/input";
import { Skeleton } from "../components/ui/skeleton";

export interface TotpEnrollment {
  secret: string;
  otpauth_url: string;
}

/** The TOTP fields to send: both when enrolling, neither for password only. */
function totpFields(enrollment: TotpEnrollment | null, code: string) {
  return enrollment ? { totp_secret: enrollment.secret, totp_code: code.trim() } : {};
}

/** Centred card used by every signed-out screen. */
export function AuthLayout({ title, description, children }: { title: string; description?: ReactNode; children: ReactNode }) {
  return (
    <div className="flex min-h-svh flex-col items-center justify-center bg-muted/40 px-4 py-10">
      <div className="mb-6 flex items-center gap-2">
        <BrandMark />
        <span className="text-sm font-semibold">Tokenless</span>
      </div>
      <div className="w-full max-w-md rounded-lg border bg-card p-6 text-card-foreground sm:p-8">
        <div className="mb-6 space-y-1.5">
          <h1 className="text-xl font-semibold tracking-tight">{title}</h1>
          {description && <div className="text-sm text-muted-foreground">{description}</div>}
        </div>
        {children}
      </div>
    </div>
  );
}

function AuthenticatorChoice({ checked, onChange }: { checked: boolean; onChange: (v: boolean) => void }) {
  return (
    <CheckField
      id="use-totp"
      checked={checked}
      onChange={onChange}
      hint="Optional. Every sign-in then also asks for a 6-digit code from the app."
    >
      Use an authenticator app
    </CheckField>
  );
}

export function EnrollmentBox({ enrollment }: { enrollment: TotpEnrollment }) {
  return (
    <Alert>
      <Smartphone className="size-4" />
      <AlertTitle>Add this account to your authenticator app</AlertTitle>
      <AlertDescription className="space-y-3">
        <p>Enter the key below, or open the link on a phone, then type the 6-digit code it shows.</p>
        <div className="flex items-center gap-2">
          <code className="min-w-0 flex-1 break-all rounded-md border bg-muted/40 px-3 py-2 font-mono text-xs text-foreground">
            {enrollment.secret}
          </code>
          <CopyButton value={enrollment.secret} />
        </div>
        <a href={enrollment.otpauth_url} className="text-sm font-medium underline underline-offset-4">
          Open in authenticator
        </a>
      </AlertDescription>
    </Alert>
  );
}

function PasswordField({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  return (
    <Field label="Password" htmlFor="new-password" hint="At least 12 characters.">
      <Input
        id="new-password"
        type="password"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        autoComplete="new-password"
        minLength={12}
        required
      />
    </Field>
  );
}

export function CodeField({ value, onChange, required, autoFocus }: { value: string; onChange: (v: string) => void; required?: boolean; autoFocus?: boolean }) {
  return (
    <Input
      id="totp-code"
      value={value}
      onChange={(e) => onChange(e.target.value)}
      inputMode="numeric"
      autoComplete="one-time-code"
      placeholder="123456"
      className="font-mono tracking-widest"
      required={required}
      autoFocus={autoFocus}
    />
  );
}

/** Opened from an invite link: create an account with the offered role. */
export function AcceptInvite({ token, onDone }: { token: string; onDone: () => void }) {
  const info = useLoad(() => post<InviteInfo>("/invites/inspect", { invite_token: token }), [token]);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [useTotp, setUseTotp] = useState(false);
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

  if (info.loading)
    return (
      <AuthLayout title="Checking your invite…">
        <div className="space-y-3">
          <Skeleton className="h-10 w-full" />
          <Skeleton className="h-10 w-full" />
        </div>
      </AuthLayout>
    );
  if (created)
    return (
      <AuthLayout title="Account created">
        <div className="space-y-5">
          <p className="text-sm">
            You can now sign in as <strong>{created.username}</strong> with the <strong>{created.role}</strong> role
            {created.totp_enrolled ? ", using the next code from your authenticator." : "."}
          </p>
          <Button type="button" className="w-full" onClick={onDone}>
            Go to sign in
          </Button>
        </div>
      </AuthLayout>
    );
  if (info.error || !info.data)
    return (
      <AuthLayout
        title="This invite cannot be used"
        description="Invites work once and expire. Ask the admin who invited you for a new link."
      >
        <div className="space-y-5">
          <ErrorBanner error={info.error ?? "The invite could not be read."} />
          <Button type="button" variant="outline" className="w-full" onClick={onDone}>
            Go to sign in
          </Button>
        </div>
      </AuthLayout>
    );

  return (
    <AuthLayout
      title={`Join as ${info.data.role}`}
      description={
        <>
          This invite expires <When at={info.data.expires_at} />. Choose a username and password.
        </>
      }
    >
      {stage === "name" ? (
        <form onSubmit={begin} className="space-y-5">
          <ErrorBanner error={action.error} />
          <Field label="Username" htmlFor="username" hint="Lowercase letters, digits, '_', '-' and '.'.">
            <Input id="username" value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" required />
          </Field>
          <AuthenticatorChoice checked={useTotp} onChange={setUseTotp} />
          <Button type="submit" className="w-full" disabled={action.busy}>
            Continue
          </Button>
        </form>
      ) : (
        <form onSubmit={finish} className="space-y-5">
          <ErrorBanner error={action.error} />
          {enrollment && <EnrollmentBox enrollment={enrollment} />}
          <PasswordField value={password} onChange={setPassword} />
          {enrollment && (
            <Field label="Authenticator code" htmlFor="totp-code">
              <CodeField value={code} onChange={setCode} required />
            </Field>
          )}
          <div className="flex gap-2">
            <Button type="button" variant="outline" onClick={() => setStage("name")}>
              <ChevronLeft />
              Back
            </Button>
            <Button type="submit" className="flex-1" disabled={action.busy}>
              Create account
            </Button>
          </div>
        </form>
      )}
    </AuthLayout>
  );
}

/** Username and password; a second screen asks for the code only when the account has an authenticator. */
export function Login({ onLogin }: { onLogin: (s: SessionInfo) => void }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [stage, setStage] = useState<"password" | "code">("password");
  const action = useAction();

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const trimmed = stage === "code" ? code.trim() : "";
    const result = await action.run(async () => {
      try {
        return await post<SessionInfo>("/auth/login", { username, password, ...(trimmed ? { totp_code: trimmed } : {}) });
      } catch (err) {
        if (err instanceof ApiError && err.problem.code === "second_factor_required") return "code" as const;
        if (stage === "code" && err instanceof ApiError && err.problem.code === "unauthenticated")
          throw new Error("That code is wrong or has expired. Enter the one your app shows now.");
        throw err;
      }
    });
    if (result === "code") setStage("code");
    else if (result) onLogin(result);
  };

  const back = () => {
    setStage("password");
    setCode("");
    action.clearError();
  };

  if (stage === "code")
    return (
      <AuthLayout title="Enter your code" description={<>Open your authenticator app and enter the code for {username}.</>}>
        <form onSubmit={submit} className="space-y-5">
          <ErrorBanner error={action.error} title="Sign-in failed" />
          <Field label="Authenticator code" htmlFor="totp-code">
            <CodeField value={code} onChange={setCode} required autoFocus />
          </Field>
          <div className="flex gap-2">
            <Button type="button" variant="outline" onClick={back}>
              <ChevronLeft />
              Back
            </Button>
            <Button type="submit" className="flex-1" disabled={action.busy}>
              Sign in
            </Button>
          </div>
        </form>
      </AuthLayout>
    );

  return (
    <AuthLayout title="Sign in">
      <form onSubmit={submit} className="space-y-5">
        <ErrorBanner error={action.error} title="Sign-in failed" />
        <Field label="Username" htmlFor="username">
          <Input id="username" value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" autoFocus required />
        </Field>
        <Field label="Password" htmlFor="password">
          <Input
            id="password"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="current-password"
            required
          />
        </Field>
        <Button type="submit" className="w-full" disabled={action.busy}>
          Sign in
        </Button>
      </form>
    </AuthLayout>
  );
}

/**
 * Asks someone with an authenticator for a fresh code before a sensitive
 * action is retried. Password-only accounts are never asked.
 */
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
    <Dialog
      open={open}
      onOpenChange={(o) => {
        if (!o) {
          setValue("");
          action.clearError();
          onResult(false);
        }
      }}
    >
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{totpEnrolled ? "Confirm with your authenticator" : "Confirm your password"}</DialogTitle>
          <DialogDescription>
            Adding credentials, widening rules, and managing people, API keys, templates and nodes needs a confirmation
            from the last 5 minutes.
          </DialogDescription>
        </DialogHeader>
        <form onSubmit={submit} className="space-y-4">
          <ErrorBanner error={action.error} />
          {totpEnrolled ? (
            <Field label="Authenticator code" htmlFor="totp-code">
              <CodeField value={value} onChange={setValue} required autoFocus />
            </Field>
          ) : (
            <Field label="Password" htmlFor="step-up-password">
              <Input
                id="step-up-password"
                autoFocus
                type="password"
                value={value}
                onChange={(e) => setValue(e.target.value)}
                autoComplete="current-password"
                required
              />
            </Field>
          )}
          <DialogActions>
            <Button type="button" variant="outline" onClick={() => onResult(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={action.busy}>
              Confirm
            </Button>
          </DialogActions>
        </form>
      </DialogContent>
    </Dialog>
  );
}
