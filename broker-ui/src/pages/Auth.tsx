// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import { useEffect, useRef, useState, type FormEvent, type ReactNode } from "react";
import { ChevronLeft, ExternalLink, Smartphone } from "lucide-react";
import { joinsVaults } from "../members";
import { ApiError, get, post, type InviteInfo, type SessionInfo, type SignInOptions, type SsoSignIn, type UserSummary } from "../api";
import {
  returnToHere,
  ssoStartHref,
  STEP_UP_CHANNEL,
  STEP_UP_DONE_ROUTE,
  type StepUpMessage,
} from "../sso";
import { useAction, useLoad } from "../hooks";
import { CheckField, CopyButton, DialogActions, ErrorBanner, Field, When } from "../components/common";
import { BrandMark } from "../components/Brand";
import { ProviderLogo } from "../components/ProviderLogo";
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
      <div className="mb-6 flex max-w-md flex-col items-center gap-3 text-center">
        <div className="flex items-center gap-2">
          <BrandMark />
          <span className="text-sm font-semibold">Tokenless</span>
        </div>
        <p className="text-sm text-muted-foreground">
          A credential broker for AI agents. Agents call APIs through your proxy, which adds the real token on the way
          out, so the agent never holds it.
        </p>
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
            You can now sign in as <strong>{created.username}</strong>
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
      title={info.data.role === "admin" ? "Join as an instance admin" : "Join tokenless"}
      description={
        <>
          {joinsVaults(info.data)} This invite expires <When at={info.data.expires_at} />. Choose a username and password.
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

/** "Continue with …" for each identity provider people sign in with here. */
function ProviderButtons({ options }: { options: SignInOptions }) {
  const back = returnToHere(window.location);
  return (
    <div className="space-y-2">
      {options.providers.map((p) => (
        <Button key={p.slug} asChild variant="outline" className="w-full">
          <a href={ssoStartHref(p.slug, back)}>
            <ProviderLogo brand={p.brand} />
            Continue with {p.name}
          </a>
        </Button>
      ))}
    </div>
  );
}

/**
 * Single sign-on buttons when providers are set up, then username and
 * password; a second screen asks for the code only when the account has an
 * authenticator. When only local admins may use a password, the password
 * form stays one click away for when the provider cannot be reached.
 */
export function Login({ onLogin, ssoError }: { onLogin: (s: SessionInfo) => void; ssoError: string | null }) {
  const options = useLoad(() => get<SignInOptions>("/auth/sign-in-options"), []);
  const [showPassword, setShowPassword] = useState(false);
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

  const providers = options.data?.providers.length ? options.data : null;
  const adminsOnly = options.data?.password_sign_in === "admins_only";
  const passwordForm = !providers || !adminsOnly || showPassword;

  return (
    <AuthLayout title="Sign in">
      {ssoError && (
        <div className="mb-5">
          <ErrorBanner error={ssoError} title="Single sign-on failed" />
        </div>
      )}
      {providers && (
        <>
          <ProviderButtons options={providers} />
          {passwordForm ? (
            <div className="my-5 flex items-center gap-3 text-xs text-muted-foreground">
              <div className="h-px flex-1 bg-border" />
              {adminsOnly ? "Local admin account" : "or with a password"}
              <div className="h-px flex-1 bg-border" />
            </div>
          ) : (
            <Button type="button" variant="link" className="mt-4 h-auto w-full p-0 text-xs text-muted-foreground" onClick={() => setShowPassword(true)}>
              Sign in with a local admin account
            </Button>
          )}
        </>
      )}
      {passwordForm && (
        <>
          <form onSubmit={submit} className="space-y-5">
            <ErrorBanner error={action.error} title="Sign-in failed" />
            <Field label="Username" htmlFor="username">
              <Input id="username" value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" autoFocus={!providers} required />
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
          {!providers && (
            <div className="mt-6 space-y-1.5 border-t pt-5 text-xs text-muted-foreground">
              <p>
                <span className="font-medium text-foreground">First time?</span> Sign in as <code>admin</code> with the
                password <code>tokenless serve</code> printed when it first started.
              </p>
              <p>
                Lost it? On the server, run <code>tokenless admin reset-password</code>. No account yet? Ask an admin for
                an invitation.
              </p>
            </div>
          )}
        </>
      )}
    </AuthLayout>
  );
}

const STEP_UP_WHY =
  "Adding credentials, widening rules, and managing people, API keys, templates and nodes needs a confirmation from the last 5 minutes.";

/**
 * Where the provider's popup lands after a step-up: tells the console that
 * opened it how it went, then closes.
 */
export function StepUpDone({ error }: { error: string | null }) {
  useEffect(() => {
    const channel = new BroadcastChannel(STEP_UP_CHANNEL);
    channel.postMessage({ ok: error === null, error } satisfies StepUpMessage);
    channel.close();
    if (error === null) window.close();
  }, [error]);
  return (
    <AuthLayout title={error === null ? "Confirmed" : "Confirmation failed"}>
      <div className="space-y-5">
        {error !== null && <ErrorBanner error={error} title="Single sign-on failed" />}
        <p className="text-sm text-muted-foreground">You can close this window.</p>
      </div>
    </AuthLayout>
  );
}

/**
 * A step-up for someone who signs in with an identity provider: they sign
 * in there again, in a popup so this page keeps its state. A blocked popup
 * falls back to going there with the whole page.
 */
function SsoStepUp({
  sso,
  initialError,
  onResult,
}: {
  sso: SsoSignIn;
  initialError: string | null;
  onResult: (ok: boolean) => void;
}) {
  const [error, setError] = useState(initialError);
  const [waiting, setWaiting] = useState(false);
  const finished = useRef(false);
  const report = useRef(onResult);
  report.current = onResult;

  useEffect(() => {
    if (!waiting) return;
    const channel = new BroadcastChannel(STEP_UP_CHANNEL);
    channel.onmessage = (e: MessageEvent<StepUpMessage>) => {
      if (finished.current) return;
      setWaiting(false);
      if (e.data.ok) {
        finished.current = true;
        report.current(true);
      } else {
        setError(e.data.error ?? "Single sign-on failed.");
      }
    };
    return () => channel.close();
  }, [waiting]);

  const go = () => {
    setError(null);
    finished.current = false;
    const popup = window.open("about:blank", "tokenless-step-up", "popup,width=520,height=700");
    if (!popup) {
      window.location.href = ssoStartHref(sso.slug, returnToHere(window.location), "step_up");
      return;
    }
    // The provider's pages get no handle on this one.
    popup.opener = null;
    popup.location.href = ssoStartHref(sso.slug, `/#/${STEP_UP_DONE_ROUTE}`, "step_up");
    setWaiting(true);
  };

  return (
    <div className="space-y-4">
      <ErrorBanner error={error} title="Single sign-on failed" />
      {waiting && (
        <p className="text-sm text-muted-foreground">
          Waiting for you to sign in to {sso.name} in the window that opened…
        </p>
      )}
      <DialogActions>
        <Button type="button" variant="outline" onClick={() => onResult(false)}>
          Cancel
        </Button>
        <Button type="button" onClick={go}>
          <ExternalLink />
          {waiting ? "Open again" : `Continue with ${sso.name}`}
        </Button>
      </DialogActions>
    </div>
  );
}

/**
 * Asks for a fresh confirmation before a sensitive action is retried: a
 * code from the authenticator, the password, or a new sign-in at the
 * identity provider the person signs in with.
 */
export function StepUpDialog({
  open,
  totpEnrolled,
  sso,
  ssoError = null,
  onResult,
}: {
  open: boolean;
  totpEnrolled: boolean;
  sso?: SsoSignIn;
  /** Why the last step-up at the provider failed, when the page went there. */
  ssoError?: string | null;
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
        {sso ? (
          <>
            <DialogHeader>
              <DialogTitle>Confirm with {sso.name}</DialogTitle>
              <DialogDescription>{STEP_UP_WHY}</DialogDescription>
            </DialogHeader>
            <SsoStepUp key={String(open)} sso={sso} initialError={ssoError} onResult={onResult} />
          </>
        ) : (
          <>
            <DialogHeader>
              <DialogTitle>{totpEnrolled ? "Confirm with your authenticator" : "Confirm your password"}</DialogTitle>
              <DialogDescription>{STEP_UP_WHY}</DialogDescription>
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
          </>
        )}
      </DialogContent>
    </Dialog>
  );
}
