// SPDX-FileCopyrightText: 2026 credential-broker contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import * as DialogPrimitive from "@radix-ui/react-dialog";
import {
  Braces,
  ChevronRight,
  FileCode2,
  KeySquare,
  LogOut,
  Menu,
  Monitor,
  Moon,
  ScrollText,
  Server,
  Settings as SettingsIcon,
  Sun,
  Timer,
  Users,
  Vault as VaultIcon,
  type LucideIcon,
} from "lucide-react";
import { ApiError, get, post, setCsrfToken, setStepUpHandler, type SessionInfo, type UserSummary } from "./api";
import { useHashRoute } from "./hooks";
import { useTheme, type Theme } from "./theme";
import { cn } from "./lib/utils";
import { ErrorBanner } from "./components/common";
import { BrandMark } from "./components/Brand";
import { Button } from "./components/ui/button-components";
import { Skeleton } from "./components/ui/skeleton";
import { AcceptInvite, AuthLayout, Login, Setup, StepUpDialog } from "./pages/Auth";
import { ApiKeys } from "./pages/ApiKeys";
import { Audit } from "./pages/Audit";
import { Nodes } from "./pages/Nodes";
import { Sessions } from "./pages/Sessions";
import { People } from "./pages/People";
import { Settings } from "./pages/Settings";
import { Templates } from "./pages/Templates";
import { Variables } from "./pages/Variables";
import { VaultDetail } from "./pages/VaultDetail";
import { Vaults } from "./pages/Vaults";

type Boot =
  | { state: "loading" }
  | { state: "setup" }
  | { state: "login" }
  | { state: "ready"; session: SessionInfo }
  | { state: "error"; message: string };

interface NavItem {
  key: string;
  label: string;
  icon: LucideIcon;
}

const NAV: { group: string; items: NavItem[] }[] = [
  {
    group: "Broker",
    items: [
      { key: "vaults", label: "Vaults", icon: VaultIcon },
      { key: "sessions", label: "Sessions", icon: Timer },
      { key: "variables", label: "Variables", icon: Braces },
      { key: "templates", label: "Templates", icon: FileCode2 },
    ],
  },
  {
    group: "Access",
    items: [
      { key: "people", label: "People", icon: Users },
      { key: "api-keys", label: "API keys", icon: KeySquare },
    ],
  },
  {
    group: "Instance",
    items: [
      { key: "proxies", label: "Proxies", icon: Server },
      { key: "audit", label: "Audit log", icon: ScrollText },
      { key: "settings", label: "Settings", icon: SettingsIcon },
    ],
  },
];

const LABELS: Record<string, string> = Object.fromEntries(NAV.flatMap((g) => g.items.map((i) => [i.key, i.label])));

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

  if (route[0] === "invite" && route[1])
    return (
      <AcceptInvite
        token={route[1]}
        onDone={() => {
          window.location.hash = "";
          setBoot({ state: "login" });
        }}
      />
    );
  if (boot.state === "loading")
    return (
      <div className="flex min-h-svh">
        <div className="hidden w-64 border-r bg-sidebar md:block" />
        <div className="flex-1 space-y-4 p-8">
          <Skeleton className="h-8 w-48" />
          <Skeleton className="h-4 w-96 max-w-full" />
          <Skeleton className="h-64 w-full" />
        </div>
      </div>
    );
  if (boot.state === "error")
    return (
      <AuthLayout title="The console could not start">
        <ErrorBanner error={boot.message} />
      </AuthLayout>
    );
  if (boot.state === "setup") return <Setup onDone={() => setBoot({ state: "login" })} />;
  if (boot.state === "login")
    return (
      <Login
        onLogin={(session) => {
          setCsrfToken(session.csrf_token);
          setBoot({ state: "ready", session });
        }}
      />
    );

  const { user } = boot.session;
  const [rawSection = "vaults", id, tab] = route;
  // "nodes" was the old name of the proxies page; keep old links working.
  const section = rawSection === "nodes" ? "proxies" : rawSection;
  const isAdmin = user.role === "admin";

  return (
    <Shell section={section} detail={section === "vaults" && id ? "Vault" : undefined} user={user} onLogout={() => void logout()}>
      {section === "vaults" && !id && <Vaults canCreate={isAdmin} />}
      {section === "vaults" && id && (
        <VaultDetail vaultId={id} tab={tab === "rules" || tab === "sessions" ? tab : "credentials"} user={user} />
      )}
      {section === "sessions" && <Sessions />}
      {section === "variables" && <Variables isAdmin={isAdmin} />}
      {section === "templates" && <Templates isAdmin={isAdmin} />}
      {section === "people" && <People me={user} />}
      {section === "api-keys" && <ApiKeys />}
      {section === "proxies" && <Nodes />}
      {section === "audit" && <Audit />}
      {section === "settings" && <Settings />}
      <StepUpDialog open={stepUpOpen} totpEnrolled={user.totp_enrolled} onResult={finishStepUp} />
    </Shell>
  );
}

// ----- shell -------------------------------------------------------------------

function Shell({
  section,
  detail,
  user,
  onLogout,
  children,
}: {
  section: string;
  detail?: string;
  user: UserSummary;
  onLogout: () => void;
  children: ReactNode;
}) {
  const [mobileOpen, setMobileOpen] = useState(false);
  const [theme, setTheme] = useTheme();
  const sidebar = <SidebarContent section={section} user={user} onLogout={onLogout} onNavigate={() => setMobileOpen(false)} />;

  return (
    <div className="flex min-h-svh w-full">
      <aside className="sticky top-0 hidden h-svh w-64 shrink-0 flex-col border-r bg-sidebar text-sidebar-foreground md:flex">
        {sidebar}
      </aside>
      <DialogPrimitive.Root open={mobileOpen} onOpenChange={setMobileOpen}>
        <DialogPrimitive.Portal>
          <DialogPrimitive.Overlay className="fixed inset-0 z-50 bg-black/60 data-[state=open]:animate-in data-[state=open]:fade-in-0 md:hidden" />
          <DialogPrimitive.Content className="fixed inset-y-0 left-0 z-50 flex w-72 flex-col border-r bg-sidebar text-sidebar-foreground data-[state=open]:animate-in data-[state=open]:slide-in-from-left md:hidden">
            <DialogPrimitive.Title className="sr-only">Navigation</DialogPrimitive.Title>
            <DialogPrimitive.Description className="sr-only">Sections of the console</DialogPrimitive.Description>
            {sidebar}
          </DialogPrimitive.Content>
        </DialogPrimitive.Portal>
      </DialogPrimitive.Root>
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-10 flex h-16 shrink-0 items-center gap-2 border-b bg-background px-4">
          <Button
            type="button"
            variant="ghost"
            size="icon"
            className="size-8 md:hidden"
            aria-label="Open navigation"
            onClick={() => setMobileOpen(true)}
          >
            <Menu />
          </Button>
          <nav aria-label="Breadcrumb" className="flex min-w-0 items-center gap-1.5 text-sm">
            {detail ? (
              <>
                <a href={`#/${section}`} className="text-muted-foreground hover:text-foreground">
                  {LABELS[section] ?? section}
                </a>
                <ChevronRight className="size-3.5 text-muted-foreground" />
                <span className="truncate font-medium">{detail}</span>
              </>
            ) : (
              <span className="truncate font-medium">{LABELS[section] ?? section}</span>
            )}
          </nav>
          <div className="ml-auto">
            <ThemeToggle theme={theme} onChange={setTheme} />
          </div>
        </header>
        <main className="min-w-0 flex-1">{children}</main>
      </div>
    </div>
  );
}

function SidebarContent({
  section,
  user,
  onLogout,
  onNavigate,
}: {
  section: string;
  user: UserSummary;
  onLogout: () => void;
  onNavigate: () => void;
}) {
  return (
    <>
      <div className="flex h-16 shrink-0 items-center gap-2 border-b px-4">
        <BrandMark />
        <div className="min-w-0 leading-tight">
          <div className="truncate text-sm font-semibold">Credential Broker</div>
          <div className="truncate text-xs text-sidebar-foreground/70">Console</div>
        </div>
      </div>
      <nav className="flex-1 overflow-y-auto p-2">
        {NAV.map((g) => (
          <div key={g.group} className="mb-2">
            <div className="flex h-8 items-center px-2 text-xs font-medium text-sidebar-foreground/70">{g.group}</div>
            <ul className="flex flex-col gap-1">
              {g.items.map((item) => {
                const active = section === item.key;
                return (
                  <li key={item.key}>
                    <a
                      href={`#/${item.key}`}
                      onClick={onNavigate}
                      data-active={active}
                      aria-current={active ? "page" : undefined}
                      className="flex h-8 w-full items-center gap-2 rounded-md p-2 text-sm outline-none ring-sidebar-ring transition-colors hover:bg-sidebar-accent hover:text-sidebar-accent-foreground focus-visible:ring-2 data-[active=true]:bg-sidebar-accent data-[active=true]:font-medium data-[active=true]:text-sidebar-accent-foreground [&>svg]:size-4 [&>svg]:shrink-0"
                    >
                      <item.icon />
                      <span className="truncate">{item.label}</span>
                    </a>
                  </li>
                );
              })}
            </ul>
          </div>
        ))}
      </nav>
      <div className="flex items-center gap-2 border-t p-3">
        <span className="flex size-8 shrink-0 items-center justify-center rounded-full bg-sidebar-accent text-xs font-semibold uppercase">
          {user.username.slice(0, 2)}
        </span>
        <div className="min-w-0 flex-1 leading-tight">
          <div className="truncate text-sm font-medium">{user.username}</div>
          <div className="truncate text-xs text-sidebar-foreground/70">{user.role.replace("_", " ")}</div>
        </div>
        <Button type="button" variant="ghost" size="icon" className="size-8" aria-label="Sign out" title="Sign out" onClick={onLogout}>
          <LogOut />
        </Button>
      </div>
    </>
  );
}

const THEMES: { value: Theme; label: string; icon: LucideIcon }[] = [
  { value: "light", label: "Light", icon: Sun },
  { value: "dark", label: "Dark", icon: Moon },
  { value: "system", label: "System", icon: Monitor },
];

function ThemeToggle({ theme, onChange }: { theme: Theme; onChange: (t: Theme) => void }) {
  return (
    <div role="radiogroup" aria-label="Theme" className="flex items-center gap-0.5 rounded-md border p-0.5">
      {THEMES.map((t) => (
        <button
          key={t.value}
          type="button"
          role="radio"
          aria-checked={theme === t.value}
          aria-label={t.label}
          title={t.label}
          onClick={() => onChange(t.value)}
          className={cn(
            "flex size-7 items-center justify-center rounded-sm text-muted-foreground transition-colors hover:text-foreground",
            theme === t.value && "bg-accent text-foreground",
          )}
        >
          <t.icon className="size-3.5" />
        </button>
      ))}
    </div>
  );
}
