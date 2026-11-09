// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import * as DialogPrimitive from "@radix-ui/react-dialog";
import {
  Boxes,
  Braces,
  ChevronRight,
  FileCode2,
  FolderLock as VaultIcon,
  KeySquare,
  LogOut,
  Menu,
  Monitor,
  Moon,
  PanelLeftClose,
  PanelLeftOpen,
  ScrollText,
  Server,
  Settings as SettingsIcon,
  Sun,
  Timer,
  Users,
  type LucideIcon,
} from "lucide-react";
import {
  ApiError,
  get,
  post,
  setCsrfToken,
  setStepUpHandler,
  type NodeInfo,
  type Page,
  type SessionInfo,
  type UserSummary,
} from "./api";
import { proxyAttention } from "./proxyHealth";
import { useHashQuery, useHashRoute } from "./hooks";
import { BreadcrumbContext, trail, type Crumb } from "./breadcrumbs";
import { parseAddServiceContext } from "./addService";
import { parseBundleFormContext } from "./bundleForm";
import { useTheme, type Theme } from "./theme";
import { useSidebarCollapsed } from "./sidebar";
import { cn } from "./lib/utils";
import { ErrorBanner } from "./components/common";
import { BrandMark } from "./components/Brand";
import { Button } from "./components/ui/button-components";
import { Skeleton } from "./components/ui/skeleton";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "./components/ui/tooltip";
import { AcceptInvite, AuthLayout, Login, StepUpDialog, StepUpDone } from "./pages/Auth";
import { ProviderFormPage } from "./pages/SingleSignOn";
import { STEP_UP_DONE_ROUTE, takeSsoError } from "./sso";
import { Account } from "./pages/Account";
import { BundleDetail, bundleTab } from "./pages/BundleDetail";
import { BundleFormPage } from "./pages/BundleFormPage";
import { Bundles } from "./pages/Bundles";
import { AddService } from "./pages/AddService";
import { ApiKeys } from "./pages/ApiKeys";
import { Audit } from "./pages/Audit";
import { Nodes } from "./pages/Nodes";
import { ProxyDetail } from "./pages/ProxyDetail";
import { ServiceDetail } from "./pages/ServiceDetail";
import { Sessions } from "./pages/Sessions";
import { SessionPage } from "./pages/SessionPage";
import { People } from "./pages/People";
import { Settings } from "./pages/Settings";
import { Templates } from "./pages/Templates";
import { Variables } from "./pages/Variables";
import { VaultDetail, vaultTab } from "./pages/VaultDetail";
import { Vaults } from "./pages/Vaults";

type Boot =
  | { state: "loading" }
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
      { key: "bundles", label: "Access bundles", icon: Boxes },
      { key: "sessions", label: "Sessions", icon: Timer },
      { key: "templates", label: "Templates", icon: FileCode2 },
      { key: "variables", label: "Variables", icon: Braces },
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

const LABELS: Record<string, string> = {
  ...Object.fromEntries(NAV.flatMap((g) => g.items.map((i) => [i.key, i.label]))),
  "add-service": "Add a service",
  account: "Account",
};

export function App() {
  const [boot, setBoot] = useState<Boot>({ state: "loading" });
  const [stepUpOpen, setStepUpOpen] = useState(false);
  // Why a sign-in or step-up at an identity provider failed, read once from
  // the address the provider sent the browser back to.
  const [ssoError, setSsoError] = useState(takeSsoError);
  const pending = useRef<((ok: boolean) => void) | null>(null);
  const ssoErrorRef = useRef(ssoError);
  ssoErrorRef.current = ssoError;
  const route = useHashRoute();
  const query = useHashQuery();

  const load = useCallback(async () => {
    try {
      const session = await get<SessionInfo>("/auth/me");
      setCsrfToken(session.csrf_token);
      setBoot({ state: "ready", session });
      // Back from a step-up that failed at the provider: say why where
      // it would have been confirmed.
      if (session.sso) setStepUpOpen((open) => open || ssoErrorRef.current !== null);
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
    setSsoError(null);
    pending.current?.(ok);
    pending.current = null;
  };

  const logout = async () => {
    try {
      await post<void>("/auth/logout");
    } finally {
      setCsrfToken(null);
      setSsoError(null);
      setBoot({ state: "login" });
    }
  };

  if (route[0] === STEP_UP_DONE_ROUTE) return <StepUpDone error={ssoError} />;
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
  if (boot.state === "login")
    return (
      <Login
        ssoError={ssoError}
        onLogin={(session) => {
          setSsoError(null);
          setCsrfToken(session.csrf_token);
          setBoot({ state: "ready", session });
        }}
      />
    );

  const { user } = boot.session;
  const [rawSection = "vaults", id, tab, sub] = route;
  // "nodes" was the old name of the proxies page; keep old links working.
  const section = rawSection === "nodes" ? "proxies" : rawSection;
  const isAdmin = user.role === "admin";

  return (
    <Shell section={section} user={user} onLogout={() => void logout()}>
      {section === "vaults" && !id && <Vaults canCreate={isAdmin} />}
      {section === "vaults" && id && tab === "services" && sub && (
        <ServiceDetail vaultId={id} credentialId={sub} user={user} />
      )}
      {section === "vaults" && id && !(tab === "services" && sub) && (
        <VaultDetail vaultId={id} tab={vaultTab(tab)} user={user} />
      )}
      {section === "add-service" && <AddService ctx={parseAddServiceContext(id, query)} user={user} />}
      {section === "bundles" && !id && <Bundles user={user} />}
      {section === "bundles" && id === "new" && <BundleFormPage ctx={parseBundleFormContext(undefined, query)} />}
      {section === "bundles" && id && id !== "new" && tab === "edit" && (
        <BundleFormPage key={id} ctx={parseBundleFormContext(id, query)} />
      )}
      {section === "bundles" && id && id !== "new" && tab !== "edit" && (
        <BundleDetail bundleId={id} tab={bundleTab(tab)} user={user} />
      )}
      {section === "sessions" && !id && <Sessions me={user} />}
      {section === "sessions" && id && <SessionPage sessionId={id} user={user} />}
      {section === "variables" && <Variables isAdmin={isAdmin} />}
      {section === "templates" && <Templates user={user} />}
      {section === "people" && <People me={user} />}
      {section === "api-keys" && <ApiKeys />}
      {section === "proxies" && !id && <Nodes />}
      {section === "proxies" && id && <ProxyDetail nodeId={id} />}
      {section === "audit" && <Audit me={user} />}
      {section === "settings" && !id && <Settings />}
      {section === "settings" && id === "sso" && tab === "new" && <ProviderFormPage />}
      {section === "settings" && id === "sso" && tab && tab !== "new" && <ProviderFormPage key={tab} providerId={tab} />}
      {section === "account" && <Account user={user} sso={boot.session.sso} onChanged={() => void load()} />}
      <StepUpDialog
        open={stepUpOpen}
        totpEnrolled={user.totp_enrolled}
        sso={boot.session.sso}
        ssoError={ssoError}
        onResult={finishStepUp}
      />
    </Shell>
  );
}

// ----- shell -------------------------------------------------------------------

type Alerts = Partial<Record<string, "critical" | "warning">>;

const ALERT_POLL_MS = 30_000;

/**
 * Sections that need someone to act, so the sidebar can say so from any
 * page. Only admins manage proxies, so only they are asked.
 */
function useSectionAlerts(isAdmin: boolean): Alerts {
  const [alerts, setAlerts] = useState<Alerts>({});
  useEffect(() => {
    if (!isAdmin) return;
    let cancelled = false;
    const check = async () => {
      try {
        const nodes = await get<Page<NodeInfo>>("/nodes?page_size=100");
        const attention = proxyAttention(nodes.items, new Date());
        if (!cancelled) setAlerts(attention.level === "ok" ? {} : { proxies: attention.level });
      } catch {
        // The Proxies page reports its own errors; the sidebar stays quiet.
      }
    };
    void check();
    const timer = window.setInterval(() => void check(), ALERT_POLL_MS);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [isAdmin]);
  return alerts;
}

function Shell({
  section,
  user,
  onLogout,
  children,
}: {
  section: string;
  user: UserSummary;
  onLogout: () => void;
  children: ReactNode;
}) {
  const [mobileOpen, setMobileOpen] = useState(false);
  const [crumbs, setCrumbs] = useState<Crumb[] | null>(null);
  const [theme, setTheme] = useTheme();
  const [collapsed, toggleCollapsed] = useSidebarCollapsed();
  const alerts = useSectionAlerts(user.role === "admin");
  const sidebar = (iconsOnly: boolean) => (
    <SidebarContent
      section={section}
      user={user}
      alerts={alerts}
      collapsed={iconsOnly}
      onLogout={onLogout}
      onNavigate={() => setMobileOpen(false)}
    />
  );

  return (
    <BreadcrumbContext.Provider value={setCrumbs}>
    <TooltipProvider delayDuration={200}>
      <div className="flex min-h-svh w-full">
        <aside
          data-collapsed={collapsed}
          className={cn(
            "sticky top-0 hidden h-svh shrink-0 flex-col border-r bg-sidebar text-sidebar-foreground transition-[width] duration-200 md:flex",
            collapsed ? "w-14" : "w-64",
          )}
        >
          {sidebar(collapsed)}
        </aside>
        <DialogPrimitive.Root open={mobileOpen} onOpenChange={setMobileOpen}>
          <DialogPrimitive.Portal>
            <DialogPrimitive.Overlay className="fixed inset-0 z-50 bg-black/60 data-[state=open]:animate-in data-[state=open]:fade-in-0 md:hidden" />
            <DialogPrimitive.Content className="fixed inset-y-0 left-0 z-50 flex w-72 flex-col border-r bg-sidebar text-sidebar-foreground data-[state=open]:animate-in data-[state=open]:slide-in-from-left md:hidden">
              <DialogPrimitive.Title className="sr-only">Navigation</DialogPrimitive.Title>
              <DialogPrimitive.Description className="sr-only">Sections of the console</DialogPrimitive.Description>
              {sidebar(false)}
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
            <Tooltip>
              <TooltipTrigger asChild>
                <Button
                  type="button"
                  variant="ghost"
                  size="icon"
                  className="hidden size-8 md:inline-flex"
                  aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
                  aria-expanded={!collapsed}
                  onClick={toggleCollapsed}
                >
                  {collapsed ? <PanelLeftOpen /> : <PanelLeftClose />}
                </Button>
              </TooltipTrigger>
              <TooltipContent side="bottom">
                {collapsed ? "Expand sidebar" : "Collapse sidebar"} <kbd className="ml-1 text-xs text-muted-foreground">{shortcutLabel()}</kbd>
              </TooltipContent>
            </Tooltip>
            <Breadcrumbs crumbs={trail(LABELS[section] ?? section, crumbs)} />
            <div className="ml-auto">
              <ThemeToggle theme={theme} onChange={setTheme} />
            </div>
          </header>
          <main className="min-w-0 flex-1">{children}</main>
        </div>
      </div>
    </TooltipProvider>
    </BreadcrumbContext.Provider>
  );
}

/**
 * The header trail. On narrow screens only the parent and the current page
 * show; the rest of the way back is in the sidebar.
 */
function Breadcrumbs({ crumbs }: { crumbs: Crumb[] }) {
  const last = crumbs.length - 1;
  return (
    <nav aria-label="Breadcrumb" className="min-w-0">
      <ol className="flex min-w-0 items-center gap-1.5 text-sm">
        {crumbs.map((c, i) => (
          <li key={i} className={cn("flex min-w-0 items-center gap-1.5", i < last - 1 && "hidden sm:flex")}>
            {i > 0 && (
              <ChevronRight
                aria-hidden
                className={cn("size-3.5 shrink-0 text-muted-foreground", i === last - 1 && "hidden sm:block")}
              />
            )}
            {c.label === null ? (
              <Skeleton className="h-4 w-24" />
            ) : i === last ? (
              <span aria-current="page" className="truncate font-medium">
                {c.label}
              </span>
            ) : c.href ? (
              <a href={c.href} className="truncate text-muted-foreground hover:text-foreground">
                {c.label}
              </a>
            ) : (
              <span className="truncate text-muted-foreground">{c.label}</span>
            )}
          </li>
        ))}
      </ol>
    </nav>
  );
}

function shortcutLabel(): string {
  return /Mac|iPhone|iPad/.test(navigator.platform) ? "⌘B" : "Ctrl+B";
}

/** In the icon-only sidebar, a control's name shows as a tooltip to its right. */
function SideTip({ label, show, children }: { label: string; show: boolean; children: ReactNode }) {
  if (!show) return <>{children}</>;
  return (
    <Tooltip>
      <TooltipTrigger asChild>{children}</TooltipTrigger>
      <TooltipContent side="right">{label}</TooltipContent>
    </Tooltip>
  );
}

function SidebarContent({
  section,
  user,
  alerts,
  collapsed,
  onLogout,
  onNavigate,
}: {
  section: string;
  user: UserSummary;
  alerts: Alerts;
  /** Icons only, each named by a tooltip. */
  collapsed: boolean;
  onLogout: () => void;
  onNavigate: () => void;
}) {
  const role = user.role.replace("_", " ");
  return (
    <>
      <div className={cn("flex h-16 shrink-0 items-center gap-2 border-b", collapsed ? "justify-center px-2" : "px-4")}>
        <BrandMark />
        {!collapsed && (
          <div className="min-w-0 leading-tight">
            <div className="truncate text-sm font-semibold">Tokenless</div>
            <div className="truncate text-xs text-sidebar-foreground/70">Console</div>
          </div>
        )}
      </div>
      <nav aria-label="Sections" className="flex-1 overflow-y-auto overflow-x-hidden p-2">
        {NAV.map((g, i) => (
          <div key={g.group} className="mb-2">
            {collapsed ? (
              i > 0 && <div role="separator" aria-label={g.group} className="mx-2 my-2 border-t" />
            ) : (
              <div className="flex h-8 items-center px-2 text-xs font-medium text-sidebar-foreground/70">{g.group}</div>
            )}
            <ul className="flex flex-col gap-1">
              {g.items.map((item) => {
                const active = section === item.key;
                const alert = alerts[item.key];
                const name = alert ? `${item.label} (needs attention)` : item.label;
                return (
                  <li key={item.key}>
                    <SideTip label={name} show={collapsed}>
                      <a
                        href={`#/${item.key}`}
                        onClick={onNavigate}
                        data-active={active}
                        aria-current={active ? "page" : undefined}
                        aria-label={collapsed || alert ? name : undefined}
                        className={cn(
                          "relative flex h-8 w-full items-center gap-2 rounded-md p-2 text-sm outline-none ring-sidebar-ring transition-colors hover:bg-sidebar-accent hover:text-sidebar-accent-foreground focus-visible:ring-2 data-[active=true]:bg-sidebar-accent data-[active=true]:font-medium data-[active=true]:text-sidebar-accent-foreground [&>svg]:size-4 [&>svg]:shrink-0",
                          collapsed && "justify-center",
                        )}
                      >
                        <item.icon />
                        {!collapsed && <span className="truncate">{item.label}</span>}
                        {alert && (
                          <span
                            aria-hidden="true"
                            className={cn(
                              "size-2 shrink-0 rounded-full",
                              alert === "critical" ? "bg-destructive" : "bg-warning",
                              collapsed ? "absolute right-1.5 top-1.5" : "ml-auto",
                            )}
                          />
                        )}
                      </a>
                    </SideTip>
                  </li>
                );
              })}
            </ul>
          </div>
        ))}
      </nav>
      <div className={cn("flex items-center gap-2 border-t p-3", collapsed && "flex-col px-2")}>
        <SideTip label={`Account · ${user.username}`} show={collapsed}>
          <a
            href="#/account"
            onClick={onNavigate}
            aria-current={section === "account" ? "page" : undefined}
            aria-label={collapsed ? `Account, ${user.username}, ${role}` : undefined}
            className={cn(
              "flex min-w-0 items-center gap-2 rounded-md p-1 outline-none ring-sidebar-ring transition-colors hover:bg-sidebar-accent focus-visible:ring-2",
              !collapsed && "-m-1 flex-1",
              section === "account" && "bg-sidebar-accent",
            )}
          >
            <span className="flex size-8 shrink-0 items-center justify-center rounded-full bg-sidebar-accent text-xs font-semibold uppercase">
              {user.username.slice(0, 2)}
            </span>
            {!collapsed && (
              <span className="min-w-0 flex-1 leading-tight">
                <span className="block truncate text-sm font-medium">{user.username}</span>
                <span className="block truncate text-xs text-sidebar-foreground/70">{role}</span>
              </span>
            )}
          </a>
        </SideTip>
        <SideTip label="Sign out" show={collapsed}>
          <Button
            type="button"
            variant="ghost"
            size="icon"
            className="size-8"
            aria-label="Sign out"
            title={collapsed ? undefined : "Sign out"}
            onClick={onLogout}
          >
            <LogOut />
          </Button>
        </SideTip>
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
