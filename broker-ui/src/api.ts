// SPDX-FileCopyrightText: 2026 credential-broker contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// Typed client for /api/v1. Cookies carry the session; mutating requests
// add the CSRF token. A `step_up_required` problem triggers the step-up
// prompt and the request is retried once.

export type Role = "admin" | "editor" | "viewer" | "session_issuer";

export interface Problem {
  title: string;
  status: number;
  detail: string;
  code: string;
  retry_after_secs?: number;
}

export class ApiError extends Error {
  readonly problem: Problem;
  constructor(problem: Problem) {
    super(problem.detail);
    this.problem = problem;
  }
}

export interface Page<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
}

export interface UserSummary {
  id: string;
  username: string;
  role: Role;
  created_at: string;
  disabled_at: string | null;
  totp_enrolled: boolean;
}

export interface Invite {
  id: string;
  role: Role;
  created_by: string;
  created_at: string;
  expires_at: string;
  accepted_at: string | null;
  accepted_by: string | null;
  revoked_at: string | null;
}

export interface InviteInfo {
  role: Role;
  expires_at: string;
}

export interface SessionInfo {
  user: UserSummary;
  csrf_token: string;
  expires_at: string;
  step_up_at: string | null;
}

export interface Vault {
  id: string;
  name: string;
  scope: string;
  created_at: string;
}

export interface CredentialField {
  name: string;
  label: string;
  description: string;
  required: boolean;
}

export type Injection =
  | { method: "bearer"; field: string }
  | { method: "basic"; username_field: string; password_field: string }
  | { method: "header"; name: string; field: string; prefix?: string };

export interface ServiceTemplate {
  id: string;
  version: number;
  name: string;
  description: string;
  hosts: string[];
  allow: { paths: string[]; methods: string[] };
  credential_fields: CredentialField[];
  injection: Injection;
  validation?: { method: string; path: string; expect_status: number[] };
  host_override: { allowed: boolean; required: boolean; label?: string };
  oauth?: { token_url: string; refresh_token_single_use: boolean; honour_expires_in: boolean };
}

export interface StoredTemplate {
  template: ServiceTemplate;
  yaml: string;
  source: "builtin" | "imported";
  status: "approved" | "pending_approval";
  imported_by: string | null;
  approved_by: string | null;
  created_at: string;
}

export interface CredentialMeta {
  id: string;
  vault_id: string;
  name: string;
  template_id: string;
  template_version: number;
  host_override: string[];
  field_names: string[];
  created_by: string;
  created_at: string;
  updated_at: string;
}

export interface Rule {
  id: string;
  vault_id: string;
  credential_id: string;
  name: string;
  allow: { hosts: string[]; paths: string[]; methods: string[] };
  enabled: boolean;
  created_by: string;
  created_at: string;
  updated_at: string;
}

export interface ProxySession {
  id: string;
  vault_id: string;
  rule_ids: string[];
  labels: Record<string, string>;
  request_limit: number | null;
  created_by: string;
  created_at: string;
  expires_at: string;
  revoked_at: string | null;
}

export interface ApiKey {
  id: string;
  name: string;
  prefix: string;
  vault_id: string;
  role: Role;
  created_by: string;
  created_at: string;
  expires_at: string;
  revoked_at: string | null;
  last_used_at: string | null;
}

export interface NodeInfo {
  id: string;
  name: string;
  seal_public_key: string;
  cert_serial: string;
  cert_not_after: string;
  enrolled_at: string;
  last_seen_at: string | null;
  revoked_at: string | null;
}

export interface AuditEvent {
  id: string;
  at: string;
  actor: string;
  action: string;
  outcome: string;
  vault_id?: string;
  target?: string;
  detail: Record<string, string>;
}

export interface EgressPolicy {
  block_private: boolean;
  allow: string[];
}

export interface Settings {
  unmatched_host_policy: "passthrough" | "deny";
  egress: EgressPolicy;
}

export interface CredentialValidation {
  credential_id: string;
  ok: boolean;
  host: string;
  method: string;
  path: string;
  status: number | null;
  expected_status: number[];
  detail: string;
}

let csrfToken: string | null = null;
export function setCsrfToken(token: string | null): void {
  csrfToken = token;
}

type StepUpHandler = () => Promise<boolean>;
let stepUpHandler: StepUpHandler | null = null;
export function setStepUpHandler(handler: StepUpHandler | null): void {
  stepUpHandler = handler;
}

function toProblem(status: number, statusText: string, text: string): Problem {
  try {
    const parsed: unknown = JSON.parse(text);
    if (parsed && typeof parsed === "object" && "code" in parsed && "detail" in parsed) {
      return parsed as Problem;
    }
  } catch {
    // not JSON; fall through
  }
  return { title: statusText, status, detail: text || statusText, code: "http_error" };
}

export async function api<T>(method: string, path: string, body?: unknown, retried = false): Promise<T> {
  const headers: Record<string, string> = {};
  if (body !== undefined) headers["content-type"] = "application/json";
  if (csrfToken && method !== "GET") headers["x-csrf-token"] = csrfToken;
  const response = await fetch(`/api/v1${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
    credentials: "same-origin",
    cache: "no-store",
  });
  const text = await response.text();
  if (!response.ok) {
    const problem = toProblem(response.status, response.statusText, text);
    if (problem.code === "step_up_required" && !retried && stepUpHandler) {
      if (await stepUpHandler()) return api<T>(method, path, body, true);
    }
    throw new ApiError(problem);
  }
  if (response.status === 204 || text === "") return undefined as T;
  return JSON.parse(text) as T;
}

export const get = <T,>(path: string) => api<T>("GET", path);
export const post = <T,>(path: string, body: unknown = {}) => api<T>("POST", path, body);
export const put = <T,>(path: string, body: unknown) => api<T>("PUT", path, body);
export const patch = <T,>(path: string, body: unknown) => api<T>("PATCH", path, body);
export const del = (path: string) => api<void>("DELETE", path);

export function errorMessage(e: unknown): string {
  if (e instanceof ApiError) return `${e.problem.title}: ${e.problem.detail}`;
  if (e instanceof Error) return e.message;
  return String(e);
}
