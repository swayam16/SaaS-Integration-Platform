export type Role = "viewer" | "operator" | "admin";

export interface Me {
  authenticated: true;
  email: string;
  name: string;
  role: Role;
  csrf: string;
  expires: number;
  environment: string;
}

export interface Connection {
  connected_at?: number;
  connected_by?: string;
  updated_at?: number;
  instance_url?: string;
  org_id?: string;
  team_id?: string;
  team_name?: string;
  scope?: string;
}

export interface Overview {
  connections: { salesforce: Connection | null; slack: Connection | null };
  totals_24h: Record<string, number>;
  series: { hour: string; events: number; dead_lettered: number }[];
  dead_letters: number;
  queue_depth: number | null;
  lag_ms_p50: number | null;
  lag_ms_p95: number | null;
  reconcile: { last_run?: number; last_enqueued?: number; last_scanned?: number };
  breakers: { salesforce: string; slack: string };
  settings: { channel_id?: string; instance_url?: string };
}

export interface Activity {
  direction: "sf_to_slack" | "slack_to_sf";
  object: string;
  record: string;
  outcome: string;
  at: number;
  lag_ms: number;
}

export interface DeadLetter {
  id: string;
  reason: string;
  summary: string;
  receive_count: number;
  created_at: number;
}

export interface AuditEntry {
  at: number;
  actor: string;
  action: string;
  target: string;
  detail: Record<string, unknown>;
  ip: string;
}

export interface Person {
  id: string;
  userName: string;
  name: string;
  active: boolean;
  groups: string[];
  role: Role;
  created: string;
}

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}

let csrfToken = "";

export function setCsrf(token: string): void {
  csrfToken = token;
}

export async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const method = (init.method ?? "GET").toUpperCase();
  const headers = new Headers(init.headers);
  if (method !== "GET") {
    headers.set("X-CSRF-Token", csrfToken);
    if (init.body) headers.set("Content-Type", "application/json");
  }
  const resp = await fetch(path, { ...init, headers, credentials: "same-origin" });
  const text = await resp.text();
  const data = text ? JSON.parse(text) : null;
  if (!resp.ok) {
    throw new ApiError(resp.status, (data && (data.error as string)) || `Request failed (${resp.status})`);
  }
  return data as T;
}

export const ROLE_RANK: Record<Role, number> = { viewer: 1, operator: 2, admin: 3 };

export function can(me: Me, role: Role): boolean {
  return ROLE_RANK[me.role] >= ROLE_RANK[role];
}
