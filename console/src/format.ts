const nf = new Intl.NumberFormat("en-US");

export const num = (n: number | null | undefined): string => (n == null ? "–" : nf.format(n));

export function ago(ts: number | undefined, now: number = Date.now() / 1000): string {
  if (!ts) return "never";
  const s = Math.max(0, Math.round(now - ts));
  if (s < 45) return "just now";
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  if (s < 86400) return `${Math.round(s / 3600)} h ago`;
  return `${Math.round(s / 86400)} d ago`;
}

export function when(ts: number): string {
  return new Date(ts * 1000).toLocaleString("en-US", {
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
    second: "2-digit",
  });
}

export function ms(n: number | null | undefined): string {
  if (n == null) return "–";
  return n < 1000 ? `${Math.round(n)} ms` : `${(n / 1000).toFixed(1)} s`;
}

const OUTCOMES: Record<string, string> = {
  created: "Created",
  updated: "Updated",
  unchanged: "No visible change",
  duplicate: "Duplicate ignored",
  skipped_stale: "Older change skipped",
  skipped_echo: "Own write, not echoed",
  ignored_not_case_thread: "Not a case thread",
  ignored_unknown_message: "Button on unknown message",
  ignored_unknown_action: "Unknown button",
};

export function outcome(direction: string, code: string): string {
  if (code === "created") return direction === "sf_to_slack" ? "Posted to Slack" : "Created in Salesforce";
  return OUTCOMES[code] ?? code.replace(/_/g, " ");
}

export function isQuiet(code: string): boolean {
  return code !== "created" && code !== "updated";
}

const ACTIONS: Record<string, string> = {
  "auth.login": "Signed in",
  "auth.logout": "Signed out",
  "auth.login_failed": "Sign-in failed",
  "auth.login_denied": "Sign-in refused",
  "settings.update": "Changed settings",
  "deadletter.replay": "Replayed a failed sync",
  "deadletter.replay_all": "Replayed all failed syncs",
  "deadletter.discard": "Discarded a failed sync",
  "sync.reconcile": "Ran a reconciliation",
  "scim.user.create": "Okta provisioned a user",
  "scim.user.update": "Okta updated a user",
  "scim.user.deactivate": "Okta deactivated a user",
  "scim.user.reactivate": "Okta reactivated a user",
  "scim.user.delete": "Okta deleted a user",
  "scim.group.create": "Okta pushed a group",
  "scim.group.update": "Okta updated a group",
  "scim.group.delete": "Okta removed a group",
};

export function auditAction(action: string): string {
  if (ACTIONS[action]) return ACTIONS[action];
  const m = action.match(/^connection\.(\w+)\.(\w+)$/);
  if (m) {
    const app = m[1] === "salesforce" ? "Salesforce" : "Slack";
    const verb = { connected: "Connected", disconnected: "Disconnected", failed: "Connection failed:", denied: "Connection declined:" }[m[2]] ?? m[2];
    return `${verb} ${app}`;
  }
  return action;
}
