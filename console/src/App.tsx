import { useEffect, useState } from "react";
import { api, ApiError, can, type Me, type Role, setCsrf } from "./api";
import { useHashRoute } from "./hooks";
import { Overview } from "./pages/Overview";
import { ActivityPage } from "./pages/Activity";
import { DeadLetters } from "./pages/DeadLetters";
import { Connections } from "./pages/Connections";
import { SettingsPage } from "./pages/Settings";
import { AuditPage } from "./pages/Audit";
import { People } from "./pages/People";

const NAV: { path: string; label: string; role: Role }[] = [
  { path: "/overview", label: "Overview", role: "viewer" },
  { path: "/activity", label: "Activity", role: "viewer" },
  { path: "/deadletters", label: "Failed syncs", role: "viewer" },
  { path: "/connections", label: "Connections", role: "viewer" },
  { path: "/settings", label: "Settings", role: "viewer" },
  { path: "/audit", label: "Audit log", role: "admin" },
  { path: "/people", label: "People", role: "admin" },
];

const ROLE_LABEL: Record<Role, string> = { viewer: "Viewer", operator: "Operator", admin: "Admin" };

export function App() {
  const [me, setMe] = useState<Me | null | "signed-out">(null);
  const [path, query] = useHashRoute();

  useEffect(() => {
    api<Me>("/api/me")
      .then((m) => {
        setCsrf(m.csrf);
        setMe(m);
      })
      .catch((e) => setMe(e instanceof ApiError && e.status === 401 ? "signed-out" : null));
  }, []);

  if (me === null) return <div className="boot" aria-busy="true" />;
  if (me === "signed-out") return <SignIn />;

  const signOut = async () => {
    await api("/api/logout", { method: "POST", body: "{}" }).catch(() => undefined);
    window.location.href = "/";
  };
  const allowed = NAV.filter((n) => can(me, n.role));
  const current = allowed.find((n) => n.path === path) ? path : "/overview";

  return (
    <div className="shell">
      <aside className="nav">
        <a className="brand" href="#/overview" aria-label="SyncBridge home">
          <Mark />
          <span>SyncBridge</span>
        </a>
        <nav aria-label="Main">
          {allowed.map((n) => (
            <a key={n.path} href={`#${n.path}`} aria-current={current === n.path ? "page" : undefined}>
              {n.label}
            </a>
          ))}
        </nav>
        <div className="who">
          <span className="who-name">{me.name}</span>
          <span className="who-role">{ROLE_LABEL[me.role]}</span>
          <button className="link" onClick={signOut}>
            Sign out
          </button>
        </div>
      </aside>
      <main className="page" id="main">
        {current === "/overview" && <Overview me={me} />}
        {current === "/activity" && <ActivityPage />}
        {current === "/deadletters" && <DeadLetters me={me} />}
        {current === "/connections" && <Connections me={me} query={query} />}
        {current === "/settings" && <SettingsPage me={me} />}
        {current === "/audit" && <AuditPage />}
        {current === "/people" && <People />}
      </main>
    </div>
  );
}

function SignIn() {
  const next = encodeURIComponent(window.location.pathname + window.location.hash);
  return (
    <div className="signin">
      <div className="signin-box">
        <Mark size={40} />
        <h1>SyncBridge</h1>
        <p>Salesforce and Slack, kept in step. Sign in with your company account to manage the sync.</p>
        <a className="button primary" href={`/saml/login?next=${next}`}>
          Sign in with Okta
        </a>
        <p className="fine">Access is managed by your Okta administrator.</p>
      </div>
    </div>
  );
}

export function Mark({ size = 24 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" aria-hidden="true">
      <rect width="32" height="32" rx="7" fill="var(--ink)" />
      <path
        d="M7 12h14l-3-3M25 20H11l3 3"
        fill="none"
        stroke="var(--signal-light)"
        strokeWidth="2.4"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}
