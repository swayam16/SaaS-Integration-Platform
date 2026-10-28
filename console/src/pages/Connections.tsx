import { useState } from "react";
import { api, can, type Connection, type Me } from "../api";
import { ago } from "../format";
import { useData } from "../hooks";

type Provider = "salesforce" | "slack";

const INFO: Record<Provider, { name: string; what: string; scopes: string }> = {
  salesforce: {
    name: "Salesforce",
    what: "Reads Cases and writes Case messages and button actions back to your org.",
    scopes: "Access the API, refresh token (offline access)",
  },
  slack: {
    name: "Slack",
    what: "Posts one message per Case to your support channel and reads replies in those threads.",
    scopes: "Post messages, read channel history, read user names",
  },
};

export function Connections({ me, query }: { me: Me; query: URLSearchParams }) {
  const { data, error, reload } = useData<Record<Provider, Connection | null>>("/api/connections");
  const [busy, setBusy] = useState<Provider | null>(null);
  const [failure, setFailure] = useState<string | null>(null);
  const just = query.get("connected") as Provider | null;
  const denied = query.get("error");

  const connect = async (p: Provider) => {
    setBusy(p);
    try {
      const { url } = await api<{ url: string }>(`/api/connections/${p}/start`, { method: "POST", body: "{}" });
      window.location.href = url;
    } catch (e) {
      setFailure((e as Error).message);
      setBusy(null);
    }
  };

  const disconnect = async (p: Provider) => {
    if (!window.confirm(`Disconnect ${INFO[p].name}? Syncing stops until it’s connected again.`)) return;
    setBusy(p);
    await api(`/api/connections/${p}`, { method: "DELETE" }).catch((e) => setFailure((e as Error).message));
    setBusy(null);
    reload();
  };

  return (
    <>
      <header className="page-head">
        <h1>Connections</h1>
        <p className="muted">SyncBridge signs in to each app with OAuth. Tokens are encrypted with your AWS KMS key.</p>
      </header>
      {just && <p className="notice" role="status">Connected {INFO[just]?.name ?? just}.</p>}
      {denied && <p className="error">The connection was cancelled before it finished.</p>}
      {failure && <p className="error">{failure}</p>}
      {error && <p className="error">Couldn’t load connections: {error}</p>}
      <div className="connections">
        {(["salesforce", "slack"] as Provider[]).map((p) => {
          const c = data?.[p];
          return (
            <section key={p} className="conn">
              <div className="conn-head">
                <h2>{INFO[p].name}</h2>
                <span className={`status ${c ? "ok" : "off"}`}>{c ? "Connected" : "Not connected"}</span>
              </div>
              <p>{INFO[p].what}</p>
              {c && (
                <dl className="facts small">
                  <dt>{p === "salesforce" ? "Org" : "Workspace"}</dt>
                  <dd>{p === "salesforce" ? c.instance_url : `${c.team_name ?? ""} (${c.team_id})`}</dd>
                  <dt>Connected by</dt>
                  <dd>
                    {c.connected_by}, {ago(c.connected_at)}
                  </dd>
                </dl>
              )}
              <p className="fine">Permissions requested: {INFO[p].scopes}.</p>
              {can(me, "admin") ? (
                <div className="row">
                  <button className={`button ${c ? "" : "primary"}`} onClick={() => connect(p)} disabled={busy !== null}>
                    {c ? "Reconnect" : `Connect ${INFO[p].name}`}
                  </button>
                  {c && (
                    <button className="button quiet" onClick={() => disconnect(p)} disabled={busy !== null}>
                      Disconnect
                    </button>
                  )}
                </div>
              ) : (
                <p className="fine">Only admins can change connections.</p>
              )}
            </section>
          );
        })}
      </div>
    </>
  );
}
