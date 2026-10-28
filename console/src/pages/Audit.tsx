import type { AuditEntry } from "../api";
import { auditAction, when } from "../format";
import { useData } from "../hooks";

export function AuditPage() {
  const { data, error } = useData<AuditEntry[]>("/api/audit?limit=200", 15000);
  return (
    <>
      <header className="page-head">
        <h1>Audit log</h1>
        <p className="muted">Sign-ins, provisioning from Okta, connection and settings changes. Kept for one year.</p>
      </header>
      {error && <p className="error">Couldn’t load the audit log: {error}</p>}
      {data && data.length === 0 && <p className="empty">No entries yet.</p>}
      {data && data.length > 0 && (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>When</th>
                <th>Who</th>
                <th>What</th>
                <th>Details</th>
              </tr>
            </thead>
            <tbody>
              {data.map((a, i) => (
                <tr key={`${a.at}-${i}`} className={a.action.includes("fail") || a.action.includes("denied") ? "flagged" : ""}>
                  <td className="nowrap">{when(a.at)}</td>
                  <td>{a.actor}</td>
                  <td>
                    {auditAction(a.action)}
                    {a.target && <span className="muted"> {a.target}</span>}
                  </td>
                  <td className="reason">
                    {Object.entries(a.detail)
                      .map(([k, v]) => `${k.replace(/_/g, " ")}: ${String(v)}`)
                      .join("; ")}
                    {a.ip && <span className="muted"> from {a.ip}</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}
