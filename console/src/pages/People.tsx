import type { Person } from "../api";
import { useData } from "../hooks";

const ROLE: Record<Person["role"], string> = { admin: "Admin", operator: "Operator", viewer: "Viewer" };

export function People() {
  const { data, error } = useData<Person[]>("/api/users");
  return (
    <>
      <header className="page-head">
        <h1>People</h1>
        <p className="muted">
          Provisioned from Okta with SCIM. Roles follow Okta groups: SyncBridge Admins, Operators and Viewers. To change
          who has access, assign the app or move people between groups in Okta.
        </p>
      </header>
      {error && <p className="error">Couldn’t load people: {error}</p>}
      {data && data.length === 0 && (
        <p className="empty">No one is provisioned yet. Assign the SyncBridge app to people in Okta to give them access.</p>
      )}
      {data && data.length > 0 && (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Email</th>
                <th>Role</th>
                <th>Okta groups</th>
                <th>Access</th>
              </tr>
            </thead>
            <tbody>
              {data.map((p) => (
                <tr key={p.id} className={p.active ? "" : "quiet"}>
                  <td>{p.name}</td>
                  <td>{p.userName}</td>
                  <td>{ROLE[p.role]}</td>
                  <td>{p.groups.join(", ") || <span className="muted">None</span>}</td>
                  <td>{p.active ? "Active" : "Deactivated in Okta"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}
