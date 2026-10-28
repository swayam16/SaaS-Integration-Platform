import { useState } from "react";
import { api, can, type DeadLetter, type Me } from "../api";
import { when } from "../format";
import { useData } from "../hooks";

export function DeadLetters({ me }: { me: Me }) {
  const { data, error, reload } = useData<DeadLetter[]>("/api/deadletters", 10000);
  const [busy, setBusy] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const act = async (id: string, kind: "replay" | "discard") => {
    setBusy(id);
    try {
      if (kind === "replay") await api(`/api/deadletters/${encodeURIComponent(id)}/replay`, { method: "POST", body: "{}" });
      else await api(`/api/deadletters/${encodeURIComponent(id)}`, { method: "DELETE" });
      setNotice(kind === "replay" ? "Sent back to the queue. It will sync within a minute." : "Discarded.");
    } catch (e) {
      setNotice((e as Error).message);
    }
    setBusy(null);
    reload();
  };

  const replayAll = async () => {
    setBusy("all");
    const r = await api<{ replayed: number }>("/api/deadletters/replay-all", { method: "POST", body: "{}" }).catch(
      (e) => ({ replayed: -1, error: (e as Error).message }),
    );
    setNotice(r.replayed >= 0 ? `Retried ${r.replayed} records.` : "Retry failed.");
    setBusy(null);
    reload();
  };

  return (
    <>
      <header className="page-head">
        <h1>Failed syncs</h1>
        <p className="muted">
          Records the sync gave up on after repeated retries. Retrying is always safe: a record that already synced won’t be
          written twice.
        </p>
      </header>
      {notice && (
        <p className="notice" role="status">
          {notice}
        </p>
      )}
      {error && <p className="error">Couldn’t load failed syncs: {error}</p>}
      {data && data.length === 0 && <p className="empty">No failed syncs. Records that can’t be synced will show up here.</p>}
      {data && data.length > 0 && (
        <>
          <div className="toolbar">
            <span className="muted">{data.length} waiting</span>
            {can(me, "operator") && (
              <button className="button" onClick={replayAll} disabled={busy !== null}>
                Retry all
              </button>
            )}
          </div>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Failed</th>
                  <th>Record</th>
                  <th>Why</th>
                  <th className="num">Attempts</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {data.map((d) => (
                  <tr key={d.id}>
                    <td className="nowrap">{when(d.created_at)}</td>
                    <td>{d.summary}</td>
                    <td className="reason">{d.reason}</td>
                    <td className="num">{d.receive_count}</td>
                    <td className="actions">
                      {can(me, "operator") && (
                        <button className="button small" onClick={() => act(d.id, "replay")} disabled={busy !== null}>
                          Retry
                        </button>
                      )}
                      {can(me, "admin") && (
                        <button className="button small quiet" onClick={() => act(d.id, "discard")} disabled={busy !== null}>
                          Discard
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {!can(me, "operator") && <p className="fine">Operators and admins can retry failed syncs.</p>}
        </>
      )}
    </>
  );
}
