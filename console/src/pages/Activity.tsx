import { useState } from "react";
import type { Activity } from "../api";
import { isQuiet, ms, outcome, when } from "../format";
import { useData } from "../hooks";

type Filter = "all" | "sf_to_slack" | "slack_to_sf";

export function ActivityPage() {
  const [filter, setFilter] = useState<Filter>("all");
  const [showQuiet, setShowQuiet] = useState(true);
  const { data, error } = useData<Activity[]>("/api/activity?limit=200", 5000);
  const rows = (data ?? []).filter(
    (r) => (filter === "all" || r.direction === filter) && (showQuiet || !isQuiet(r.outcome)),
  );
  return (
    <>
      <header className="page-head">
        <h1>Activity</h1>
        <p className="muted">Every record the sync handled in the last 7 days, newest first.</p>
      </header>
      <div className="toolbar">
        <div className="segmented" role="group" aria-label="Direction">
          {(
            [
              ["all", "Both directions"],
              ["sf_to_slack", "Salesforce to Slack"],
              ["slack_to_sf", "Slack to Salesforce"],
            ] as [Filter, string][]
          ).map(([value, label]) => (
            <button key={value} aria-pressed={filter === value} onClick={() => setFilter(value)}>
              {label}
            </button>
          ))}
        </div>
        <label className="check">
          <input type="checkbox" checked={showQuiet} onChange={(e) => setShowQuiet(e.target.checked)} />
          Show skipped duplicates and echoes
        </label>
      </div>
      {error && <p className="error">Couldn’t load activity: {error}</p>}
      {data && rows.length === 0 && <p className="empty">Nothing here yet. New syncs appear within seconds.</p>}
      {rows.length > 0 && <ActivityTable rows={rows} />}
    </>
  );
}

export function ActivityTable({ rows, compact = false }: { rows: Activity[]; compact?: boolean }) {
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>When</th>
            <th>Direction</th>
            <th>Record</th>
            <th>Result</th>
            {!compact && <th className="num">Delay</th>}
          </tr>
        </thead>
        <tbody>
          {rows.map((r, i) => (
            <tr key={`${r.at}-${i}`} className={isQuiet(r.outcome) ? "quiet" : ""}>
              <td className="nowrap">{when(r.at)}</td>
              <td className="nowrap">
                <Direction d={r.direction} />
              </td>
              <td>
                <span className="obj">{objectName(r.object)}</span> <code>{r.record}</code>
              </td>
              <td>{outcome(r.direction, r.outcome)}</td>
              {!compact && <td className="num">{ms(r.lag_ms)}</td>}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Direction({ d }: { d: Activity["direction"] }) {
  return d === "sf_to_slack" ? (
    <span className="dir">
      Salesforce <Arrow /> Slack
    </span>
  ) : (
    <span className="dir">
      Slack <Arrow /> Salesforce
    </span>
  );
}

function Arrow() {
  return (
    <svg width="14" height="10" viewBox="0 0 14 10" aria-label="to" role="img">
      <path d="M1 5h11M8.5 1.5 12 5 8.5 8.5" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
    </svg>
  );
}

function objectName(o: string): string {
  return { Case: "Case", Case_Message__c: "Case message", message: "Thread reply", action: "Button" }[o] ?? o;
}
