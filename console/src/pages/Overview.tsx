import { useState } from "react";
import { api, can, type Activity, type Me, type Overview as OverviewData } from "../api";
import { ago, ms, num } from "../format";
import { useData } from "../hooks";
import { ActivityTable } from "./Activity";

export function Overview({ me }: { me: Me }) {
  const { data: o, error, reload } = useData<OverviewData>("/api/overview", 5000);
  const { data: activity } = useData<Activity[]>("/api/activity?limit=8", 5000);
  if (error) return <p className="error">Couldn’t load the overview: {error}</p>;
  if (!o) return <p className="muted">Loading…</p>;

  const t = o.totals_24h;
  const toSlack = (t.sf_to_slack_creates ?? 0) + (t.sf_to_slack_updates ?? 0);
  const toSf = (t.slack_to_sf_messages ?? 0) + (t.slack_to_sf_actions ?? 0);

  return (
    <>
      <header className="page-head">
        <h1>Overview</h1>
        <p className="muted">Last 24 hours, refreshed every few seconds.</p>
      </header>

      <Relay o={o} toSlack={toSlack} toSf={toSf} />
      <Attention o={o} me={me} reload={reload} />

      <section className="split">
        <div>
          <h2>Records processed per hour</h2>
          <Throughput series={o.series} />
        </div>
        <div>
          <h2>Health</h2>
          <dl className="facts">
            <dt>Delivery delay</dt>
            <dd>
              {ms(o.lag_ms_p50)} typical, {ms(o.lag_ms_p95)} slowest 5%
            </dd>
            <dt>Waiting in queue</dt>
            <dd>{o.queue_depth == null ? "Managed by SQS" : num(o.queue_depth)}</dd>
            <dt>Duplicates caught</dt>
            <dd>{num(t.duplicates_suppressed ?? 0)} repeated notifications ignored</dd>
            <dt>Echoes skipped</dt>
            <dd>{num(t.echoes_suppressed ?? 0)} of our own writes not synced back</dd>
            <dt>Last reconciliation</dt>
            <dd>
              {ago(o.reconcile.last_run)}
              {o.reconcile.last_run != null && `, ${num(o.reconcile.last_enqueued ?? 0)} records re-sent`}
            </dd>
          </dl>
        </div>
      </section>

      <section>
        <div className="section-head">
          <h2>Latest activity</h2>
          <a href="#/activity">See all activity</a>
        </div>
        {activity && <ActivityTable rows={activity} compact />}
      </section>
    </>
  );
}

function Relay({ o, toSlack, toSf }: { o: OverviewData; toSlack: number; toSf: number }) {
  const sf = o.connections.salesforce;
  const sl = o.connections.slack;
  const host = sf?.instance_url ? new URL(sf.instance_url).host.replace(".my.salesforce.com", "") : null;
  const down = (b: string) => b === "open";
  return (
    <section className="relay" aria-label="Sync between Salesforce and Slack">
      <div className={`end ${sf ? "" : "off"}`}>
        <span className="end-name">Salesforce</span>
        <span className="end-detail">{sf ? host : "Not connected"}</span>
        {down(o.breakers.salesforce) && <span className="flag bad">Unreachable, retrying</span>}
      </div>
      <div className="lanes">
        <div className="lane">
          <span className="lane-count">{num(toSlack)}</span>
          <span className="lane-label">case changes posted to Slack</span>
          <span className="wire" data-dir="right" aria-hidden="true" />
        </div>
        <div className="lane">
          <span className="wire" data-dir="left" aria-hidden="true" />
          <span className="lane-count">{num(toSf)}</span>
          <span className="lane-label">replies and actions written to Salesforce</span>
        </div>
      </div>
      <div className={`end ${sl ? "" : "off"}`}>
        <span className="end-name">Slack</span>
        <span className="end-detail">
          {sl ? `${sl.team_name || sl.team_id}${o.settings.channel_id ? `, ${o.settings.channel_id}` : ""}` : "Not connected"}
        </span>
        {down(o.breakers.slack) && <span className="flag bad">Unreachable, retrying</span>}
      </div>
    </section>
  );
}

function Attention({ o, me, reload }: { o: OverviewData; me: Me; reload: () => void }) {
  const [busy, setBusy] = useState(false);
  const missing = [
    !o.connections.salesforce && "Salesforce isn’t connected",
    !o.connections.slack && "Slack isn’t connected",
    !o.settings.channel_id && "no Slack channel is chosen",
  ].filter(Boolean) as string[];

  if (missing.length) {
    return (
      <p className="attention warn">
        Sync is paused: {missing.join(", ")}.{" "}
        <a href={!o.settings.channel_id && o.connections.slack ? "#/settings" : "#/connections"}>Finish setup</a>
      </p>
    );
  }
  if (o.dead_letters > 0) {
    const replay = async () => {
      setBusy(true);
      await api("/api/deadletters/replay-all", { method: "POST", body: "{}" }).catch(() => undefined);
      setBusy(false);
      reload();
    };
    return (
      <p className="attention bad">
        {o.dead_letters === 1 ? "1 record" : `${num(o.dead_letters)} records`} couldn’t be synced and need a look.{" "}
        <a href="#/deadletters">Review failed syncs</a>
        {can(me, "operator") && (
          <>
            {" or "}
            <button className="link" onClick={replay} disabled={busy}>
              {busy ? "Retrying…" : "retry all now"}
            </button>
          </>
        )}
      </p>
    );
  }
  return <p className="attention ok">Everything is in sync. Nothing needs your attention.</p>;
}

function Throughput({ series }: { series: OverviewData["series"] }) {
  const max = Math.max(1, ...series.map((s) => s.events));
  const w = 24 * 14;
  return (
    <figure className="chart">
      <svg viewBox={`0 0 ${w} 100`} role="img" aria-label="Records processed in each of the last 24 hours">
        <line x1="0" x2={w} y1="99.5" y2="99.5" className="axis" />
        {series.map((s, i) => {
          const h = Math.max(s.events ? 2 : 0, (s.events / max) * 92);
          return (
            <g key={s.hour}>
              <rect x={i * 14 + 2} y={100 - h} width="10" height={h} rx="1.5" className={s.dead_lettered ? "bar bad" : "bar"}>
                <title>
                  {s.hour.slice(11)}:00 UTC: {num(s.events)} records{s.dead_lettered ? `, ${s.dead_lettered} failed` : ""}
                </title>
              </rect>
            </g>
          );
        })}
      </svg>
      <figcaption>
        <span>24 h ago</span>
        <span>Peak {num(max)} per hour</span>
        <span>Now</span>
      </figcaption>
    </figure>
  );
}
