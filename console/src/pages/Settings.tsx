import { type FormEvent, useEffect, useState } from "react";
import { api, can, type Me } from "../api";
import { useData } from "../hooks";

export function SettingsPage({ me }: { me: Me }) {
  const { data, reload } = useData<{ channel_id?: string }>("/api/settings");
  const [channel, setChannel] = useState("");
  const [status, setStatus] = useState<{ ok: boolean; text: string } | null>(null);
  const editable = can(me, "admin");
  const origin = window.location.origin;

  useEffect(() => setChannel(data?.channel_id ?? ""), [data]);

  const save = async (e: FormEvent) => {
    e.preventDefault();
    try {
      await api("/api/settings", { method: "PUT", body: JSON.stringify({ channel_id: channel.trim() }) });
      setStatus({ ok: true, text: "Channel saved. New and updated Cases post there from now on." });
      reload();
    } catch (err) {
      setStatus({ ok: false, text: (err as Error).message });
    }
  };

  return (
    <>
      <header className="page-head">
        <h1>Settings</h1>
      </header>
      <section className="narrow">
        <h2>Slack channel</h2>
        <form onSubmit={save} className="form">
          <label htmlFor="channel">Channel ID</label>
          <p className="fine" id="channel-help">
            In Slack, open the channel’s details; the ID is at the bottom and starts with C (or G for private channels).
            Invite the SyncBridge app to the channel first.
          </p>
          <div className="row">
            <input
              id="channel"
              value={channel}
              onChange={(e) => setChannel(e.target.value)}
              placeholder="C0123456789"
              aria-describedby="channel-help"
              disabled={!editable}
              spellCheck={false}
              autoComplete="off"
            />
            {editable && (
              <button className="button primary" type="submit" disabled={channel.trim() === (data?.channel_id ?? "")}>
                Save channel
              </button>
            )}
          </div>
          {status && <p className={status.ok ? "notice" : "error"}>{status.text}</p>}
          {!editable && <p className="fine">Only admins can change the channel.</p>}
        </form>
      </section>
      <section className="narrow">
        <h2>Endpoints for setup</h2>
        <p className="muted">Paste these into Salesforce, Slack and Okta as the setup guide describes.</p>
        <dl className="facts endpoints">
          <dt>Salesforce notifications</dt>
          <dd><Copyable value={`${origin}/webhooks/salesforce`} /></dd>
          <dt>Slack event subscriptions</dt>
          <dd><Copyable value={`${origin}/webhooks/slack/events`} /></dd>
          <dt>Slack interactivity</dt>
          <dd><Copyable value={`${origin}/webhooks/slack/interactivity`} /></dd>
          <dt>Okta single sign-on URL</dt>
          <dd><Copyable value={`${origin}/saml/acs`} /></dd>
          <dt>Okta audience URI</dt>
          <dd><Copyable value={`${origin}/saml/metadata`} /></dd>
          <dt>Okta SCIM base URL</dt>
          <dd><Copyable value={`${origin}/scim/v2`} /></dd>
        </dl>
      </section>
    </>
  );
}

function Copyable({ value }: { value: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <span className="copyable">
      <code>{value}</code>
      <button
        className="link"
        onClick={async () => {
          await navigator.clipboard?.writeText(value);
          setCopied(true);
          window.setTimeout(() => setCopied(false), 1500);
        }}
      >
        {copied ? "Copied" : "Copy"}
      </button>
    </span>
  );
}
