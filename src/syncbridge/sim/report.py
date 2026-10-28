"""Markdown report for the failure harness."""

from __future__ import annotations

from .harness import ChaosReport


def _n(x: float) -> str:
    return f"{x:,.0f}" if isinstance(x, (int, float)) else str(x)


def markdown(main: ChaosReport, naive: ChaosReport | None = None) -> str:
    c, r, t, f, h, a = (
        main.config,
        main.records,
        main.traffic,
        main.faults,
        main.handling,
        main.audit,
    )
    sf_f, sl_f = f["salesforce_api"], f["slack_api"]
    lines = [
        "# Failure test report",
        "",
        f"Seed {c['seed']} · {_n(r['salesforce_cases'])} Salesforce Cases created over "
        f"{c['duration'] / 60:.0f} virtual minutes · run time {main.timing['wall_seconds']} s",
        "",
        "The real platform code (signed webhook routes, queue, worker, sync engine, API clients, "
        "reconciler) ran against the Salesforce and Slack simulators with faults injected at "
        "every layer. Afterwards both systems were audited record by record.",
        "",
        "## Result",
        "",
        "| Check | Result |",
        "|---|---:|",
        f"| Records synced (Cases + case messages both ways) | **{_n(r['total_records_synced'])}** |",
        f"| Duplicate Slack messages for a Case | **{a['duplicate_slack_case_messages']}** |",
        f"| Duplicate Slack thread replies | **{a['duplicate_slack_thread_replies']}** |",
        f"| Duplicate Case_Message__c records in Salesforce | "
        f"**{a['duplicate_salesforce_case_messages']}** |",
        f"| Cases missing in Slack | {a['cases_missing_in_slack']} |",
        f"| Slack replies missing in Salesforce | {a['slack_replies_missing_in_salesforce']} |",
        f"| Slack Case messages that differ from final Salesforce state | "
        f"{a['slack_cases_not_matching_salesforce']} |",
        f"| Salesforce case messages that differ from final Slack text | "
        f"{a['salesforce_messages_not_matching_slack']} |",
        "",
        "## What was synced",
        "",
        f"- {_n(r['salesforce_cases'])} Cases → one Slack message each, kept up to date through "
        f"{_n(t['salesforce_notifications'])} Salesforce change notifications",
        f"- {_n(r['case_messages_from_salesforce'])} agent messages from Salesforce → Slack "
        "thread replies",
        f"- {_n(r['case_messages_from_slack'])} Slack thread replies "
        f"(+{_n(r['slack_edits'])} edits) → Case_Message__c records",
        f"- {_n(r['slack_button_clicks'])} Slack button clicks (escalate / close / reopen) → "
        "Case updates",
        "",
        "## Faults injected",
        "",
        "| Layer | Fault | Count |",
        "|---|---|---:|",
        f"| Salesforce webhooks | delivered twice (callout retry) | "
        f"{_n(f['salesforce_webhooks'].get('duplicated', 0))} |",
        f"| Salesforce webhooks | never delivered | "
        f"{_n(f['salesforce_webhooks'].get('dropped', 0))} |",
        f"| Salesforce webhooks | delayed up to {c['max_delivery_delay']:.0f} s (reordered) | all |",
        f"| Slack events | redelivered (X-Slack-Retry-Num) | "
        f"{_n(f['slack_events'].get('duplicated', 0))} |",
        f"| Salesforce API | write committed, then timeout or 500 | "
        f"{_n(sf_f.get('timeout_after', 0) + sf_f.get('error_after', 0))} |",
        f"| Salesforce API | 503 / connection refused / row lock / limit | "
        f"{_n(sf_f.get('error_before', 0) + sf_f.get('connect_error', 0) + sf_f.get('lock_error', 0) + sf_f.get('rate_limit', 0))} |",
        f"| Salesforce API | full outage ({(c['salesforce_outage'][1] - c['salesforce_outage'][0]) / 60:.1f} min) | "
        f"{_n(sf_f.get('outage', 0))} calls refused |",
        f"| Salesforce API | access token expired | {f['salesforce_token_expiries']} |",
        f"| Slack API | message posted, then timeout or 500 | "
        f"{_n(sl_f.get('timeout_after', 0) + sl_f.get('error_after', 0))} |",
        f"| Slack API | 429 with Retry-After | {_n(sl_f.get('rate_limit', 0))} |",
        f"| Slack API | 503 / connection reset | "
        f"{_n(sl_f.get('error_before', 0) + sl_f.get('connect_error', 0))} |",
        f"| Slack API | full outage ({(c['slack_outage'][1] - c['slack_outage'][0]) / 60:.1f} min) | "
        f"{_n(sl_f.get('outage', 0))} calls refused |",
        f"| Worker | hard crash mid-message (no cleanup) | "
        f"{_n(sum(f['worker_crashes'].values()))} |",
        "",
        "## How the platform handled them",
        "",
        f"- **{_n(h['engine_outcomes'].get('duplicate', 0))}** duplicate deliveries recognised "
        "by idempotency key and acknowledged without a write",
        f"- **{_n(h['recovered_via_slack_metadata'])}** posts whose outcome was unknown "
        "(timeout after Slack accepted it, or a crash right after posting) found again "
        "through message metadata instead of being posted twice",
        f"- {_n(h['engine_outcomes'].get('skipped_stale', 0))} out-of-order events dropped by "
        "version guards; "
        f"{_n(h['engine_outcomes'].get('skipped_echo', 0))} echoes of our own writes ignored",
        f"- {_n(h['inline_retries'])} inline retries with jittered backoff; "
        f"{_n(h['rate_limited_responses'])} rate-limit responses honoured via Retry-After",
        f"- Circuit breakers opened {h['circuit_breaker_opens']['salesforce']}× for Salesforce "
        f"and {h['circuit_breaker_opens']['slack']}× for Slack, skipping "
        f"{_n(h['calls_skipped_by_open_circuit'])} calls during outages",
        f"- {_n(t['redeliveries'])} queue redeliveries (crashes, deferrals)",
        f"- {h['dead_lettered_during_run']} messages dead-lettered during the outages, all "
        f"replayed afterwards ({h['dead_letters_after_replay']} left)",
        f"- Reconciler scanned {_n(h['reconciler']['scanned'])} records and re-enqueued "
        f"{_n(h['reconciler']['enqueued'])} whose webhook never arrived",
    ]
    if naive is not None:
        na = naive.audit
        lines += [
            "",
            "## Baseline: the same run without the safeguards",
            "",
            "Same seed and faults, with the engine in `naive` mode: check the mapping table, "
            "then write, and retry failed calls as they are (no idempotency keys, record locks, "
            "PENDING reservations, metadata recovery or upserts).",
            "",
            "| Check | With safeguards | Naive |",
            "|---|---:|---:|",
            f"| Duplicate Slack messages for a Case | {a['duplicate_slack_case_messages']} | "
            f"{_n(na['duplicate_slack_case_messages'])} |",
            f"| Duplicate Slack thread replies | {a['duplicate_slack_thread_replies']} | "
            f"{_n(na['duplicate_slack_thread_replies'])} |",
            f"| Duplicate Case_Message__c records | {a['duplicate_salesforce_case_messages']} | "
            f"{_n(na['duplicate_salesforce_case_messages'])} |",
            f"| Slack Case messages out of date | {a['slack_cases_not_matching_salesforce']} | "
            f"{_n(na['slack_cases_not_matching_salesforce'])} |",
            f"| Salesforce messages out of date | {a['salesforce_messages_not_matching_slack']} | "
            f"{_n(na['salesforce_messages_not_matching_slack'])} |",
            f"| Slack replies missing in Salesforce | {a['slack_replies_missing_in_salesforce']} | "
            f"{_n(na['slack_replies_missing_in_salesforce'])} |",
        ]
    lines += [
        "",
        "## Traffic",
        "",
        f"{_n(t['webhook_deliveries'])} webhook deliveries · {_n(t['queue_receives'])} queue "
        f"receives · {_n(t['salesforce_api_calls'])} Salesforce API calls · "
        f"{_n(t['slack_api_calls'])} Slack API calls · "
        f"{main.timing['virtual_seconds_total'] / 60:.0f} virtual minutes",
        "",
        "Reproduce: `syncbridge chaos --cases 10000 --seed 7 --baseline`",
    ]
    return "\n".join(lines) + "\n"
