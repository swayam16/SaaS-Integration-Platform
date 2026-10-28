"""Failure-injection harness: runs the real platform code (webhook routes with signature checks,
queue semantics, worker, engine, clients, reconciler) against the Salesforce and Slack
simulators in virtual time, with faults on every layer, then audits both systems record by
record.

Virtual time: user activity, webhook delivery, queue visibility, leases and outage windows all
run on one VirtualClock. Inline retry sleeps are recorded but do not advance the shared clock,
the way many Lambda workers back off in parallel without blocking each other.
"""

from __future__ import annotations

import heapq
import json
import random
import time
from collections import Counter
from dataclasses import asdict, dataclass, field

import httpx

from ..clock import VirtualClock
from ..config import Settings
from ..http import Request
from ..platform import build_platform
from ..queue import MemoryQueue
from ..retry import RetryPolicy
from ..salesforce.webhook import sign as sf_sign
from ..store.memory import MemoryStore
from ..sync.engine import SETTINGS
from ..sync.worker import DEADLETTERS, replay
from ..webhooks import webhook_routes
from .faults import DeliveryPlan, FaultPlan
from .salesforce import SalesforceSim
from .slack import USERS, SlackSim

CHANNEL = "C0SUPPORT1"
SUBJECTS = [
    "Login fails with SSO error",
    "Invoice total is wrong",
    "API returns 500 on export",
    "Cannot reset password",
    "Webhook deliveries delayed",
    "Data import stuck at 90%",
    "Mobile app crashes on launch",
    "Report shows duplicate rows",
    "Need SAML setup help",
    "Billing address update",
    "Slow dashboard loading",
    "Permission denied on project",
]
ACCOUNTS = [
    "Globex",
    "Initech",
    "Umbrella Health",
    "Stark Logistics",
    "Wayne Retail",
    "Hooli Cloud",
    "Soylent Foods",
    "Vandelay Imports",
    "Wonka Labs",
    "Tyrell Robotics",
]
AGENTS = ["Priya Raman", "Marcus Hale", "Elena Sokolova", "Tomás Ibarra"]


class WorkerCrash(BaseException):
    """Simulated hard crash (Lambda timeout / OOM): no except or cleanup code gets to run
    business logic, so claims and locks are left behind exactly as a killed process leaves them."""


class ParallelSleepClock(VirtualClock):
    """Shares time with the main clock but sleeping does not advance it."""

    def __init__(self, base: VirtualClock):
        self.base = base
        self.slept = 0.0

    def now(self) -> float:
        return self.base.now()

    def sleep(self, seconds: float) -> None:
        self.slept += max(0.0, seconds)


@dataclass
class ChaosConfig:
    cases: int = 10_000
    duration: float = 1800.0
    update_ratio: float = 0.6
    agent_message_ratio: float = 0.35
    slack_reply_ratio: float = 0.35
    edit_ratio: float = 0.2
    click_ratio: float = 0.25
    seed: int = 7
    naive: bool = False
    faults: bool = True
    crash_rate: float = 0.01
    api_error_rate: float = 0.02
    api_ambiguous_rate: float = 0.02
    rate_limit_rate: float = 0.01
    webhook_duplicate_rate: float = 0.10
    webhook_drop_rate: float = 0.01
    max_delivery_delay: float = 20.0
    slack_outage: tuple[float, float] = (600.0, 780.0)
    salesforce_outage: tuple[float, float] = (1200.0, 1290.0)
    batch: int = 40
    tick: float = 0.25


@dataclass
class ChaosReport:
    config: dict
    records: dict = field(default_factory=dict)
    traffic: dict = field(default_factory=dict)
    faults: dict = field(default_factory=dict)
    handling: dict = field(default_factory=dict)
    audit: dict = field(default_factory=dict)
    timing: dict = field(default_factory=dict)


class Chaos:
    def __init__(self, cfg: ChaosConfig, store_factory=None):
        self.cfg = cfg
        self.rng = random.Random(cfg.seed)
        self.clock = VirtualClock()
        self.t0 = self.clock.now()
        f = cfg.faults
        sf_faults = FaultPlan(
            error_before=cfg.api_error_rate / 2 if f else 0,
            error_after=cfg.api_ambiguous_rate / 2 if f else 0,
            timeout_after=cfg.api_ambiguous_rate / 2 if f else 0,
            connect_error=0.005 if f else 0,
            rate_limit=cfg.rate_limit_rate / 4 if f else 0,
            lock_error=0.005 if f else 0,
            outages=[(self.t0 + cfg.salesforce_outage[0], self.t0 + cfg.salesforce_outage[1])]
            if f
            else [],
            rng=random.Random(cfg.seed + 1),
        )
        slack_faults = FaultPlan(
            error_before=cfg.api_error_rate / 2 if f else 0,
            error_after=cfg.api_ambiguous_rate / 2 if f else 0,
            timeout_after=cfg.api_ambiguous_rate / 2 if f else 0,
            connect_error=0.005 if f else 0,
            rate_limit=cfg.rate_limit_rate if f else 0,
            outages=[(self.t0 + cfg.slack_outage[0], self.t0 + cfg.slack_outage[1])] if f else [],
            rng=random.Random(cfg.seed + 2),
        )
        delivery = dict(
            duplicate=cfg.webhook_duplicate_rate if f else 0,
            max_delay=cfg.max_delivery_delay if f else 0,
        )
        self.sf = SalesforceSim(
            self.clock,
            faults=sf_faults,
            delivery=DeliveryPlan(
                **delivery, drop=cfg.webhook_drop_rate if f else 0, rng=random.Random(cfg.seed + 3)
            ),
            expire_token_every=2500 if f else 0,
        )
        self.slack = SlackSim(
            self.clock,
            faults=slack_faults,
            delivery=DeliveryPlan(**delivery, rng=random.Random(cfg.seed + 4)),
        )
        self.settings = Settings(
            base_url="https://syncbridge.test",
            environment="test",
            sf_login_url="https://login.salesforce.com",
            sf_client_id="sim-sf-client",
            sf_client_secret="sim-sf-secret",
            sf_webhook_secret=self.sf.webhook_secret,
            slack_api_base="https://slack.com/api",
            slack_signing_secret=self.slack.signing_secret,
            slack_client_id="sim",
            slack_client_secret="sim",
        )
        self.store = store_factory(self.clock) if store_factory else MemoryStore(self.clock)
        self.queue = MemoryQueue(
            self.clock,
            visibility_timeout=60.0,
            max_receives=8,
            rng=random.Random(cfg.seed + 5),
            shuffle=True,
        )
        self.crash_rng = random.Random(cfg.seed + 6)
        self.crashes = Counter()
        self.worker_clock = ParallelSleepClock(self.clock)

        def route(request: httpx.Request) -> httpx.Response:
            host = request.url.host
            if host.endswith("salesforce.com"):
                return self.sf(request)
            if host == "slack.com":
                return self.slack(request)
            return httpx.Response(404)

        self.platform = build_platform(
            self.settings,
            clock=self.worker_clock,
            store=self.store,
            queue=self.queue,
            transport=httpx.MockTransport(route),
            retry=RetryPolicy(rng=random.Random(cfg.seed + 7)),
            naive=cfg.naive,
            record_activity=False,
            crash_hook=self._crash_point,
        )
        self.routes = webhook_routes(self.platform)
        self.agenda: list[tuple[float, int, str, tuple]] = []
        self._seq = 0
        self.case_ids: list[str] = []
        self.human_replies: dict[tuple[str, str], str] = {}  # (channel, ts) -> final text
        self.webhook_status = Counter()
        self.actions_done = Counter()
        self._slack_index: dict[str, str] = {}
        self._scanned = 0

    # --- setup ----------------------------------------------------------------------------------

    def connect(self) -> None:
        p = self.platform
        sf_tokens = json.loads(
            httpx.Client(transport=httpx.MockTransport(self.sf))
            .post(
                "https://login.salesforce.com/services/oauth2/token",
                data={"grant_type": "authorization_code", "code": self._sf_code()},
            )
            .content
        )
        p.vault.save(
            "salesforce",
            {
                "access_token": sf_tokens["access_token"],
                "refresh_token": sf_tokens["refresh_token"],
                "instance_url": sf_tokens["instance_url"],
            },
            "harness",
        )
        p.vault.save(
            "slack",
            {"access_token": self.slack.issue_token(), "team_id": self.slack.team_id},
            "harness",
        )
        self.store.put(
            SETTINGS, "sync", {"channel_id": CHANNEL, "instance_url": self.sf.instance_url}
        )

    def _sf_code(self) -> str:
        code = "harness-code"
        self.sf.codes[code] = ""
        return code

    # --- crash injection -----------------------------------------------------------------------------

    def _crash_point(self, point: str) -> None:
        if self.cfg.faults and self.crash_rng.random() < self.cfg.crash_rate:
            self.crashes[point] += 1
            self.platform.engine.crashing = True
            raise WorkerCrash(point)

    # --- agenda ------------------------------------------------------------------------------------

    def at(self, t: float, action: str, *args) -> None:
        self._seq += 1
        heapq.heappush(self.agenda, (t, self._seq, action, args))

    def plan(self) -> None:
        cfg, r = self.cfg, self.rng
        for i in range(cfg.cases):
            t = self.t0 + r.uniform(0, cfg.duration)
            self.at(t, "create_case", i)

    def _schedule_followups(self, case_id: str, t: float) -> None:
        cfg, r = self.cfg, self.rng
        if r.random() < cfg.update_ratio:
            for _ in range(r.choice([1, 1, 2, 3])):
                self.at(t + r.expovariate(1 / 40), "update_case", case_id)
        if r.random() < cfg.agent_message_ratio:
            self.at(t + r.uniform(5, 400), "agent_message", case_id)
        if r.random() < cfg.slack_reply_ratio:
            self.at(t + r.uniform(20, 600), "slack_reply", case_id, 0)
        if r.random() < cfg.click_ratio:
            self.at(t + r.uniform(30, 900), "click", case_id, 0)

    def _do(self, action: str, args: tuple) -> None:
        r = self.rng
        if action == "create_case":
            rec = self.sf.create_case(
                {
                    "Subject": r.choice(SUBJECTS),
                    "Priority": r.choice(["Low", "Medium", "High"]),
                    "AccountName": r.choice(ACCOUNTS),
                    "OwnerName": r.choice(AGENTS),
                    "Description": f"Reported via web form. Ticket ref {r.randint(10000, 99999)}.",
                }
            )
            self.case_ids.append(rec["Id"])
            self._schedule_followups(rec["Id"], self.clock.now())
        elif action == "update_case":
            rec = self.sf.cases[args[0]]
            change = r.choice(["status", "priority", "both", "subject"])
            fields: dict = {}
            if change in ("status", "both"):
                fields["Status"] = r.choice(["Working", "On Hold", "Escalated", "Closed"])
            if change in ("priority", "both"):
                fields["Priority"] = r.choice(["Low", "Medium", "High"])
            if change == "subject":
                fields["Subject"] = rec["Subject"] + " (updated)"
            self.sf.update_case(args[0], fields)
        elif action == "agent_message":
            self.sf.add_message(
                {
                    "Case__c": args[0],
                    "Author__c": r.choice(AGENTS),
                    "Body__c": f"Update from support: step {r.randint(1, 9)} done.",
                    "Source__c": "Salesforce",
                }
            )
        elif action in ("slack_reply", "click"):
            case_id, tries = args
            msg = self._slack_message_for(case_id)
            if msg is None:  # not visible in Slack yet; people can't reply to what they can't see
                if tries < 20:
                    self.at(self.clock.now() + 60, action, case_id, tries + 1)
                else:
                    self.actions_done[f"{action}_gave_up"] += 1
                return
            user = r.choice(list(USERS))
            if action == "slack_reply":
                text = f"Customer says: {r.choice(['still broken', 'works now', 'any ETA?'])}"
                reply = self.slack.human_reply(CHANNEL, msg["ts"], user, text)
                self.human_replies[(CHANNEL, reply["ts"])] = text
                if r.random() < self.cfg.edit_ratio:
                    self.at(self.clock.now() + r.uniform(3, 120), "edit", reply["ts"])
            else:
                status = self.sf.cases[case_id]["Status"]
                action_id = (
                    "case_reopen"
                    if status == "Closed"
                    else r.choice(["case_close", "case_escalate"])
                )
                self.slack.click(CHANNEL, msg["ts"], action_id, case_id, user)
            self.actions_done[action] += 1
        elif action == "edit":
            text = f"(edited) Customer says: {r.choice(['fixed', 'still failing', 'thanks'])}"
            self.slack.human_edit(CHANNEL, args[0], text)
            self.human_replies[(CHANNEL, args[0])] = text
            self.actions_done["edit"] += 1

    def _slack_message_for(self, case_id: str) -> dict | None:
        key = f"case:{case_id}"
        idx = self._slack_index
        ts = idx.get(key)
        if ts is None:
            for m in self.slack.channels[CHANNEL][self._scanned :]:
                k = ((m.get("metadata") or {}).get("event_payload") or {}).get("sync_key")
                if k and k.startswith("case:") and k not in idx:
                    idx[k] = m["ts"]
            self._scanned = len(self.slack.channels[CHANNEL])
            ts = idx.get(key)
        return None if ts is None else self.slack.by_ts[(CHANNEL, ts)]

    # --- delivery ----------------------------------------------------------------------------------

    def _post(self, path: str, body: bytes, headers: dict[str, str]) -> int:
        resp = self.routes.dispatch(Request("POST", path, headers=headers, body=body))
        self.webhook_status[(path, resp.status)] += 1
        return resp.status

    def deliver(self) -> int:
        n = 0
        for out in self.sf.due_notifications():
            body = json.dumps(out.payload).encode()
            ts = int(self.clock.now())
            self._post(
                "/webhooks/salesforce",
                body,
                {
                    "content-type": "application/json",
                    "x-syncbridge-timestamp": str(ts),
                    "x-syncbridge-signature": sf_sign(self.sf.webhook_secret, ts, body),
                },
            )
            n += 1
        for out in self.slack.due_events():
            body, headers = self.slack.encode(out)
            path = (
                "/webhooks/slack/events" if out.kind == "event" else "/webhooks/slack/interactivity"
            )
            self._post(path, body, headers)
            n += 1
        return n

    def work(self) -> int:
        msgs = self.queue.receive(self.cfg.batch)
        for m in msgs:
            engine = self.platform.engine
            engine.crashing = False
            try:
                outcome = self.platform.worker.handle(m.body, m.receive_count)
            except WorkerCrash:
                continue  # message stays in flight until its visibility timeout expires
            if outcome.ack:
                self.queue.delete(m)
            elif outcome.delay is not None:
                self.queue.change_visibility(m, outcome.delay)
        return len(msgs)

    def _next_time(self) -> float | None:
        times = [
            t
            for t in (
                self.agenda[0][0] if self.agenda else None,
                min((o.deliver_at for o in self.sf.outbox), default=None),
                min((o.deliver_at for o in self.slack.outbox), default=None),
                self.queue.next_visible_at(),
            )
            if t is not None
        ]
        return min(times) if times else None

    def step(self) -> bool:
        while self.agenda and self.agenda[0][0] <= self.clock.now():
            _, _, action, args = heapq.heappop(self.agenda)
            self._do(action, args)
        delivered = self.deliver()
        worked = self.work()
        if delivered or worked:
            self.clock.advance(self.cfg.tick)
            return True
        nxt = self._next_time()
        if nxt is None:
            return False
        self.clock.advance(max(self.cfg.tick, nxt - self.clock.now()))
        return True

    def drain(self) -> None:
        while self.step():
            pass

    # --- run -----------------------------------------------------------------------------------------

    def run(self) -> ChaosReport:
        wall = time.perf_counter()
        self.connect()
        self.plan()
        self.drain()
        live_done = self.clock.now()
        dlq_before = len(self.store.list(DEADLETTERS))
        sqs_dlq = len(self.queue.dlq)
        # A webhook that never arrives can only be found by asking Salesforce.
        reconciled = self.platform.reconciler.run(full=True)
        self.drain()
        replayed = 0
        for dl_id, _ in self.store.list(DEADLETTERS):
            replay(self.store, self.queue, dl_id)
            replayed += 1
        for m in list(self.queue.dlq):
            self.queue.send(m.body)
            replayed += 1
        self.queue.dlq.clear()
        self.drain()
        return self._report(
            time.perf_counter() - wall, live_done, dlq_before, sqs_dlq, reconciled, replayed
        )

    # --- audit ---------------------------------------------------------------------------------------

    def _report(
        self,
        wall: float,
        live_done: float,
        dlq_before: int,
        sqs_dlq: int,
        reconciled: dict,
        replayed: int,
    ) -> ChaosReport:
        cfg = self.cfg
        rep = ChaosReport(config=asdict(cfg))
        top = self.slack.top_level(CHANNEL)
        posts = Counter()
        for m in top:
            key = ((m.get("metadata") or {}).get("event_payload") or {}).get("sync_key", "")
            if key.startswith("case:"):
                posts[key] += 1
        replies_by_key = Counter()
        for m in self.slack.channels[CHANNEL]:
            key = ((m.get("metadata") or {}).get("event_payload") or {}).get("sync_key", "")
            if key.startswith("msg:"):
                replies_by_key[key] += 1
        cases = self.sf.cases
        agent_msgs = [m for m in self.sf.messages.values() if m.get("Source__c") != "Slack"]
        slack_msgs = [m for m in self.sf.messages.values() if m.get("Source__c") == "Slack"]
        sf_by_slack = Counter((m.get("Slack_Channel__c"), m.get("Slack_TS__c")) for m in slack_msgs)

        dup_case_posts = sum(c - 1 for c in posts.values() if c > 1)
        dup_replies = sum(c - 1 for c in replies_by_key.values() if c > 1)
        dup_sf = sum(c - 1 for c in sf_by_slack.values() if c > 1)
        missing_cases = sum(1 for cid in cases if posts.get(f"case:{cid}", 0) == 0)
        missing_replies = sum(1 for m in agent_msgs if replies_by_key.get(f"msg:{m['Id']}", 0) == 0)
        missing_sf = sum(1 for k in self.human_replies if sf_by_slack.get(k, 0) == 0)

        stale_slack = 0
        by_key = {}
        for m in top:
            key = ((m.get("metadata") or {}).get("event_payload") or {}).get("sync_key", "")
            by_key.setdefault(key, m)
        for cid, rec in cases.items():
            m = by_key.get(f"case:{cid}")
            want = (
                f"Case {rec['CaseNumber']}: {rec['Subject']} [{rec['Status']}, {rec['Priority']}]"
            )
            if m is None or m["text"] != want:
                stale_slack += 1
        body_mismatch = 0
        latest = {}
        for m in slack_msgs:
            latest.setdefault((m.get("Slack_Channel__c"), m.get("Slack_TS__c")), m)
        for k, text in self.human_replies.items():
            m = latest.get(k)
            if m is None or m.get("Body__c") != text:
                body_mismatch += 1

        sf_stats, slack_stats = self.platform.sf.stats, self.platform.slack.stats
        rep.records = {
            "salesforce_cases": len(cases),
            "case_messages_from_salesforce": len(agent_msgs),
            "case_messages_from_slack": len(self.human_replies),
            "slack_edits": self.actions_done["edit"],
            "slack_button_clicks": self.actions_done["click"],
            "total_records_synced": len(cases) + len(agent_msgs) + len(self.human_replies),
        }
        rep.traffic = {
            "salesforce_notifications": self.sf.notifications,
            "webhook_deliveries": sum(v for (p, s), v in self.webhook_status.items()),
            "queue_messages_sent": self.queue.sent,
            "queue_receives": self.queue.received,
            "redeliveries": self.queue.received - self.queue.deleted,
            "salesforce_api_calls": self.sf.api_calls["total"],
            "slack_api_calls": sum(self.slack.api_calls.values()),
        }
        rep.faults = {
            "salesforce_api": dict(self.sf.faults.injected),
            "slack_api": dict(self.slack.faults.injected),
            "salesforce_webhooks": dict(self.sf.delivery.injected),
            "slack_events": dict(self.slack.delivery.injected),
            "worker_crashes": dict(self.crashes),
            "salesforce_token_expiries": (
                self.sf.api_calls["total"] // self.sf.expire_token_every
                if self.sf.expire_token_every
                else 0
            ),
        }
        rep.handling = {
            "engine_outcomes": dict(sorted(self.platform.engine.stats.outcomes.items())),
            "inline_retries": sf_stats.retries + slack_stats.retries,
            "rate_limited_responses": sf_stats.rate_limited + slack_stats.rate_limited,
            "ambiguous_failures": sf_stats.ambiguous + slack_stats.ambiguous,
            "recovered_via_slack_metadata": self.platform.slack.recovered_by_metadata,
            "circuit_breaker_opens": {
                "salesforce": self.platform.sf.breaker.opened,
                "slack": self.platform.slack.breaker.opened,
            },
            "calls_skipped_by_open_circuit": (
                self.platform.sf.breaker.short_circuited
                + self.platform.slack.breaker.short_circuited
            ),
            "deferred_to_queue": self.platform.worker.deferred,
            "dead_lettered_during_run": dlq_before + sqs_dlq,
            "reconciler": reconciled,
            "replayed_from_dead_letter": replayed,
            "dead_letters_after_replay": len(self.store.list(DEADLETTERS)) + len(self.queue.dlq),
        }
        rep.audit = {
            "duplicate_slack_case_messages": dup_case_posts,
            "duplicate_slack_thread_replies": dup_replies,
            "duplicate_salesforce_case_messages": dup_sf,
            "duplicate_writes_total": dup_case_posts + dup_replies + dup_sf,
            "cases_missing_in_slack": missing_cases,
            "salesforce_messages_missing_in_slack": missing_replies,
            "slack_replies_missing_in_salesforce": missing_sf,
            "slack_cases_not_matching_salesforce": stale_slack,
            "salesforce_messages_not_matching_slack": body_mismatch,
        }
        rep.timing = {
            "virtual_seconds_live": round(live_done - self.t0, 1),
            "virtual_seconds_total": round(self.clock.now() - self.t0, 1),
            "wall_seconds": round(wall, 1),
            "inline_backoff_seconds": round(self.worker_clock.slept, 1),
        }
        return rep


def run_chaos(cfg: ChaosConfig) -> ChaosReport:
    return Chaos(cfg).run()
