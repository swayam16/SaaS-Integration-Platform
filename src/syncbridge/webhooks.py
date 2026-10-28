"""Inbound webhook routes: verify, enqueue, acknowledge. No sync work happens here, so the
endpoints answer in milliseconds and a slow Salesforce or Slack never causes a webhook timeout."""

from __future__ import annotations

import json

from .http import HttpError, Request, Response, Router, json_response
from .platform import Platform
from .salesforce import webhook as sf_webhook
from .slack import webhook as slack_webhook


def webhook_routes(p: Platform) -> Router:
    r = Router()
    tol = p.settings.webhook_tolerance_seconds

    def metric(name: str, n: int = 1) -> None:
        p.engine._metric(name, n)

    @r.route("POST", "/webhooks/salesforce")
    def salesforce(req: Request) -> Response:
        if not sf_webhook.verify(
            p.settings.sf_webhook_secret, req.headers, req.body, p.clock.now(), tol
        ):
            metric("webhooks_rejected")
            raise HttpError(401, "invalid signature")
        messages = sf_webhook.to_queue_messages(req.json() or {}, p.clock.now())
        for m in messages:
            p.queue.send(m)
        metric("webhooks_received", len(messages))
        return json_response({"accepted": len(messages)}, 202)

    def _slack_verified(req: Request) -> None:
        if not slack_webhook.verify(
            p.settings.slack_signing_secret, req.headers, req.body, p.clock.now(), tol
        ):
            metric("webhooks_rejected")
            raise HttpError(401, "invalid signature")

    def _team_ok(team_id: str) -> bool:
        status = p.vault.status("slack") or {}
        return not status.get("team_id") or not team_id or status["team_id"] == team_id

    @r.route("POST", "/webhooks/slack/events")
    def slack_events(req: Request) -> Response:
        _slack_verified(req)
        payload = req.json() or {}
        if payload.get("type") == "url_verification":
            return json_response({"challenge": payload.get("challenge", "")})
        if payload.get("type") != "event_callback" or not _team_ok(payload.get("team_id", "")):
            return json_response({"ok": True})
        msg = slack_webhook.event_to_message(payload, p.clock.now())
        if msg:
            if req.header("x-slack-retry-num"):
                msg["slack_retry"] = int(req.header("x-slack-retry-num") or 0)
            p.queue.send(msg)
            metric("webhooks_received")
        return json_response({"ok": True})

    @r.route("POST", "/webhooks/slack/interactivity")
    def slack_interactivity(req: Request) -> Response:
        _slack_verified(req)
        form = req.form()
        try:
            team = (json.loads(form.get("payload", "{}")).get("team") or {}).get("id", "")
        except json.JSONDecodeError as exc:
            raise HttpError(400, "bad payload") from exc
        if not _team_ok(team):
            return Response(200)
        messages = slack_webhook.interaction_to_messages(form, p.clock.now())
        for m in messages:
            p.queue.send(m)
        metric("webhooks_received", len(messages))
        return Response(200)

    return r
