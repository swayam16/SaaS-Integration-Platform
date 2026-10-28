"""AWS Lambda entry points (see infra/template.yaml).

    webhooks   API Gateway: /webhooks/*          verify + enqueue, nothing else
    api        API Gateway: /api/*, /saml/*, /oauth/*   admin console backend
    scim       API Gateway: /scim/v2/*           Okta provisioning
    worker     SQS event source (batch, partial failures reported)
    reconcile  EventBridge schedule, every 5 minutes

Each function gets only the IAM permissions its job needs; they share this code package.
Components are built once per container and reused across invocations.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

logger = logging.getLogger("syncbridge")
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

_cache: dict[str, Any] = {}


def _platform():
    if "platform" not in _cache:
        from .platform import get_platform

        _cache["platform"] = get_platform()
    return _cache["platform"]


def _router(name: str):
    if name not in _cache:
        p = _platform()
        if name == "webhooks":
            from .webhooks import webhook_routes

            _cache[name] = webhook_routes(p)
        else:
            from .admin.api import admin_routes, build_admin
            from .scim.server import scim_routes

            if "admin" not in _cache:
                _cache["admin"] = build_admin(p)
            ctx = _cache["admin"]
            _cache[name] = (
                admin_routes(ctx) if name == "api" else scim_routes(ctx.directory, p.settings)
            )
    return _cache[name]


def webhooks(event: dict, context: Any = None) -> dict:
    return _router("webhooks").lambda_handler(event, context)


def api(event: dict, context: Any = None) -> dict:
    return _router("api").lambda_handler(event, context)


def scim(event: dict, context: Any = None) -> dict:
    return _router("scim").lambda_handler(event, context)


def worker(event: dict, context: Any = None) -> dict:
    """SQS batch handler with ReportBatchItemFailures: only the failed messages return to the
    queue. Deferred messages get a custom visibility timeout (their backoff)."""
    p = _platform()
    failures = []
    sqs = None
    for record in event.get("Records", []):
        body = json.loads(record["body"])
        receive_count = int(record.get("attributes", {}).get("ApproximateReceiveCount", "1"))
        outcome = p.worker.handle(body, receive_count)
        if outcome.ack:
            if outcome.dead_lettered:
                logger.warning("dead-lettered %s: %s", record["messageId"], outcome.error)
            continue
        failures.append({"itemIdentifier": record["messageId"]})
        if outcome.delay is not None:
            if sqs is None:
                import boto3

                sqs = boto3.client("sqs")
            try:
                sqs.change_message_visibility(
                    QueueUrl=p.settings.queue_url,
                    ReceiptHandle=record["receiptHandle"],
                    VisibilityTimeout=int(min(43_200, outcome.delay)),
                )
            except Exception:  # noqa: BLE001 - the default visibility timeout still applies
                logger.exception("could not change visibility")
        logger.info("message %s returned to queue: %s", record["messageId"], outcome.error)
    return {"batchItemFailures": failures}


def reconcile(event: dict, context: Any = None) -> dict:
    result = _platform().reconciler.run()
    logger.info("reconcile %s", result)
    return result
