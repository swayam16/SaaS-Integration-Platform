"""Wiring: builds every component from Settings. One Platform per Lambda container (cached at
module level by handlers.py); tests and the failure harness build their own with simulators
plugged in through an httpx transport."""

from __future__ import annotations

import base64
import os
from dataclasses import dataclass

import httpx

from .clock import Clock
from .config import Settings, get_settings
from .crypto import Envelope, KmsKeyProvider, LocalKeyProvider
from .oauth import OAuthStates, TokenVault
from .queue import MemoryQueue, SqsQueue
from .retry import RetryPolicy
from .salesforce.auth import SalesforceAuth
from .salesforce.client import SalesforceClient
from .slack.auth import SlackAuth
from .slack.client import SlackClient
from .store import Store
from .store.memory import MemoryStore
from .sync.engine import SyncEngine
from .sync.reconcile import Reconciler
from .sync.worker import Worker


@dataclass
class Platform:
    settings: Settings
    clock: Clock
    store: Store
    vault: TokenVault
    states: OAuthStates
    http: httpx.Client
    sf_auth: SalesforceAuth
    sf: SalesforceClient
    slack_auth: SlackAuth
    slack: SlackClient
    engine: SyncEngine
    worker: Worker
    queue: object
    reconciler: Reconciler


def build_store(settings: Settings, clock: Clock) -> Store:
    if settings.store_backend == "dynamodb":
        from .store.dynamodb import DynamoStore

        return DynamoStore(settings.table_name, clock)
    return MemoryStore(clock)


def build_envelope(settings: Settings) -> Envelope:
    if settings.kms_key_id:
        return Envelope(KmsKeyProvider(settings.kms_key_id))
    key = settings.local_encryption_key
    if not key:
        if settings.environment not in ("local", "test"):
            raise RuntimeError("KMS_KEY_ID is required outside local development")
        key = base64.b64encode(b"local-dev-only-key-do-not-use!!!").decode()
    return Envelope(LocalKeyProvider(base64.b64decode(key)))


def build_platform(
    settings: Settings | None = None,
    *,
    clock: Clock | None = None,
    store: Store | None = None,
    queue=None,
    transport: httpx.BaseTransport | None = None,
    retry: RetryPolicy | None = None,
    naive: bool = False,
    record_activity: bool = True,
    crash_hook=None,
) -> Platform:
    settings = settings or get_settings()
    clock = clock or Clock()
    store = store or build_store(settings, clock)
    vault = TokenVault(store, build_envelope(settings), clock)
    http = httpx.Client(
        transport=transport, follow_redirects=False, headers={"User-Agent": "SyncBridge/1.0"}
    )
    retry = retry or RetryPolicy()
    sf_auth = SalesforceAuth(
        http,
        settings.sf_login_url,
        settings.sf_client_id,
        settings.sf_client_secret,
        f"{settings.base_url}/oauth/salesforce/callback",
    )
    sf = SalesforceClient(http, vault, sf_auth, settings.sf_api_version, clock, retry)
    slack_auth = SlackAuth(
        http,
        settings.slack_api_base,
        settings.slack_oauth_base,
        settings.slack_client_id,
        settings.slack_client_secret,
        f"{settings.base_url}/oauth/slack/callback",
        settings.slack_scopes,
    )
    slack = SlackClient(
        http, vault, settings.slack_api_base, clock, retry, refresher=slack_auth.refresh
    )
    if queue is None:
        queue = SqsQueue(settings.queue_url) if settings.queue_url else MemoryQueue(clock)
    engine = SyncEngine(
        store, clock, sf, slack, naive=naive, record_activity=record_activity, crash_hook=crash_hook
    )
    worker = Worker(engine, store, clock, settings.worker_max_receives)
    reconciler = Reconciler(store, clock, sf, queue)
    return Platform(
        settings,
        clock,
        store,
        vault,
        OAuthStates(store, clock),
        http,
        sf_auth,
        sf,
        slack_auth,
        slack,
        engine,
        worker,
        queue,
        reconciler,
    )


_platform: Platform | None = None


def get_platform() -> Platform:
    global _platform
    if _platform is None:
        _platform = build_platform()
    return _platform


def is_lambda() -> bool:
    return "AWS_LAMBDA_FUNCTION_NAME" in os.environ
