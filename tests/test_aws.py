"""AWS backends against moto: DynamoDB store contract, KMS envelope encryption, the Lambda
handlers with API Gateway and SQS events, and a failure test on the DynamoDB backend."""

import base64
import json
import os

import boto3
import pytest
from moto import mock_aws

from syncbridge.clock import VirtualClock
from syncbridge.crypto import Envelope, KmsKeyProvider
from syncbridge.salesforce.webhook import sign as sf_sign
from syncbridge.store import ConditionFailed
from syncbridge.store.dynamodb import DynamoStore, create_table
from syncbridge.store.memory import MemoryStore

REGION = "us-east-1"


@pytest.fixture
def aws(monkeypatch):
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    with mock_aws():
        yield


@pytest.fixture(params=["memory", "dynamodb"])
def store(request, aws):
    clock = VirtualClock()
    if request.param == "memory":
        return MemoryStore(clock)
    ddb = boto3.resource("dynamodb", region_name=REGION)
    create_table(ddb, "syncbridge-test")
    return DynamoStore("syncbridge-test", clock, ddb)


def test_store_contract(store):
    clock = store.clock
    store.put(
        "idempotency",
        "k1",
        {"status": "IN_PROGRESS", "lease": 1.5, "n": 3, "nested": {"a": [1, 2.25, "x"]}},
        [("not_exists",)],
    )
    assert store.get("idempotency", "k1") == {
        "status": "IN_PROGRESS",
        "lease": 1.5,
        "n": 3,
        "nested": {"a": [1, 2.25, "x"]},
    }
    with pytest.raises(ConditionFailed) as exc:
        store.put("idempotency", "k1", {"status": "x"}, [("not_exists",)])
    assert exc.value.current["status"] == "IN_PROGRESS"
    new = store.update(
        "idempotency",
        "k1",
        {"status": "COMPLETED"},
        [("eq", "status", "IN_PROGRESS")],
        remove=["lease"],
    )
    assert new == {"status": "COMPLETED", "n": 3, "nested": {"a": [1, 2.25, "x"]}}
    with pytest.raises(ConditionFailed):
        store.update("idempotency", "k1", {"status": "again"}, [("eq", "status", "IN_PROGRESS")])
    store.update("mappings", "case:1", {"modstamp": 10.0}, [("lt_or_missing", "modstamp", 10.0)])
    with pytest.raises(ConditionFailed):
        store.update("mappings", "case:1", {"modstamp": 9.0}, [("lt_or_missing", "modstamp", 9.0)])
    store.put("locks", "r", {"until": clock.now() + 5}, ttl=clock.now() + 5)
    clock.advance(6)
    assert store.get("locks", "r") is None
    store.put("locks", "r", {"until": 1}, [("not_exists",)])  # expired == absent
    with pytest.raises(ConditionFailed):
        store.delete("locks", "r", [("eq", "until", 2)])
    store.delete("locks", "r", [("eq", "until", 1)])
    assert store.increment("metrics", "2026-10-28T14", "events") == 1
    assert store.increment("metrics", "2026-10-28T14", "events", 2) == 3
    for i in range(5):
        store.put("audit", f"{i:03d}", {"i": i})
    assert [k for k, _ in store.list("audit", limit=3, reverse=True)] == ["004", "003", "002"]
    assert [k for k, _ in store.list("audit", prefix="00")] == ["000", "001", "002", "003", "004"]


def test_kms_envelope(aws):
    kms = boto3.client("kms", region_name=REGION)
    key_id = kms.create_key()["KeyMetadata"]["KeyId"]
    env = Envelope(KmsKeyProvider(key_id, kms))
    ctx = {"purpose": "oauth-token", "provider": "salesforce"}
    blob = env.encrypt(b"refresh-token-value", ctx)
    assert blob["kp"] == "kms" and b"refresh" not in json.dumps(blob).encode()
    assert env.decrypt(blob, ctx) == b"refresh-token-value"


def test_failure_run_on_dynamodb(aws):
    from syncbridge.sim.harness import Chaos, ChaosConfig

    ddb = boto3.resource("dynamodb", region_name=REGION)
    create_table(ddb, "chaos")
    cfg = ChaosConfig(
        cases=60, duration=150, seed=21, slack_outage=(50, 90), salesforce_outage=(110, 130)
    )
    report = Chaos(cfg, store_factory=lambda clock: DynamoStore("chaos", clock, ddb)).run()
    assert report.records["salesforce_cases"] == 60
    assert all(v == 0 for v in report.audit.values()), report.audit


# --- Lambda handlers ------------------------------------------------------------------------------


@pytest.fixture
def lambda_env(aws, monkeypatch):
    ddb = boto3.resource("dynamodb", region_name=REGION)
    create_table(ddb, "sb")
    sqs = boto3.client("sqs", region_name=REGION)
    url = sqs.create_queue(QueueName="sb-events")["QueueUrl"]
    kms = boto3.client("kms", region_name=REGION)
    env = {
        "STORE_BACKEND": "dynamodb",
        "TABLE_NAME": "sb",
        "QUEUE_URL": url,
        "KMS_KEY_ID": kms.create_key()["KeyMetadata"]["KeyId"],
        "SALESFORCE_WEBHOOK_SECRET": "whsec",
        "ENVIRONMENT": "prod",
        "PUBLIC_BASE_URL": "https://sb.example.com",
        "AWS_LAMBDA_FUNCTION_NAME": "sb-test",
    }
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    import syncbridge.config as config
    import syncbridge.handlers as handlers
    import syncbridge.platform as platform

    config._settings = None
    platform._platform = None
    handlers._cache.clear()
    yield handlers, sqs, url
    config._settings = None
    platform._platform = None
    handlers._cache.clear()


def apigw(method, path, body=b"", headers=None, cookies=None):
    return {
        "version": "2.0",
        "rawPath": path,
        "rawQueryString": "",
        "headers": headers or {},
        "cookies": cookies or [],
        "requestContext": {"http": {"method": method, "path": path, "sourceIp": "203.0.113.9"}},
        "body": base64.b64encode(body).decode(),
        "isBase64Encoded": True,
    }


def test_webhook_lambda_enqueues_to_sqs(lambda_env):
    handlers, sqs, url = lambda_env
    payload = {
        "events": [
            {
                "eventId": "e1",
                "sobject": "Case",
                "recordId": "500Hs00000ABCDEAAA",
                "changeType": "CREATE",
                "systemModstamp": "2026-10-28T12:00:00.000Z",
                "fields": {"CaseNumber": "00001001", "Subject": "x"},
            }
        ]
    }
    body = json.dumps(payload).encode()
    import time

    ts = int(time.time())
    resp = handlers.webhooks(
        apigw(
            "POST",
            "/webhooks/salesforce",
            body,
            {
                "X-SyncBridge-Timestamp": str(ts),
                "X-SyncBridge-Signature": sf_sign("whsec", ts, body),
            },
        )
    )
    assert resp["statusCode"] == 202 and json.loads(resp["body"]) == {"accepted": 1}
    assert resp["headers"]["Strict-Transport-Security"].startswith("max-age")
    msgs = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10)["Messages"]
    assert json.loads(msgs[0]["Body"])["record_id"] == "500Hs00000ABCDEAAA"
    bad = handlers.webhooks(
        apigw(
            "POST",
            "/webhooks/salesforce",
            body,
            {"X-SyncBridge-Timestamp": str(ts), "X-SyncBridge-Signature": "v1=bad"},
        )
    )
    assert bad["statusCode"] == 401


def test_worker_lambda_dead_letters_permanent_errors(lambda_env):
    handlers, sqs, url = lambda_env
    body = {
        "source": "salesforce",
        "kind": "record_change",
        "sobject": "Case",
        "record_id": "500Hs00000ABCDEAAA",
        "modstamp": "2026-10-28T12:00:00.000Z",
        "fields": {"CaseNumber": "1", "Subject": "x", "Status": "New", "Priority": "Low"},
    }
    event = {
        "Records": [
            {
                "messageId": "m1",
                "receiptHandle": "r1",
                "body": json.dumps(body),
                "attributes": {"ApproximateReceiveCount": "1"},
            }
        ]
    }
    result = handlers.worker(event)
    assert result == {"batchItemFailures": []}  # permanent: recorded, not retried forever
    from syncbridge.platform import get_platform

    dls = get_platform().store.list("deadletters")
    assert len(dls) == 1 and "no Slack channel" in dls[0][1]["reason"]


def test_api_lambda_requires_session(lambda_env):
    handlers, _, _ = lambda_env
    resp = handlers.api(apigw("GET", "/api/overview"))
    assert resp["statusCode"] == 401
    me = handlers.api(apigw("GET", "/api/me"))
    assert json.loads(me["body"])["authenticated"] is False


def test_scim_lambda_rejects_without_token(lambda_env):
    handlers, _, _ = lambda_env
    resp = handlers.scim(apigw("GET", "/scim/v2/Users"))
    assert resp["statusCode"] == 401
    assert resp["headers"]["Content-Type"] == "application/scim+json"


def test_production_requires_kms(monkeypatch):
    from syncbridge.config import Settings
    from syncbridge.platform import build_envelope

    with pytest.raises(RuntimeError, match="KMS"):
        build_envelope(Settings(environment="prod", kms_key_id="", local_encryption_key=""))
    os.environ.pop("KMS_KEY_ID", None)


def test_settings_load_from_secrets_manager(aws, monkeypatch):
    import syncbridge.config as config

    sm = boto3.client("secretsmanager", region_name=REGION)
    arn = sm.create_secret(
        Name="sb",
        SecretString=json.dumps(
            {
                "SALESFORCE_CLIENT_ID": "3MVG9.abc",
                "SLACK_SIGNING_SECRET": "sig",
                "SAML_IDP_SSO_URL": "https://acme.okta.com/app/x/sso/saml",
                "SCIM_TOKEN_SHA256": "",
            }
        ),
    )["ARN"]
    monkeypatch.setenv("SECRETS_ARN", arn)
    config._settings = None
    try:
        s = config.get_settings()
        assert s.sf_client_id == "3MVG9.abc" and s.slack_signing_secret == "sig"
        assert s.saml_idp_sso_url.endswith("/sso/saml")
        assert s.scim_token_sha256 == ""  # empty values don't override
    finally:
        config._settings = None
