"""Settings from environment variables, with secrets loaded from AWS Secrets Manager in Lambda.

Non-secret configuration lives in environment variables set by infra/template.yaml. Secrets
(client secrets, signing secrets, the SCIM token hash) live in one Secrets Manager secret whose
ARN is in SECRETS_ARN; it is fetched once per Lambda container and cached.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


def _load_secrets() -> dict[str, str]:
    arn = os.environ.get("SECRETS_ARN")
    if not arn:
        return {}
    import boto3

    raw = boto3.client("secretsmanager").get_secret_value(SecretId=arn)["SecretString"]
    return json.loads(raw)


@dataclass
class Settings:
    # Public URL of the deployment (API Gateway custom domain or CloudFront), no trailing slash.
    base_url: str = field(default_factory=lambda: _env("PUBLIC_BASE_URL", "http://localhost:8080"))
    environment: str = field(default_factory=lambda: _env("ENVIRONMENT", "local"))

    # Storage and queue
    store_backend: str = field(default_factory=lambda: _env("STORE_BACKEND", "memory"))
    table_name: str = field(default_factory=lambda: _env("TABLE_NAME", "syncbridge"))
    queue_url: str = field(default_factory=lambda: _env("QUEUE_URL", ""))
    kms_key_id: str = field(default_factory=lambda: _env("KMS_KEY_ID", ""))
    local_encryption_key: str = field(default_factory=lambda: _env("LOCAL_ENCRYPTION_KEY", ""))

    # Salesforce (connected app)
    sf_login_url: str = field(
        default_factory=lambda: _env("SALESFORCE_LOGIN_URL", "https://login.salesforce.com")
    )
    sf_client_id: str = field(default_factory=lambda: _env("SALESFORCE_CLIENT_ID"))
    sf_client_secret: str = field(default_factory=lambda: _env("SALESFORCE_CLIENT_SECRET"))
    sf_api_version: str = field(default_factory=lambda: _env("SALESFORCE_API_VERSION", "v62.0"))
    sf_webhook_secret: str = field(default_factory=lambda: _env("SALESFORCE_WEBHOOK_SECRET"))

    # Slack app
    slack_api_base: str = field(
        default_factory=lambda: _env("SLACK_API_BASE", "https://slack.com/api")
    )
    slack_oauth_base: str = field(
        default_factory=lambda: _env("SLACK_OAUTH_BASE", "https://slack.com/oauth/v2/authorize")
    )
    slack_client_id: str = field(default_factory=lambda: _env("SLACK_CLIENT_ID"))
    slack_client_secret: str = field(default_factory=lambda: _env("SLACK_CLIENT_SECRET"))
    slack_signing_secret: str = field(default_factory=lambda: _env("SLACK_SIGNING_SECRET"))
    slack_scopes: str = field(
        default_factory=lambda: _env(
            "SLACK_SCOPES", "chat:write,channels:history,groups:history,users:read"
        )
    )

    # SAML (Okta) service provider
    saml_sp_entity_id: str = field(default_factory=lambda: _env("SAML_SP_ENTITY_ID"))
    saml_idp_entity_id: str = field(default_factory=lambda: _env("SAML_IDP_ENTITY_ID"))
    saml_idp_sso_url: str = field(default_factory=lambda: _env("SAML_IDP_SSO_URL"))
    saml_idp_cert: str = field(default_factory=lambda: _env("SAML_IDP_CERT"))
    saml_allow_idp_initiated: bool = field(
        default_factory=lambda: _env("SAML_ALLOW_IDP_INITIATED", "false") == "true"
    )
    saml_clock_skew: float = 120.0

    # SCIM: only the SHA-256 of the bearer token is stored.
    scim_token_sha256: str = field(default_factory=lambda: _env("SCIM_TOKEN_SHA256"))
    require_scim_provisioning: bool = field(
        default_factory=lambda: _env("REQUIRE_SCIM_PROVISIONING", "true") == "true"
    )
    role_groups: dict[str, str] = field(
        default_factory=lambda: {
            _env("ADMIN_GROUP", "SyncBridge Admins"): "admin",
            _env("OPERATOR_GROUP", "SyncBridge Operators"): "operator",
            _env("VIEWER_GROUP", "SyncBridge Viewers"): "viewer",
        }
    )

    # Sessions
    session_idle_seconds: int = 30 * 60
    session_max_seconds: int = 8 * 3600

    # Sync behaviour
    worker_max_receives: int = 8
    webhook_tolerance_seconds: int = 300

    @property
    def secure_cookies(self) -> bool:
        return self.base_url.startswith("https://")

    @property
    def acs_url(self) -> str:
        return f"{self.base_url}/saml/acs"

    @property
    def sp_entity_id(self) -> str:
        return self.saml_sp_entity_id or f"{self.base_url}/saml/metadata"

    def apply_secrets(self, secrets: dict[str, str]) -> Settings:
        mapping = {
            "SALESFORCE_CLIENT_ID": "sf_client_id",
            "SALESFORCE_CLIENT_SECRET": "sf_client_secret",
            "SALESFORCE_LOGIN_URL": "sf_login_url",
            "SALESFORCE_WEBHOOK_SECRET": "sf_webhook_secret",
            "SLACK_CLIENT_ID": "slack_client_id",
            "SLACK_CLIENT_SECRET": "slack_client_secret",
            "SLACK_SIGNING_SECRET": "slack_signing_secret",
            "SCIM_TOKEN_SHA256": "scim_token_sha256",
            "SAML_IDP_ENTITY_ID": "saml_idp_entity_id",
            "SAML_IDP_SSO_URL": "saml_idp_sso_url",
            "SAML_IDP_CERT": "saml_idp_cert",
        }
        for key, attr in mapping.items():
            if secrets.get(key):
                setattr(self, attr, secrets[key])
        return self


_settings: Settings | None = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings().apply_secrets(_load_secrets())
    return _settings
