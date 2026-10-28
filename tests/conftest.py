import base64
import os

import pytest

os.environ.setdefault("ENVIRONMENT", "test")

from syncbridge.clock import Clock  # noqa: E402
from syncbridge.config import Settings  # noqa: E402
from syncbridge.crypto import sha256_hex  # noqa: E402
from syncbridge.saml.mock_idp import MockIdP  # noqa: E402

SCIM_TOKEN = "test-scim-token-0123456789"
BASE = "https://syncbridge.example.com"


@pytest.fixture(scope="session")
def idp():
    return MockIdP("http://www.okta.com/exk1test", "https://acme.okta.com/app/sso/saml")


@pytest.fixture
def settings(idp):
    return Settings(
        base_url=BASE,
        environment="test",
        saml_idp_entity_id=idp.entity_id,
        saml_idp_sso_url=idp.sso_url,
        saml_idp_cert=idp.cert_pem,
        scim_token_sha256=sha256_hex(SCIM_TOKEN),
        local_encryption_key=base64.b64encode(b"k" * 32).decode(),
        sf_webhook_secret="sf-secret",
        slack_signing_secret="slack-secret",
        sf_client_id="sf-client",
        sf_client_secret="sf-secret-x",
        slack_client_id="slack-client",
        slack_client_secret="slack-secret-x",
    )


@pytest.fixture
def clock():
    return Clock()
