"""SAML service provider: happy paths with Okta-shaped responses and the known attacks."""

import base64
from urllib.parse import parse_qs, urlparse

import pytest

from syncbridge.saml.mock_idp import MockIdP
from syncbridge.saml.sp import SamlError, ServiceProvider, parse_idp_metadata
from syncbridge.store.memory import MemoryStore


@pytest.fixture
def sp(settings, clock):
    return ServiceProvider(settings, MemoryStore(clock), clock)


def start_login(sp: ServiceProvider) -> str:
    url = sp.login_redirect("/#/overview")
    q = parse_qs(urlparse(url).query)
    assert q["RelayState"] == ["/#/overview"]
    return MockIdP.parse_authn_request(q["SAMLRequest"][0])["id"]


def okta_response(idp, sp, req_id, **kw):
    return idp.response(
        name_id=kw.pop("name_id", "avery@acme.example"),
        acs_url=kw.pop("acs_url", sp.s.acs_url),
        audience=kw.pop("audience", sp.s.sp_entity_id),
        in_response_to=req_id,
        attributes=kw.pop(
            "attributes",
            {
                "email": ["avery@acme.example"],
                "firstName": ["Avery"],
                "groups": ["SyncBridge Admins"],
            },
        ),
        **kw,
    )


def tamper(saml_response: str, old: str, new: str) -> str:
    xml = base64.b64decode(saml_response).decode()
    assert old in xml
    return base64.b64encode(xml.replace(old, new, 1).encode()).decode()


@pytest.mark.parametrize(
    "sign_response,sign_assertion", [(True, True), (False, True), (True, False)]
)
def test_valid_login(idp, sp, sign_response, sign_assertion):
    req_id = start_login(sp)
    ident = sp.consume(
        okta_response(idp, sp, req_id, sign_response=sign_response, sign_assertion=sign_assertion)
    )
    assert ident.name_id == "avery@acme.example"
    assert ident.groups == ["SyncBridge Admins"]
    assert ident.first("firstName") == "Avery"


def test_authn_request_targets_okta_and_acs(sp):
    url = sp.login_redirect()
    req = MockIdP.parse_authn_request(parse_qs(urlparse(url).query)["SAMLRequest"][0])
    assert url.startswith(sp.s.saml_idp_sso_url)
    assert req["acs"] == sp.s.acs_url and req["issuer"] == sp.s.sp_entity_id


def test_unsigned_response_rejected(idp, sp):
    req_id = start_login(sp)
    resp = okta_response(idp, sp, req_id, sign_response=False, sign_assertion=False)
    with pytest.raises(SamlError, match="signed"):
        sp.consume(resp)


def test_modified_nameid_breaks_signature(idp, sp):
    req_id = start_login(sp)
    resp = tamper(
        okta_response(idp, sp, req_id),
        "avery@acme.example</saml2:NameID>",
        "admin@acme.example</saml2:NameID>",
    )
    with pytest.raises(SamlError, match="signature"):
        sp.consume(resp)


def test_response_signed_by_another_key_rejected(idp, sp):
    other = MockIdP(idp.entity_id, idp.sso_url)
    req_id = start_login(sp)
    with pytest.raises(SamlError, match="signature"):
        sp.consume(okta_response(other, sp, req_id))


def test_signature_wrapping_extra_assertion_rejected(idp, sp):
    """XSW: keep the genuinely signed assertion, add an attacker assertion next to it."""
    req_id = start_login(sp)
    resp = okta_response(idp, sp, req_id, sign_response=False)
    xml = base64.b64decode(resp).decode()
    start = xml.index("<saml2:Assertion")
    evil = xml[start:].replace("avery@acme.example", "mallory@evil.example", 1)
    evil = evil[: evil.index("</saml2:Assertion>") + len("</saml2:Assertion>")]
    wrapped = xml[:start] + evil + xml[start:]
    with pytest.raises(SamlError, match="exactly one Assertion"):
        sp.consume(base64.b64encode(wrapped.encode()).decode())


def test_signature_wrapping_nested_assertion_rejected(idp, sp):
    req_id = start_login(sp)
    resp = okta_response(idp, sp, req_id, sign_response=False)
    xml = base64.b64decode(resp).decode()
    start = xml.index("<saml2:Assertion")
    original = xml[start : xml.index("</saml2p:Response>")]
    evil = original.replace("avery@acme.example", "mallory@evil.example", 1)
    hidden = f"<saml2p:Extensions>{original}</saml2p:Extensions>"
    wrapped = xml[:start] + hidden + evil + "</saml2p:Response>"
    with pytest.raises(SamlError):
        sp.consume(base64.b64encode(wrapped.encode()).decode())


def test_comment_in_nameid_does_not_truncate(idp, sp):
    """CVE-2017-11427: comments are outside the signature's canonical form. A vulnerable SP
    reads only the text before the comment and logs the attacker in as someone else."""
    req_id = start_login(sp)
    resp = okta_response(idp, sp, req_id, name_id="victim@acme.example.evil.com")
    resp = tamper(
        resp,
        "victim@acme.example.evil.com</saml2:NameID>",
        "victim@acme.example<!---->.evil.com</saml2:NameID>",
    )
    ident = sp.consume(resp)
    assert ident.name_id == "victim@acme.example.evil.com"


@pytest.mark.parametrize(
    "field,value,match",
    [
        ("audience", "https://other-app.example.com/saml/metadata", "audience"),
        ("acs_url", "https://attacker.example/saml/acs", "Destination"),
    ],
)
def test_wrong_audience_or_destination(idp, sp, field, value, match):
    req_id = start_login(sp)
    with pytest.raises(SamlError, match=match):
        sp.consume(okta_response(idp, sp, req_id, **{field: value}))


def test_wrong_issuer(idp, sp):
    req_id = start_login(sp)
    with pytest.raises(SamlError, match="Issuer"):
        sp.consume(okta_response(idp, sp, req_id, issuer="http://www.okta.com/someone-else"))


def test_expired_and_future_assertions(idp, sp):
    with pytest.raises(SamlError, match="expired"):
        sp.consume(okta_response(idp, sp, start_login(sp), issued_offset=-3600))
    with pytest.raises(SamlError, match="not yet valid"):
        sp.consume(okta_response(idp, sp, start_login(sp), issued_offset=3600))


def test_in_response_to_must_match_and_is_single_use(idp, sp):
    with pytest.raises(SamlError, match="InResponseTo"):
        sp.consume(okta_response(idp, sp, "_never-issued"))
    req_id = start_login(sp)
    resp = okta_response(idp, sp, req_id)
    sp.consume(resp)
    with pytest.raises(SamlError):
        sp.consume(resp)


def test_idp_initiated_refused_by_default_and_replay_blocked_when_allowed(idp, sp):
    resp = okta_response(idp, sp, None)
    with pytest.raises(SamlError, match="IdP-initiated"):
        sp.consume(resp)
    sp.s.saml_allow_idp_initiated = True
    resp = okta_response(idp, sp, None)
    assert sp.consume(resp).name_id == "avery@acme.example"
    with pytest.raises(SamlError, match="replayed"):
        sp.consume(resp)


def test_doctype_and_entities_rejected(sp):
    xml = (
        '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>'
        '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">&x;'
        "</samlp:Response>"
    )
    with pytest.raises(SamlError, match="DTD"):
        sp.consume(base64.b64encode(xml.encode()).decode())


def test_encrypted_assertion_rejected(sp):
    xml = (
        '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
        'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><samlp:Status><samlp:StatusCode '
        'Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>'
        "<saml:EncryptedAssertion/></samlp:Response>"
    )
    with pytest.raises(SamlError, match="encrypted"):
        sp.consume(base64.b64encode(xml.encode()).decode())


def test_failed_status_rejected(idp, sp):
    resp = tamper(okta_response(idp, sp, start_login(sp)), "status:Success", "status:Requester")
    with pytest.raises(SamlError, match="status"):
        sp.consume(resp)


def test_sp_metadata_and_idp_metadata_parsing(idp, sp):
    md = sp.metadata()
    assert sp.s.acs_url in md and 'WantAssertionsSigned="true"' in md
    parsed = parse_idp_metadata(idp.metadata().encode())
    assert parsed["entity_id"] == idp.entity_id and parsed["sso_url"] == idp.sso_url
    assert "".join(parsed["cert"].split()) == "".join(idp.cert_pem.split())
