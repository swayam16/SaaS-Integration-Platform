"""SAML 2.0 service provider for the admin console (Okta as identity provider).

SP-initiated login (HTTP-Redirect binding) and the Assertion Consumer Service (HTTP-POST
binding). The ACS treats the response as hostile until proven otherwise:

* XML parsed with entity resolution, network access and DTDs disabled; comments are stripped
  before anything is read (CVE-2017-11427-style NameID truncation).
* The signature is verified against the pinned Okta certificate with signxml (SHA-1 rejected).
  Claims are read **only** from the element signxml returns as signed, never from the original
  tree, which defeats XML signature wrapping. The signature must sit where SAML puts it: as a
  direct child of the Response or of the single Assertion.
* Issuer, Destination, Audience, Recipient, NotBefore/NotOnOrAfter (two minutes of clock skew),
  bearer subject confirmation and Status are all checked.
* InResponseTo must match a request this SP issued in the last ten minutes, consumed once.
  IdP-initiated logins (Okta dashboard tiles) are refused unless explicitly enabled.
* Each assertion ID is accepted once (replay cache until the assertion expires).
* Encrypted assertions are rejected rather than silently ignored.
"""

from __future__ import annotations

import base64
import secrets
import zlib
from dataclasses import dataclass, field
from datetime import UTC, datetime
from urllib.parse import urlencode
from xml.sax.saxutils import escape, quoteattr

from lxml import etree
from signxml import SignatureConfiguration, XMLVerifier
from signxml.exceptions import InvalidInput, InvalidSignature

from ..clock import Clock
from ..config import Settings
from ..store import ConditionFailed, Store

NS = {
    "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
    "md": "urn:oasis:names:tc:SAML:2.0:metadata",
}
REQUESTS = "saml_requests"
REPLAY = "saml_replay"
MAX_RESPONSE_BYTES = 256 * 1024
BEARER = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success"
EMAIL_FORMAT = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"


class SamlError(Exception):
    """Login rejected. The message is logged; users see a generic error."""


@dataclass
class SamlIdentity:
    name_id: str
    name_id_format: str
    issuer: str
    assertion_id: str
    session_index: str = ""
    session_not_on_or_after: float | None = None
    attributes: dict[str, list[str]] = field(default_factory=dict)

    def first(self, *names: str) -> str:
        for n in names:
            if self.attributes.get(n):
                return self.attributes[n][0]
        return ""

    @property
    def groups(self) -> list[str]:
        return self.attributes.get("groups", [])


def _parser() -> etree.XMLParser:
    return etree.XMLParser(
        resolve_entities=False,
        no_network=True,
        remove_comments=True,
        remove_pis=True,
        huge_tree=False,
        load_dtd=False,
    )


def _ts(value: str | None) -> float | None:
    if not value:
        return None
    value = value.strip().replace("Z", "+00:00")
    return datetime.fromisoformat(value).timestamp()


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _text(el) -> str:
    return "" if el is None else etree.tostring(el, method="text", encoding="unicode").strip()


class ServiceProvider:
    def __init__(self, settings: Settings, store: Store, clock: Clock):
        self.s, self.store, self.clock = settings, store, clock

    # --- SP-initiated login -------------------------------------------------------------------

    def login_redirect(self, relay_state: str = "") -> str:
        if not self.s.saml_idp_sso_url:
            raise SamlError("SAML is not configured")
        req_id = "_" + secrets.token_hex(20)
        now = self.clock.now()
        xml = (
            f'<samlp:AuthnRequest xmlns:samlp="{NS["samlp"]}" xmlns:saml="{NS["saml"]}" '
            f'ID="{req_id}" Version="2.0" IssueInstant="{_iso(now)}" '
            f"Destination={quoteattr(self.s.saml_idp_sso_url)} "
            f"AssertionConsumerServiceURL={quoteattr(self.s.acs_url)} "
            f'ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">'
            f"<saml:Issuer>{escape(self.s.sp_entity_id)}</saml:Issuer>"
            f'<samlp:NameIDPolicy Format="{EMAIL_FORMAT}" AllowCreate="true"/>'
            f"</samlp:AuthnRequest>"
        )
        self.store.put(REQUESTS, req_id, {"created": now}, [("not_exists",)], ttl=now + 600)
        deflated = zlib.compress(xml.encode())[2:-4]  # raw DEFLATE, per the Redirect binding
        params = {"SAMLRequest": base64.b64encode(deflated).decode()}
        if relay_state:
            params["RelayState"] = relay_state
        sep = "&" if "?" in self.s.saml_idp_sso_url else "?"
        return self.s.saml_idp_sso_url + sep + urlencode(params)

    # --- Assertion Consumer Service ------------------------------------------------------------

    def consume(self, saml_response: str) -> SamlIdentity:
        try:
            raw = base64.b64decode(saml_response, validate=False)
        except (ValueError, TypeError) as exc:
            raise SamlError("SAMLResponse is not base64") from exc
        if len(raw) > MAX_RESPONSE_BYTES:
            raise SamlError("SAMLResponse too large")
        if b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper():
            raise SamlError("DTDs are not allowed")
        try:
            root = etree.fromstring(raw, parser=_parser())
        except etree.XMLSyntaxError as exc:
            raise SamlError("malformed XML") from exc
        if root.tag != f"{{{NS['samlp']}}}Response":
            raise SamlError("not a SAML Response")
        if root.find("saml:EncryptedAssertion", NS) is not None:
            raise SamlError("encrypted assertions are not supported; disable encryption in Okta")

        status = root.find("samlp:Status/samlp:StatusCode", NS)
        if status is None or status.get("Value") != SUCCESS:
            raise SamlError(
                f"IdP returned status {None if status is None else status.get('Value')}"
            )
        destination = root.get("Destination")
        if destination and destination != self.s.acs_url:
            raise SamlError(f"wrong Destination {destination!r}")

        assertion = self._verified_assertion(root)
        return self._validate_assertion(assertion)

    def _verify(self, element) -> etree._Element:
        if not self.s.saml_idp_cert:
            raise SamlError("no IdP signing certificate configured")
        try:
            result = XMLVerifier().verify(
                element,
                x509_cert=self.s.saml_idp_cert,
                expect_config=SignatureConfiguration(location="./", expect_references=1),
            )
        except (InvalidSignature, InvalidInput) as exc:
            raise SamlError(f"signature check failed: {exc}") from exc
        except Exception as exc:  # signxml raises several types for malformed input
            raise SamlError(f"signature check failed: {type(exc).__name__}: {exc}") from exc
        return result.signed_xml

    def _verified_assertion(self, root) -> etree._Element:
        assertions = root.findall("saml:Assertion", NS)
        if len(assertions) != 1 or len(root.findall(".//saml:Assertion", NS)) != 1:
            raise SamlError("expected exactly one Assertion")
        if root.find("ds:Signature", NS) is not None:
            signed = self._verify(root)
            if signed.tag != root.tag or signed.get("ID") != root.get("ID"):
                raise SamlError("signature does not cover the Response")
            inner = signed.findall("saml:Assertion", NS)
            if len(inner) != 1:
                raise SamlError("signed Response must contain exactly one Assertion")
            assertion = inner[0]
            if assertion.find("ds:Signature", NS) is not None:
                # Also signed on its own: check that too, from a standalone copy.
                self._verify(etree.fromstring(etree.tostring(assertion), parser=_parser()))
            return assertion
        standalone = etree.fromstring(etree.tostring(assertions[0]), parser=_parser())
        if standalone.find("ds:Signature", NS) is None:
            raise SamlError("neither the Response nor the Assertion is signed")
        signed = self._verify(standalone)
        if signed.tag != f"{{{NS['saml']}}}Assertion" or signed.get("ID") != assertions[0].get(
            "ID"
        ):
            raise SamlError("signature does not cover the Assertion")
        return signed

    def _validate_assertion(self, a) -> SamlIdentity:
        now, skew = self.clock.now(), self.s.saml_clock_skew
        issuer = _text(a.find("saml:Issuer", NS))
        if issuer != self.s.saml_idp_entity_id:
            raise SamlError(f"unexpected Issuer {issuer!r}")

        cond = a.find("saml:Conditions", NS)
        if cond is None:
            raise SamlError("assertion has no Conditions")
        nb, noa = _ts(cond.get("NotBefore")), _ts(cond.get("NotOnOrAfter"))
        if nb is not None and now + skew < nb:
            raise SamlError("assertion not yet valid")
        if noa is None or now - skew >= noa:
            raise SamlError("assertion expired")
        audiences = [_text(x) for x in cond.findall("saml:AudienceRestriction/saml:Audience", NS)]
        if self.s.sp_entity_id not in audiences:
            raise SamlError(f"audience {audiences} does not include this SP")

        subject = a.find("saml:Subject", NS)
        name_id_el = None if subject is None else subject.find("saml:NameID", NS)
        name_id = _text(name_id_el)
        if not name_id:
            raise SamlError("assertion has no NameID")
        confirmations = [] if subject is None else subject.findall("saml:SubjectConfirmation", NS)
        data = None
        for sc in confirmations:
            if sc.get("Method") == BEARER:
                data = sc.find("saml:SubjectConfirmationData", NS)
                break
        if data is None:
            raise SamlError("no bearer SubjectConfirmation")
        if data.get("Recipient") != self.s.acs_url:
            raise SamlError(f"wrong Recipient {data.get('Recipient')!r}")
        sc_noa = _ts(data.get("NotOnOrAfter"))
        if sc_noa is None or now - skew >= sc_noa:
            raise SamlError("subject confirmation expired")
        in_response_to = data.get("InResponseTo")
        if in_response_to:
            if self.store.get(REQUESTS, in_response_to) is None:
                raise SamlError("InResponseTo does not match a pending login")
            try:
                self.store.delete(REQUESTS, in_response_to, [("exists",)])
            except ConditionFailed:
                raise SamlError("login request already used") from None
        elif not self.s.saml_allow_idp_initiated:
            raise SamlError("IdP-initiated login is disabled; start from the console")

        assertion_id = a.get("ID") or ""
        try:
            self.store.put(
                REPLAY, assertion_id, {"seen": now}, [("not_exists",)], ttl=max(noa, sc_noa) + skew
            )
        except ConditionFailed:
            raise SamlError("assertion replayed") from None

        attrs: dict[str, list[str]] = {}
        for attr in a.findall("saml:AttributeStatement/saml:Attribute", NS):
            attrs[attr.get("Name", "")] = [
                _text(v) for v in attr.findall("saml:AttributeValue", NS)
            ]
        authn = a.find("saml:AuthnStatement", NS)
        return SamlIdentity(
            name_id=name_id,
            name_id_format=name_id_el.get("Format", "") if name_id_el is not None else "",
            issuer=issuer,
            assertion_id=assertion_id,
            session_index=authn.get("SessionIndex", "") if authn is not None else "",
            session_not_on_or_after=_ts(authn.get("SessionNotOnOrAfter"))
            if authn is not None
            else None,
            attributes=attrs,
        )

    # --- metadata ----------------------------------------------------------------------------------

    def metadata(self) -> str:
        return (
            f'<?xml version="1.0"?>\n<md:EntityDescriptor xmlns:md="{NS["md"]}" '
            f"entityID={quoteattr(self.s.sp_entity_id)}>"
            f'<md:SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true" '
            f'protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">'
            f"<md:NameIDFormat>{EMAIL_FORMAT}</md:NameIDFormat>"
            f'<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" '
            f'Location={quoteattr(self.s.acs_url)} index="0" isDefault="true"/>'
            f"</md:SPSSODescriptor></md:EntityDescriptor>"
        )


def parse_idp_metadata(xml: bytes) -> dict[str, str]:
    """Read entity ID, SSO URL and signing certificate from Okta's IdP metadata."""
    root = etree.fromstring(xml, parser=_parser())
    idp = root.find("md:IDPSSODescriptor", NS)
    if idp is None:
        raise SamlError("not IdP metadata")
    sso = None
    for svc in idp.findall("md:SingleSignOnService", NS):
        if svc.get("Binding", "").endswith("HTTP-Redirect"):
            sso = svc.get("Location")
    cert = None
    for kd in idp.findall("md:KeyDescriptor", NS):
        if kd.get("use") in (None, "signing"):
            cert = _text(kd.find(".//ds:X509Certificate", NS))
            break
    if not sso or not cert:
        raise SamlError("metadata is missing the SSO URL or signing certificate")
    pem = (
        "-----BEGIN CERTIFICATE-----\n"
        + "\n".join(
            cert.replace("\n", "")[i : i + 64] for i in range(0, len(cert.replace("\n", "")), 64)
        )
        + "\n-----END CERTIFICATE-----\n"
    )
    return {"entity_id": root.get("entityID", ""), "sso_url": sso, "cert": pem}
