"""An Okta-shaped SAML identity provider for local development and tests.

Responses look like Okta's: RSA-SHA256 signatures with exclusive C14N, the signature placed
right after the Issuer, an email-format NameID, and firstName/lastName/email/groups attributes.
It signs with a throwaway key generated at start-up. Never use it outside development.
"""

from __future__ import annotations

import base64
import datetime as dt
import secrets
import zlib
from urllib.parse import parse_qs
from xml.sax.saxutils import escape, quoteattr

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from lxml import etree
from signxml import CanonicalizationMethod, XMLSigner

from ..clock import Clock

NS_P = "urn:oasis:names:tc:SAML:2.0:protocol"
NS_A = "urn:oasis:names:tc:SAML:2.0:assertion"
NS_DS = "http://www.w3.org/2000/09/xmldsig#"


def _iso(ts: float) -> str:
    return dt.datetime.fromtimestamp(ts, tz=dt.UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def self_signed(common_name: str = "dev-idp.okta.local") -> tuple[str, str]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Okta (mock)"),
        ]
    )
    now = dt.datetime.now(dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=3650))
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode()
    return key_pem, cert.public_bytes(serialization.Encoding.PEM).decode()


class MockIdP:
    def __init__(self, entity_id: str, sso_url: str, clock: Clock | None = None):
        self.entity_id, self.sso_url = entity_id, sso_url
        self.clock = clock or Clock()
        self.key_pem, self.cert_pem = self_signed()

    def _sign(self, element: etree._Element) -> etree._Element:
        signer = XMLSigner(c14n_algorithm=CanonicalizationMethod.EXCLUSIVE_XML_CANONICALIZATION_1_0)
        return signer.sign(
            element, key=self.key_pem, cert=self.cert_pem, reference_uri=element.get("ID")
        )

    def response(
        self,
        *,
        name_id: str,
        acs_url: str,
        audience: str,
        in_response_to: str | None = None,
        attributes: dict[str, list[str]] | None = None,
        sign_response: bool = True,
        sign_assertion: bool = True,
        lifetime: float = 300.0,
        issued_offset: float = 0.0,
        issuer: str | None = None,
    ) -> str:
        now = self.clock.now() + issued_offset
        resp_id, a_id = "id" + secrets.token_hex(16), "id" + secrets.token_hex(16)
        irt = f' InResponseTo="{in_response_to}"' if in_response_to else ""
        attrs = "".join(
            f"<saml2:Attribute Name={quoteattr(k)} "
            f'NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified">'
            + "".join(
                f'<saml2:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" '
                f'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
                f'xsi:type="xs:string">{escape(v)}</saml2:AttributeValue>'
                for v in vals
            )
            + "</saml2:Attribute>"
            for k, vals in (attributes or {}).items()
        )
        ds_placeholder = f'<ds:Signature xmlns:ds="{NS_DS}" Id="placeholder"></ds:Signature>'
        assertion = (
            f'<saml2:Assertion xmlns:saml2="{NS_A}" ID="{a_id}" IssueInstant="{_iso(now)}" '
            f'Version="2.0"><saml2:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">'
            f"{escape(issuer or self.entity_id)}</saml2:Issuer>"
            f"{ds_placeholder if sign_assertion else ''}"
            f"<saml2:Subject><saml2:NameID "
            f'Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{escape(name_id)}'
            f'</saml2:NameID><saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">'
            f'<saml2:SubjectConfirmationData{irt} NotOnOrAfter="{_iso(now + lifetime)}" '
            f"Recipient={quoteattr(acs_url)}/></saml2:SubjectConfirmation></saml2:Subject>"
            f'<saml2:Conditions NotBefore="{_iso(now - 60)}" NotOnOrAfter="{_iso(now + lifetime)}">'
            f"<saml2:AudienceRestriction><saml2:Audience>{escape(audience)}</saml2:Audience>"
            f"</saml2:AudienceRestriction></saml2:Conditions>"
            f'<saml2:AuthnStatement AuthnInstant="{_iso(now)}" SessionIndex="{a_id}">'
            f"<saml2:AuthnContext><saml2:AuthnContextClassRef>"
            f"urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
            f"</saml2:AuthnContextClassRef></saml2:AuthnContext></saml2:AuthnStatement>"
            f"<saml2:AttributeStatement>{attrs}</saml2:AttributeStatement></saml2:Assertion>"
        )
        a_el = etree.fromstring(assertion)
        if sign_assertion:
            a_el = self._sign(a_el)
        response = (
            f'<saml2p:Response xmlns:saml2p="{NS_P}" Destination={quoteattr(acs_url)} ID="{resp_id}"'
            f'{irt} IssueInstant="{_iso(now)}" Version="2.0">'
            f'<saml2:Issuer xmlns:saml2="{NS_A}" '
            f'Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">{escape(self.entity_id)}'
            f"</saml2:Issuer>{ds_placeholder if sign_response else ''}"
            f'<saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>'
            f"</saml2p:Status></saml2p:Response>"
        )
        r_el = etree.fromstring(response)
        r_el.append(a_el)
        if sign_response:
            r_el = self._sign(r_el)
        return base64.b64encode(etree.tostring(r_el)).decode()

    @staticmethod
    def parse_authn_request(saml_request: str) -> dict:
        xml = zlib.decompress(base64.b64decode(saml_request), -15)
        root = etree.fromstring(xml)
        issuer = root.find(f"{{{NS_A}}}Issuer")
        return {
            "id": root.get("ID"),
            "acs": root.get("AssertionConsumerServiceURL"),
            "issuer": issuer.text if issuer is not None else "",
        }

    def metadata(self) -> str:
        cert_b64 = "".join(self.cert_pem.strip().splitlines()[1:-1])
        return (
            f'<?xml version="1.0" encoding="UTF-8"?><md:EntityDescriptor '
            f'xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID={quoteattr(self.entity_id)}>'
            f'<md:IDPSSODescriptor WantAuthnRequestsSigned="false" '
            f'protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">'
            f'<md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="{NS_DS}"><ds:X509Data>'
            f"<ds:X509Certificate>{cert_b64}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>"
            f"</md:KeyDescriptor><md:NameIDFormat>"
            f"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>"
            f'<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" '
            f"Location={quoteattr(self.sso_url)}/>"
            f'<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" '
            f"Location={quoteattr(self.sso_url)}/></md:IDPSSODescriptor></md:EntityDescriptor>"
        )

    def login_page(self, query: str, users: list[dict], acs_fallback: str) -> str:
        """Dev-only sign-in screen: pick a provisioned user, get POSTed back to the ACS."""
        q = {k: v[0] for k, v in parse_qs(query).items()}
        req = self.parse_authn_request(q["SAMLRequest"]) if "SAMLRequest" in q else {}
        rows = (
            "".join(
                f'<button name="user" value={quoteattr(u["email"])}>'
                f"<b>{escape(u['name'])}</b><span>{escape(u['email'])} · {escape(', '.join(u['groups']) or 'no groups')}"
                f"</span></button>"
                for u in users
            )
            or "<p>No users provisioned yet.</p>"
        )
        return f"""<!doctype html><html><head><meta charset="utf-8"><title>Mock Okta sign-in</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>body{{font:15px/1.5 system-ui;background:#f4f4f6;margin:0;display:grid;place-items:center;min-height:100vh}}
main{{background:#fff;border-radius:12px;padding:28px;width:min(420px,92vw);box-shadow:0 1px 3px #0002}}
h1{{font-size:18px;margin:0 0 4px}}p{{color:#666;margin:0 0 18px;font-size:13px}}
button{{display:block;width:100%;text-align:left;border:1px solid #ddd;background:#fff;border-radius:8px;
padding:10px 12px;margin:6px 0;cursor:pointer;font:inherit}}button:hover{{border-color:#1662dd}}
button span{{display:block;color:#666;font-size:12.5px}}</style></head><body><main>
<h1>Mock Okta</h1><p>Development identity provider. Choose a SCIM-provisioned user to sign in.</p>
<form method="post" action="{escape(self.sso_url)}">
<input type="hidden" name="request_id" value={quoteattr(req.get("id") or "")}>
<input type="hidden" name="acs" value={quoteattr(req.get("acs") or acs_fallback)}>
<input type="hidden" name="audience" value={quoteattr(req.get("issuer") or "")}>
<input type="hidden" name="RelayState" value={quoteattr(q.get("RelayState", ""))}>{rows}</form>
</main></body></html>"""

    @staticmethod
    def post_form(acs: str, saml_response: str, relay_state: str) -> str:
        return f"""<!doctype html><html><body onload="document.forms[0].submit()">
<form method="post" action={quoteattr(acs)}>
<input type="hidden" name="SAMLResponse" value={quoteattr(saml_response)}>
<input type="hidden" name="RelayState" value={quoteattr(relay_state)}>
<noscript><button>Continue</button></noscript></form></body></html>"""
