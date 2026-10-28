"""Salesforce OAuth 2.0.

* Web server flow with PKCE: an admin clicks "Connect Salesforce" in the console, approves the
  connected app, and the callback exchanges the code for an access token, a refresh token and
  the org's `instance_url`.
* Refresh token flow: access tokens expire (session timeout); the client refreshes on
  INVALID_SESSION_ID, single-flight through the TokenVault.
* JWT bearer flow (optional): server-to-server login as a dedicated integration user with a
  certificate uploaded to the connected app, for orgs that do not allow refresh tokens.
"""

from __future__ import annotations

import time
from urllib.parse import urlencode

import httpx

from ..errors import PermanentError, TransientError


class SalesforceAuth:
    def __init__(
        self,
        http: httpx.Client,
        login_url: str,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
    ):
        self.http = http
        self.login_url = login_url.rstrip("/")
        self.client_id, self.client_secret = client_id, client_secret
        self.redirect_uri = redirect_uri

    def authorize_url(self, state: str, code_challenge: str) -> str:
        return f"{self.login_url}/services/oauth2/authorize?" + urlencode(
            {
                "response_type": "code",
                "client_id": self.client_id,
                "redirect_uri": self.redirect_uri,
                "state": state,
                "scope": "api refresh_token",
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
                "prompt": "login consent",
            }
        )

    def _token(self, data: dict) -> dict:
        try:
            resp = self.http.post(
                f"{self.login_url}/services/oauth2/token",
                data=data,
                headers={"Accept": "application/json"},
                timeout=15.0,
            )
        except httpx.TransportError as exc:
            raise TransientError(f"token endpoint unreachable: {exc}") from exc
        if resp.status_code >= 500:
            raise TransientError(f"token endpoint {resp.status_code}")
        body = resp.json()
        if resp.status_code != 200:
            raise PermanentError(
                f"Salesforce OAuth error: {body.get('error')}: {body.get('error_description', '')}"
            )
        return body

    def exchange_code(self, code: str, code_verifier: str) -> dict:
        body = self._token(
            {
                "grant_type": "authorization_code",
                "code": code,
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "redirect_uri": self.redirect_uri,
                "code_verifier": code_verifier,
            }
        )
        org_id = body.get("id", "").rstrip("/").split("/")[-2] if body.get("id") else ""
        return {
            "access_token": body["access_token"],
            "refresh_token": body.get("refresh_token"),
            "instance_url": body["instance_url"],
            "id_url": body.get("id"),
            "org_id": org_id,
            "scope": body.get("scope", ""),
            "issued_at": body.get("issued_at"),
        }

    def refresh(self, tokens: dict) -> dict:
        if tokens.get("refresh_token"):
            body = self._token(
                {
                    "grant_type": "refresh_token",
                    "refresh_token": tokens["refresh_token"],
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                }
            )
        elif tokens.get("jwt_username"):
            return self.jwt_bearer(tokens["jwt_username"], tokens["jwt_private_key"])
        else:
            raise PermanentError("Salesforce session expired and no refresh method is configured")
        # A refresh response never includes a new refresh token; keep the old one.
        return {
            "access_token": body["access_token"],
            "instance_url": body.get("instance_url", tokens.get("instance_url")),
        }

    def jwt_bearer(self, username: str, private_key_pem: str) -> dict:
        import jwt

        assertion = jwt.encode(
            {
                "iss": self.client_id,
                "sub": username,
                "aud": self.login_url,
                "exp": int(time.time()) + 180,
            },
            private_key_pem,
            algorithm="RS256",
        )
        body = self._token(
            {"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer", "assertion": assertion}
        )
        return {
            "access_token": body["access_token"],
            "instance_url": body["instance_url"],
            "jwt_username": username,
            "jwt_private_key": private_key_pem,
        }

    def revoke(self, token: str) -> None:
        try:
            self.http.post(
                f"{self.login_url}/services/oauth2/revoke", data={"token": token}, timeout=10.0
            )
        except httpx.TransportError:
            pass
