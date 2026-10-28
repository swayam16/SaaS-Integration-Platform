"""Slack OAuth v2 install flow, with optional token rotation."""

from __future__ import annotations

from urllib.parse import urlencode

import httpx

from ..errors import PermanentError, TransientError


class SlackAuth:
    def __init__(
        self,
        http: httpx.Client,
        api_base: str,
        authorize_url: str,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        scopes: str,
    ):
        self.http = http
        self.api_base = api_base.rstrip("/")
        self.authorize_base = authorize_url
        self.client_id, self.client_secret = client_id, client_secret
        self.redirect_uri, self.scopes = redirect_uri, scopes

    def authorize_url(self, state: str) -> str:
        return (
            self.authorize_base
            + "?"
            + urlencode(
                {
                    "client_id": self.client_id,
                    "scope": self.scopes,
                    "state": state,
                    "redirect_uri": self.redirect_uri,
                }
            )
        )

    def _oauth(self, data: dict) -> dict:
        try:
            resp = self.http.post(
                f"{self.api_base}/oauth.v2.access",
                data=data,
                auth=(self.client_id, self.client_secret),
                timeout=15.0,
            )
        except httpx.TransportError as exc:
            raise TransientError(f"oauth.v2.access unreachable: {exc}") from exc
        if resp.status_code >= 500:
            raise TransientError(f"oauth.v2.access {resp.status_code}")
        body = resp.json()
        if not body.get("ok"):
            raise PermanentError(f"Slack OAuth error: {body.get('error')}")
        return body

    def exchange_code(self, code: str) -> dict:
        body = self._oauth({"code": code, "redirect_uri": self.redirect_uri})
        tokens = {
            "access_token": body["access_token"],
            "scope": body.get("scope", ""),
            "bot_user_id": body.get("bot_user_id", ""),
            "team_id": (body.get("team") or {}).get("id", ""),
            "team_name": (body.get("team") or {}).get("name", ""),
        }
        if body.get("refresh_token"):  # token rotation enabled on the app
            tokens["refresh_token"] = body["refresh_token"]
        return tokens

    def refresh(self, tokens: dict) -> dict:
        if not tokens.get("refresh_token"):
            raise PermanentError("Slack token rotation is not enabled")
        body = self._oauth(
            {"grant_type": "refresh_token", "refresh_token": tokens["refresh_token"]}
        )
        return {
            "access_token": body["access_token"],
            "refresh_token": body.get("refresh_token", tokens["refresh_token"]),
        }

    def revoke(self, token: str) -> None:
        try:
            self.http.post(
                f"{self.api_base}/auth.revoke",
                headers={"Authorization": f"Bearer {token}"},
                timeout=10.0,
            )
        except httpx.TransportError:
            pass
