"""Sign in with ChatGPT: the open-source, self-hosted OAuth flow.

The user's ChatGPT plan pays for the agents' model calls. This module follows
OpenAI's "ChatGPT plan usage for open-source and locally hosted apps" docs
(developers.openai.com/siwc/token-sharing-open-source):

- a public client with PKCE and no secret; the first sign-in registers the
  app (`client_id=dynamic_agent_client`) and returns the issued client id;
- a loopback redirect on 127.0.0.1, which the dashboard serves at
  /auth/callback (open the dashboard as http://127.0.0.1:<port>, not localhost);
- tokens kept server-side in one 0600 file, written atomically, never logged;
- refreshes serialised, because the refresh token rotates on every use.

Nothing here reads the user's ChatGPT conversations: the scopes cover
identity and plan-funded Responses API requests only.
"""

from __future__ import annotations

import base64
import fcntl
import hashlib
import json
import os
import re
import secrets
import time
import uuid
from collections.abc import Callable
from contextlib import contextmanager
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

import httpx

ISSUER = "https://auth.openai.com"
AUTHORIZE_URL = f"{ISSUER}/api/accounts/authorize"
TOKEN_URL = f"{ISSUER}/api/accounts/oauth/token"
DISCOVERY_URL = f"{ISSUER}/.well-known/openid-configuration"
RESOURCE = "https://api.openai.com/v1"
REGISTRATION_CLIENT_ID = "dynamic_agent_client"
APP_NAME = "PRAXIS"
PLAN_SCOPE = "chatgpt.tokens.use.direct"
SCOPES = f"openid profile email offline_access resource.invoke {PLAN_SCOPE}"
REDIRECT_PATTERN = re.compile(r"^http://127\.0\.0\.1:\d{2,5}/auth/callback$")
# Refresh errors that mean the sign-in is gone and OAuth must be repeated.
SIGNED_OUT_ERRORS = {
    "invalid_grant",
    "invalid_refresh_token",
    "token_expired",
    "refresh_token_expired",
    "refresh_token_invalidated",
    "refresh_token_reused",
}
PENDING_TTL = 600
REFRESH_MARGIN = 300


class ChatGPTAuthError(RuntimeError):
    pass


def _state_dir() -> Path:
    return Path(os.environ.get("PRAXIS_STATE_DIR") or Path.home() / ".local/state/praxis")


def verify_id_token(token: str, client_id: str, nonce: str) -> dict[str, Any]:
    """Check signature (OpenAI's published keys), issuer, audience, expiry and nonce."""
    import jwt

    config = httpx.get(DISCOVERY_URL, timeout=20).raise_for_status().json()
    key = jwt.PyJWKClient(config["jwks_uri"]).get_signing_key_from_jwt(token)
    claims = jwt.decode(
        token,
        key.key,
        algorithms=config.get("id_token_signing_alg_values_supported", ["RS256"]),
        audience=client_id,
        issuer=config.get("issuer", ISSUER),
    )
    if claims.get("nonce") != nonce:
        raise ChatGPTAuthError("the ID token's nonce does not match this sign-in")
    return claims


class ChatGPTAuth:
    """One ChatGPT sign-in for this PRAXIS install, stored in `<state>/chatgpt.json`."""

    def __init__(
        self,
        directory: Path | None = None,
        http: httpx.Client | None = None,
        verify: Callable[[str, str, str], dict[str, Any]] = verify_id_token,
    ):
        self.directory = directory or _state_dir()
        self.path = self.directory / "chatgpt.json"
        self.http = http or httpx.Client(timeout=30)
        self.verify = verify

    # -- storage -------------------------------------------------------------
    @contextmanager
    def _locked(self):
        """Read-modify-write the credential file under an exclusive lock."""
        self.directory.mkdir(parents=True, exist_ok=True)
        with open(self.directory / "chatgpt.lock", "w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            record = json.loads(self.path.read_text()) if self.path.is_file() else {}
            changed = [False]

            def save() -> None:
                changed[0] = True

            try:
                yield record, save
            finally:
                # Saved even when the step fails: a used sign-in attempt stays
                # used, and a dead refresh token stays forgotten.
                if changed[0]:
                    temporary = self.path.with_suffix(".tmp")
                    handle = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                    with os.fdopen(handle, "w") as out:
                        json.dump(record, out)
                    os.replace(temporary, self.path)

    def _post(self, url: str, form: dict[str, str]) -> dict[str, Any]:
        response = self.http.post(url, data=form)
        try:
            body = response.json() if response.content else {}
        except ValueError:
            body = {}
        if response.status_code >= 400:
            code = body.get("error") if isinstance(body.get("error"), str) else None
            code = code or (body.get("error") or {}).get("code") or f"http_{response.status_code}"
            raise ChatGPTAuthError(code)
        return body

    # -- sign-in ---------------------------------------------------------------
    def start(self, redirect_uri: str) -> str:
        """Begin a sign-in. Returns the URL to open in the user's browser."""
        if not REDIRECT_PATTERN.match(redirect_uri):
            raise ChatGPTAuthError(
                "open the dashboard as http://127.0.0.1:<port> (not localhost or another "
                "host): ChatGPT sign-in only returns to a 127.0.0.1 address"
            )
        verifier = secrets.token_urlsafe(64)
        challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
            .rstrip(b"=")
            .decode()
        )
        state, nonce = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
        with self._locked() as (record, save):
            # The host id is chosen once, before the first sign-in, and kept.
            record.setdefault("host_id", f"urn:uuid:{uuid.uuid4()}")
            pending = {
                k: v
                for k, v in record.get("pending", {}).items()
                if v["created"] > time.time() - PENDING_TTL
            }
            pending[state] = {
                "verifier": verifier,
                "nonce": nonce,
                "redirect_uri": redirect_uri,
                "created": time.time(),
            }
            record["pending"] = pending
            save()
            client_id = record.get("client_id")
            params = {
                "client_id": client_id or REGISTRATION_CLIENT_ID,
                "ext_agent_host_id": record["host_id"],
                "response_type": "code",
                "redirect_uri": redirect_uri,
                "scope": SCOPES,
                "resource": RESOURCE,
                "state": state,
                "nonce": nonce,
                "code_challenge_method": "S256",
                "code_challenge": challenge,
            }
            if not client_id:
                params["agent_name_hint"] = APP_NAME
        return f"{AUTHORIZE_URL}?{urlencode(params)}"

    def complete(self, params: dict[str, str]) -> dict[str, Any]:
        """Finish a sign-in with the query parameters of the callback."""
        with self._locked() as (record, save):
            pending = record.get("pending", {}).pop(params.get("state", ""), None)
            save()
            if pending is None or pending["created"] < time.time() - PENDING_TTL:
                raise ChatGPTAuthError(
                    "this sign-in attempt is unknown or has expired; start again"
                )
            if params.get("error"):
                raise ChatGPTAuthError(f"sign-in was not completed: {params['error']}")
            client_id = params.get("client_id") or record.get("client_id")
            if not client_id or client_id == REGISTRATION_CLIENT_ID or not params.get("code"):
                raise ChatGPTAuthError("the callback is missing the code or the client id")
            tokens = self._post(
                TOKEN_URL,
                {
                    "grant_type": "authorization_code",
                    "client_id": client_id,
                    "code": params["code"],
                    "code_verifier": pending["verifier"],
                    "redirect_uri": pending["redirect_uri"],
                    "resource": RESOURCE,
                },
            )
            claims = self.verify(tokens["id_token"], client_id, pending["nonce"])
            granted = (tokens.get("scope") or params.get("scope") or "").split()
            record["client_id"] = client_id
            record["account"] = {
                "sub": claims["sub"],
                "email": claims.get("email"),
                "name": claims.get("name"),
            }
            record["scope"] = granted
            self._store_tokens(record, tokens)
        return self.status()

    @staticmethod
    def _store_tokens(record: dict[str, Any], tokens: dict[str, Any]) -> None:
        record["access_token"] = tokens["access_token"]
        record["refresh_token"] = tokens.get("refresh_token", record.get("refresh_token"))
        record["expires_at"] = time.time() + int(tokens.get("expires_in", 3600))
        if tokens.get("id_token"):
            record["id_token"] = tokens["id_token"]

    # -- use ---------------------------------------------------------------------
    def status(self) -> dict[str, Any]:
        """What the dashboard shows. Never includes a token."""
        record = json.loads(self.path.read_text()) if self.path.is_file() else {}
        connected = bool(record.get("refresh_token"))
        scope = record.get("scope", [])
        return {
            "connected": connected,
            "account": record.get("account") if connected else None,
            "plan_usage": connected and PLAN_SCOPE in scope,
            "model": record.get("model"),
            "registered": bool(record.get("client_id")),
        }

    def access_token(self) -> str:
        """A valid access token, refreshed when it is close to expiry."""
        with self._locked() as (record, save):
            if not record.get("refresh_token"):
                raise ChatGPTAuthError("not signed in with ChatGPT")
            if PLAN_SCOPE not in record.get("scope", []):
                raise ChatGPTAuthError(
                    "signed in, but ChatGPT plan usage was not granted; sign in again and allow it"
                )
            if record.get("expires_at", 0) - time.time() > REFRESH_MARGIN:
                return record["access_token"]
            try:
                tokens = self._post(
                    TOKEN_URL,
                    {
                        "grant_type": "refresh_token",
                        "client_id": record["client_id"],
                        "refresh_token": record["refresh_token"],
                        "resource": RESOURCE,
                    },
                )
            except ChatGPTAuthError as error:
                if str(error) in SIGNED_OUT_ERRORS:
                    self._forget(record)
                    save()
                    raise ChatGPTAuthError(
                        "the ChatGPT sign-in has expired; sign in again"
                    ) from error
                raise
            self._store_tokens(record, tokens)
            save()
            return record["access_token"]

    @staticmethod
    def _forget(record: dict[str, Any]) -> None:
        # Keep the host id and the issued client id: the next sign-in reuses them.
        for key in ("access_token", "refresh_token", "id_token", "expires_at", "scope", "account"):
            record.pop(key, None)

    def models(self) -> list[dict[str, str]]:
        """Models this account may use on its plan."""
        response = self.http.get(
            f"{RESOURCE}/models", headers={"Authorization": f"Bearer {self.access_token()}"}
        )
        response.raise_for_status()
        body = response.json()
        return [
            {"slug": m["slug"], "name": m.get("display_name") or m["slug"]}
            for m in body.get("models", [])
            if m.get("visibility") == "list"
        ]

    def set_model(self, slug: str) -> None:
        with self._locked() as (record, save):
            record["model"] = slug
            save()

    def chosen_model(self) -> str:
        """The model picked in the dashboard, or the first one the account lists."""
        record = json.loads(self.path.read_text()) if self.path.is_file() else {}
        if record.get("model"):
            return record["model"]
        available = self.models()
        if not available:
            raise ChatGPTAuthError("this ChatGPT account lists no usable model")
        return available[0]["slug"]

    def disconnect(self) -> None:
        """Revoke the refresh token at OpenAI and forget the tokens."""
        with self._locked() as (record, save):
            token, client_id = record.get("refresh_token"), record.get("client_id")
            self._forget(record)
            save()
        if token and client_id:
            config = self.http.get(DISCOVERY_URL).json()
            endpoint = config.get("revocation_endpoint")
            if endpoint:
                self.http.post(
                    endpoint,
                    data={
                        "token": token,
                        "token_type_hint": "refresh_token",
                        "client_id": client_id,
                    },
                )
