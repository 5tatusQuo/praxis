"""Sign in with ChatGPT and the OpenAI provider, without touching the network."""

from __future__ import annotations

import json
import stat
import time
from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse

import httpx
import pytest

from praxis import chatgpt_auth
from praxis.agents.llm import AgentError
from praxis.agents.openai_llm import ANSWER_TOOL, OpenAILLM
from praxis.agents.toolbox import Toolbox
from praxis.chatgpt_auth import ChatGPTAuth, ChatGPTAuthError

REDIRECT = "http://127.0.0.1:3000/auth/callback"


class FakeOpenAI:
    """auth.openai.com and the models list."""

    def __init__(self):
        self.forms: list[dict] = []
        self.refresh_error: str | None = None
        self.count = 0

    def handler(self, request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/oauth/token"):
            form = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
            self.forms.append(form)
            if form["grant_type"] == "refresh_token" and self.refresh_error:
                return httpx.Response(400, json={"error": self.refresh_error})
            self.count += 1
            return httpx.Response(
                200,
                json={
                    "access_token": f"access-{self.count}",
                    "refresh_token": f"refresh-{self.count}",
                    "id_token": "id-token",
                    "expires_in": 3600,
                    "scope": chatgpt_auth.SCOPES,
                },
            )
        if request.url.path.endswith("/models"):
            assert request.headers["authorization"].startswith("Bearer access-")
            models = [
                {"slug": "gpt-test", "display_name": "GPT Test", "visibility": "list"},
                {"slug": "hidden", "display_name": "Hidden", "visibility": "hide"},
            ]
            return httpx.Response(200, json={"models": models})
        if "openid-configuration" in request.url.path:
            return httpx.Response(
                200, json={"revocation_endpoint": "https://auth.openai.com/revoke"}
            )
        if request.url.path == "/revoke":
            self.forms.append({"revoked": parse_qs(request.content.decode())["token"][0]})
            return httpx.Response(200)
        return httpx.Response(404)


@pytest.fixture
def openai_side():
    return FakeOpenAI()


@pytest.fixture
def auth(tmp_path, openai_side):
    def verify(token, client_id, nonce):
        assert token == "id-token" and client_id == "oaiapp_123" and nonce
        return {"sub": "user-1", "email": "analyst@example.invalid", "name": "A. Analyst"}

    http = httpx.Client(transport=httpx.MockTransport(openai_side.handler))
    return ChatGPTAuth(tmp_path / "state", http, verify)


def sign_in(auth) -> dict:
    query = parse_qs(urlparse(auth.start(REDIRECT)).query)
    callback = {"state": query["state"][0], "code": "the-code", "client_id": "oaiapp_123"}
    return query, auth.complete(callback)


def test_first_sign_in_registers_the_app_and_stores_tokens_privately(auth, openai_side):
    query, status = sign_in(auth)
    assert query["client_id"] == ["dynamic_agent_client"] and query["agent_name_hint"] == ["PRAXIS"]
    assert query["code_challenge_method"] == ["S256"] and query["resource"] == [
        "https://api.openai.com/v1"
    ]
    assert (
        "chatgpt.tokens.use.direct" in query["scope"][0] and "offline_access" in query["scope"][0]
    )
    assert query["ext_agent_host_id"][0].startswith("urn:uuid:")
    exchange = openai_side.forms[0]
    assert exchange["grant_type"] == "authorization_code" and exchange["client_id"] == "oaiapp_123"
    assert exchange["code_verifier"] and "client_secret" not in exchange
    assert status == {
        "connected": True,
        "account": {"sub": "user-1", "email": "analyst@example.invalid", "name": "A. Analyst"},
        "plan_usage": True,
        "model": None,
        "registered": True,
    }
    assert "token" not in json.dumps(status), "status never carries a token"
    assert stat.S_IMODE(auth.path.stat().st_mode) == 0o600
    # The next sign-in reuses the issued client id and the same host id.
    again = parse_qs(urlparse(auth.start(REDIRECT)).query)
    assert again["client_id"] == ["oaiapp_123"] and "agent_name_hint" not in again
    assert again["ext_agent_host_id"] == query["ext_agent_host_id"]


def test_only_a_loopback_callback_is_accepted(auth):
    for bad in ("http://localhost:3000/auth/callback", "https://praxis.example.com/auth/callback"):
        with pytest.raises(ChatGPTAuthError, match="127.0.0.1"):
            auth.start(bad)


def test_callback_must_match_a_pending_attempt(auth):
    with pytest.raises(ChatGPTAuthError, match="unknown or has expired"):
        auth.complete({"state": "forged", "code": "x", "client_id": "oaiapp_123"})
    state = parse_qs(urlparse(auth.start(REDIRECT)).query)["state"][0]
    with pytest.raises(ChatGPTAuthError, match="access_denied"):
        auth.complete({"state": state, "error": "access_denied"})
    with pytest.raises(ChatGPTAuthError, match="unknown or has expired"):
        auth.complete({"state": state, "code": "x", "client_id": "oaiapp_123"})  # single use


def test_access_token_refreshes_and_rotates(auth, openai_side):
    sign_in(auth)
    assert auth.access_token() == "access-1", "a fresh token is reused"
    record = json.loads(auth.path.read_text())
    record["expires_at"] = time.time() + 60
    auth.path.write_text(json.dumps(record))
    assert auth.access_token() == "access-2"
    refresh = openai_side.forms[-1]
    assert refresh["grant_type"] == "refresh_token" and refresh["refresh_token"] == "refresh-1"
    assert refresh["client_id"] == "oaiapp_123" and "scope" not in refresh
    assert json.loads(auth.path.read_text())["refresh_token"] == "refresh-2"


def test_a_dead_refresh_token_signs_out(auth, openai_side):
    sign_in(auth)
    record = json.loads(auth.path.read_text())
    auth.path.write_text(json.dumps({**record, "expires_at": 0}))
    openai_side.refresh_error = "refresh_token_reused"
    with pytest.raises(ChatGPTAuthError, match="sign in again"):
        auth.access_token()
    status = auth.status()
    assert not status["connected"] and status["registered"], "the issued client id is kept"


def test_models_choice_and_disconnect(auth, openai_side):
    sign_in(auth)
    assert auth.models() == [{"slug": "gpt-test", "name": "GPT Test"}]
    assert auth.chosen_model() == "gpt-test"
    auth.set_model("gpt-other")
    assert auth.chosen_model() == "gpt-other"
    auth.disconnect()
    assert {"revoked": "refresh-1"} in openai_side.forms
    assert not auth.status()["connected"]
    with pytest.raises(ChatGPTAuthError, match="not signed in"):
        auth.access_token()


# -- the provider -----------------------------------------------------------------
def item(**fields):
    return SimpleNamespace(**fields, model_dump=lambda exclude_none=True: dict(fields))


class FakeResponses:
    def __init__(self, turns):
        self.turns, self.requests = list(turns), []

    def create(self, **body):
        self.requests.append(body)
        items = self.turns.pop(0)
        done = [SimpleNamespace(type="response.output_item.done", item=i) for i in items]
        usage = SimpleNamespace(input_tokens=10, output_tokens=5)
        final = SimpleNamespace(output=items, usage=usage)
        return [*done, SimpleNamespace(type="response.completed", response=final)]


SCHEMA = {
    "type": "object",
    "properties": {"n": {"type": "integer"}},
    "required": ["n"],
    "additionalProperties": False,
}


def call(name, arguments, call_id):
    return item(type="function_call", name=name, arguments=json.dumps(arguments), call_id=call_id)


def test_openai_provider_runs_the_tool_loop(content):
    responses = FakeResponses(
        [
            [item(type="reasoning", encrypted_content="opaque"), call("list_detections", {}, "c1")],
            [call(ANSWER_TOOL, {"n": "wrong type"}, "c2")],
            [call("write_detection", {}, "c3"), call(ANSWER_TOOL, {"n": 1}, "c4")],
        ]
    )
    llm = OpenAILLM(model="gpt-test", client=SimpleNamespace(responses=responses))
    events = []
    box = Toolbox(content, audit=lambda action, detail: events.append(action))
    answer = llm.run(
        actor="curator", system="Be useful.", task="Count.", toolbox=box,
        allowed=["list_detections"], answer_schema=SCHEMA,
    )  # fmt: skip
    assert answer == {"n": 1}
    first, second, third = responses.requests
    assert first["store"] is False and first["stream"] is True and first["model"] == "gpt-test"
    assert "max_output_tokens" not in first and "temperature" not in first
    assert [t["name"] for t in first["tools"]] == ["list_detections", ANSWER_TOOL]
    assert first["tools"][-1]["parameters"] == SCHEMA
    # Nothing is stored at OpenAI, so reasoning and calls are sent back each turn.
    kinds = [i["type"] for i in second["input"]]
    assert kinds == ["message", "reasoning", "function_call", "function_call_output"]
    assert "PRX-000900" in second["input"][-1]["output"]
    assert third["input"][-1]["output"].startswith("ERROR: invalid answer")
    assert events.count("llm:curator") == 3 and "tool:list_detections" in events


def test_openai_provider_refuses_tools_outside_the_allow_list(content):
    responses = FakeResponses(
        [[call("write_detection", {}, "c1")], [call(ANSWER_TOOL, {"n": 2}, "c2")]]
    )
    llm = OpenAILLM(model="gpt-test", client=SimpleNamespace(responses=responses))
    llm.run(
        actor="reviewer",
        system="s",
        task="t",
        toolbox=Toolbox(content),
        allowed=[],
        answer_schema=SCHEMA,
    )
    assert "is not available to you" in responses.requests[1]["input"][-1]["output"]


def test_plan_limit_is_reported_plainly(content):
    class Limited:
        def create(self, **body):
            error = SimpleNamespace(code="subscription_sharing_usage_limit_exceeded")
            return [SimpleNamespace(type="response.failed", response=SimpleNamespace(error=error))]

    llm = OpenAILLM(model="gpt-test", client=SimpleNamespace(responses=Limited()))
    with pytest.raises(AgentError, match="usage limit is reached"):
        llm.run(
            actor="a",
            system="s",
            task="t",
            toolbox=Toolbox(content),
            allowed=[],
            answer_schema=SCHEMA,
        )


def test_provider_choice(monkeypatch):
    from praxis.agents import llm, openai_llm

    monkeypatch.setenv("PRAXIS_LLM_PROVIDER", "openai")
    assert isinstance(llm.default_llm(), OpenAILLM)
    monkeypatch.setenv("PRAXIS_LLM_PROVIDER", "anthropic")
    assert isinstance(llm.default_llm(), llm.ClaudeLLM)
    monkeypatch.setenv("PRAXIS_LLM_PROVIDER", "auto")
    monkeypatch.setattr(openai_llm, "chatgpt_connected", lambda: True)
    assert isinstance(llm.default_llm(), OpenAILLM), "a ChatGPT sign-in wins when nothing is forced"
