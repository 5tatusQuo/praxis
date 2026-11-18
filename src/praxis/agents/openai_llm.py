"""An LLM provider on OpenAI's Responses API, paid for by a ChatGPT plan.

Used when the operator has signed in with ChatGPT in the dashboard. The access
token comes from praxis-api (which owns the sign-in and its refreshes); this
module never sees a refresh token.

Shaped by the plan-usage preview's rules: Responses API only, `store: false`
and `stream: true` on every request, the full history resent each turn, no
sampling or output-limit fields. The final answer is returned through a
`submit_answer` function tool whose parameters are the answer schema.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any

import httpx

from praxis.agents.llm import AgentError, _check, run_tool
from praxis.agents.toolbox import Toolbox

BASE_URL = "https://api.openai.com/v1"
ANSWER_TOOL = "submit_answer"
USAGE_PAGE = "https://chatgpt.com/settings/usage"
ERROR_HELP = {
    "subscription_sharing_usage_limit_exceeded": f"the ChatGPT plan's usage limit is reached; see {USAGE_PAGE}",
    "subscription_sharing_user_not_eligible": "this ChatGPT account is not eligible for plan usage in other apps",
    "subscription_sharing_usage_unavailable": "ChatGPT plan usage is temporarily unavailable; try again shortly",
    "subscription_sharing_invalid_user": "the ChatGPT sign-in is no longer valid; sign in again in the dashboard",
    "chatpass_v2_scope_not_authorized": "plan usage was not granted; sign in again in the dashboard and allow it",
}


def fetch_credential() -> dict[str, Any]:
    """Ask praxis-api for a current access token and the chosen model."""
    api = os.environ.get("PRAXIS_API_URL")
    if not api:
        raise AgentError("PRAXIS_API_URL is not set; run through deploy/with-server.sh")
    response = httpx.post(
        f"{api.rstrip('/')}/api/llm/chatgpt/token",
        headers={"Authorization": f"Bearer {os.environ.get('PRAXIS_API_TOKEN', '')}"},
        timeout=60,
    )
    if response.status_code != 200:
        detail = response.json().get("detail") if response.content else response.status_code
        raise AgentError(f"no ChatGPT credential: {detail}")
    return response.json()


def chatgpt_connected() -> bool:
    api = os.environ.get("PRAXIS_API_URL")
    if not api:
        return False
    try:
        response = httpx.get(
            f"{api.rstrip('/')}/api/llm",
            headers={"Authorization": f"Bearer {os.environ.get('PRAXIS_API_TOKEN', '')}"},
            timeout=15,
        )
        return response.status_code == 200 and bool(response.json()["chatgpt"]["plan_usage"])
    except (httpx.HTTPError, KeyError, ValueError):
        return False


def _function(name: str, description: str, parameters: dict[str, Any]) -> dict[str, Any]:
    return {"type": "function", "name": name, "description": description, "parameters": parameters}


@dataclass
class OpenAILLM:
    """Agents on a ChatGPT plan. `client` and `credential` are injectable for tests."""

    model: str | None = field(default_factory=lambda: os.environ.get("PRAXIS_OPENAI_MODEL"))
    effort: str | None = field(default_factory=lambda: os.environ.get("PRAXIS_OPENAI_EFFORT"))
    max_turns: int = 40
    client: Any = None
    credential: Any = fetch_credential

    @property
    def name(self) -> str:
        return self.model or "chatgpt-plan"

    def _client(self):
        if self.client is not None:
            return self.client
        from openai import OpenAI

        granted = self.credential()
        self.model = self.model or granted["model"]
        # The OAuth access token is sent as the bearer credential. No SDK
        # retries: the preview's errors say when to stop rather than repeat.
        return OpenAI(api_key=granted["access_token"], base_url=BASE_URL, max_retries=0)

    def _request(self, client, body: dict[str, Any], tools: list[dict[str, Any]]):
        """One streamed request. Returns (output items, usage)."""
        import openai

        def send(declared):
            return client.responses.create(**body, tools=declared, store=False, stream=True)

        try:
            try:
                stream = send(tools)
            except openai.BadRequestError as error:
                # The preview asks for function tools to be grouped in a
                # namespace; fall back to that if plain tools are refused.
                if "tool" not in str(getattr(error, "param", "") or error).lower():
                    raise
                grouped = [
                    {
                        "type": "namespace",
                        "name": "praxis",
                        "description": "PRAXIS detection engineering tools",
                        "tools": tools,
                    }
                ]
                stream = send(grouped)
            items, final = [], None
            for event in stream:
                if event.type == "response.output_item.done":
                    items.append(event.item)
                elif event.type == "response.completed":
                    final = event.response
                elif event.type in ("response.failed", "response.incomplete"):
                    error = getattr(event.response, "error", None)
                    code = getattr(error, "code", None) or event.type
                    raise AgentError(ERROR_HELP.get(code, f"the model run ended early: {code}"))
        except openai.APIStatusError as error:
            code = getattr(error, "code", None) or (getattr(error, "body", None) or {}).get("code")
            raise AgentError(
                ERROR_HELP.get(
                    code, f"OpenAI refused the request ({error.status_code}): {code or error}"
                )
            ) from error
        if final is None:
            raise AgentError("the stream ended without a completed response")
        return items or list(final.output), getattr(final, "usage", None)

    def run(
        self,
        *,
        actor: str,
        system: str,
        task: str,
        toolbox: Toolbox,
        allowed: list[str],
        answer_schema: dict[str, Any],
    ) -> dict[str, Any]:
        client = self._client()
        registry = toolbox.tools()
        tools = [_function(n, registry[n].description, registry[n].schema) for n in allowed]
        tools.append(
            _function(
                ANSWER_TOOL,
                "Give your final answer. Call this exactly once, when the work is done.",
                answer_schema,
            )
        )
        instructions = (
            f"{system}\nWhen you have finished, call the `{ANSWER_TOOL}` tool with your final "
            "answer. Do not put the final answer in plain text."
        )
        history: list[dict[str, Any]] = [
            {"type": "message", "role": "user", "content": [{"type": "input_text", "text": task}]}
        ]
        for _turn in range(self.max_turns):
            body: dict[str, Any] = {
                "model": self.model,
                "instructions": instructions,
                "input": list(history),
                # Reasoning must travel with the history, since nothing is stored.
                "include": ["reasoning.encrypted_content"],
            }
            if self.effort:
                body["reasoning"] = {"effort": self.effort}
            items, usage = self._request(client, body, tools)
            toolbox.audit(
                f"llm:{actor}",
                {
                    "model": self.model,
                    "input_tokens": getattr(usage, "input_tokens", None),
                    "output_tokens": getattr(usage, "output_tokens", None),
                },
            )
            calls = [item for item in items if item.type == "function_call"]
            history += [item.model_dump(exclude_none=True) for item in items]
            results = []
            for call in calls:
                name = call.name.rsplit(".", 1)[-1]  # a namespaced tool may arrive as praxis.name
                try:
                    arguments = json.loads(call.arguments or "{}")
                except json.JSONDecodeError:
                    arguments, text, failed = None, "arguments were not valid JSON", True
                if arguments is not None and name == ANSWER_TOOL:
                    try:
                        _check(arguments, answer_schema, "answer")
                        return arguments
                    except ValueError as error:
                        text, failed = f"invalid answer: {error}", True
                elif arguments is not None and (name not in allowed or name not in registry):
                    text, failed = f"tool {name!r} is not available to you", True
                elif arguments is not None:
                    text, failed = run_tool(toolbox, registry[name], arguments)
                results.append(
                    {
                        "type": "function_call_output",
                        "call_id": call.call_id,
                        "output": f"ERROR: {text}" if failed else text,
                    }
                )
            if not calls:
                results.append(
                    {
                        "type": "message",
                        "role": "user",
                        "content": [
                            {
                                "type": "input_text",
                                "text": f"Continue. When you are done, call `{ANSWER_TOOL}`.",
                            }
                        ],
                    }
                )
            history += results
        raise AgentError(f"{actor}: no final answer after {self.max_turns} turns")
