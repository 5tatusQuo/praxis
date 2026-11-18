"""The LLM behind the agents. Claude through the Anthropic SDK; swappable.

An agent run is: a system prompt, one task message, a set of allow-listed
tools, and a JSON schema for the final answer. `run` drives the tool loop and
returns the parsed answer. Tests use `ScriptedLLM`, which needs no network.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any, Protocol

from praxis.agents.toolbox import Tool, Toolbox

DEFAULT_MODEL = "claude-opus-5-5"
# Lets the API re-run a request on another model if a safety classifier
# declines it, instead of failing the whole agent run.
FALLBACK_BETA = "server-side-fallback-2026-07-01"


class AgentError(RuntimeError):
    pass


class LLM(Protocol):
    name: str

    def run(
        self,
        *,
        actor: str,
        system: str,
        task: str,
        toolbox: Toolbox,
        allowed: list[str],
        answer_schema: dict[str, Any],
    ) -> dict[str, Any]: ...


def _check(value: Any, schema: dict[str, Any], path: str = "input") -> None:
    """Minimal JSON-schema check for tool inputs (types, required, enum, no extras)."""
    kind = schema.get("type")
    if "enum" in schema and value not in schema["enum"]:
        raise ValueError(f"{path} must be one of {schema['enum']}")
    if kind == "object":
        if not isinstance(value, dict):
            raise ValueError(f"{path} must be an object")
        properties = schema.get("properties", {})
        for name in schema.get("required", []):
            if name not in value:
                raise ValueError(f"{path}.{name} is required")
        if schema.get("additionalProperties") is False:
            extra = sorted(set(value) - set(properties))
            if extra:
                raise ValueError(f"{path} has unknown fields {extra}")
        for name, sub in properties.items():
            if name in value:
                _check(value[name], sub, f"{path}.{name}")
    elif kind == "array":
        if not isinstance(value, list):
            raise ValueError(f"{path} must be an array")
        if len(value) < schema.get("minItems", 0):
            raise ValueError(f"{path} needs at least {schema['minItems']} item(s)")
        for index, item in enumerate(value):
            _check(item, schema.get("items", {}), f"{path}[{index}]")
    elif kind == "string" and not isinstance(value, str):
        raise ValueError(f"{path} must be a string")
    elif kind == "integer" and (not isinstance(value, int) or isinstance(value, bool)):
        raise ValueError(f"{path} must be an integer")


def run_tool(toolbox: Toolbox, tool: Tool, arguments: Any) -> tuple[str, bool]:
    """Validate the input against the tool's schema, then run it."""
    try:
        _check(arguments, tool.schema)
    except ValueError as err:
        return f"invalid input: {err}", True
    return toolbox.call(tool.name, arguments)


@dataclass
class ClaudeLLM:
    """Claude via the Anthropic SDK. Credentials come from the environment."""

    model: str = field(default_factory=lambda: os.environ.get("PRAXIS_LLM_MODEL", DEFAULT_MODEL))
    effort: str = field(default_factory=lambda: os.environ.get("PRAXIS_LLM_EFFORT", "high"))
    max_turns: int = 40
    max_tokens: int = 32000

    @property
    def name(self) -> str:
        return self.model

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
        import anthropic

        client = anthropic.Anthropic()
        registry = toolbox.tools()
        tools = [registry[name] for name in allowed]
        definitions = [
            {
                "name": t.name,
                "description": t.description,
                "input_schema": t.schema,
                # Large inputs (a whole detection) stream as they are written;
                # run_tool validates them, since the API then does not.
                "eager_input_streaming": True,
            }
            for t in tools
        ]
        messages: list[dict[str, Any]] = [{"role": "user", "content": task}]
        for _turn in range(self.max_turns):
            with client.beta.messages.stream(
                model=self.model,
                max_tokens=self.max_tokens,
                system=[{"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}],
                tools=definitions,
                messages=messages,
                thinking={"type": "adaptive"},
                output_config={
                    "effort": self.effort,
                    "format": {"type": "json_schema", "schema": answer_schema},
                },
                betas=[FALLBACK_BETA],
                fallbacks="default",
            ) as stream:
                response = stream.get_final_message()
            toolbox.audit(
                f"llm:{actor}",
                {
                    "model": response.model,
                    "stop_reason": response.stop_reason,
                    "input_tokens": response.usage.input_tokens,
                    "output_tokens": response.usage.output_tokens,
                    "cache_read_tokens": response.usage.cache_read_input_tokens,
                    "request_id": response._request_id,
                },
            )
            if response.stop_reason == "refusal":
                raise AgentError(f"{actor}: the model declined the request")
            if response.stop_reason == "max_tokens":
                raise AgentError(f"{actor}: the answer was cut off at max_tokens")
            messages.append({"role": "assistant", "content": response.content})
            if response.stop_reason == "pause_turn":
                continue
            calls = [block for block in response.content if block.type == "tool_use"]
            if not calls:
                text = "".join(b.text for b in response.content if b.type == "text")
                try:
                    return json.loads(text)
                except json.JSONDecodeError as err:
                    raise AgentError(f"{actor}: final answer was not JSON: {err}") from err
            results = []
            for block in calls:
                tool = registry.get(block.name)
                if tool is None or block.name not in allowed:
                    content, failed = f"tool {block.name!r} is not available to you", True
                else:
                    content, failed = run_tool(toolbox, tool, block.input)
                results.append(
                    {
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": content,
                        "is_error": failed,
                    }
                )
            messages.append({"role": "user", "content": results})
        raise AgentError(f"{actor}: no final answer after {self.max_turns} turns")


@dataclass
class ScriptedLLM:
    """A stand-in for tests: plays back tool calls and answers per actor."""

    # actor -> list of steps; a step is ("tool", name, arguments) or ("answer", dict)
    script: dict[str, list[tuple]]
    name: str = "scripted"
    seen: list[dict[str, Any]] = field(default_factory=list)

    def run(self, *, actor, system, task, toolbox, allowed, answer_schema) -> dict[str, Any]:
        self.seen.append({"actor": actor, "system": system, "task": task, "allowed": allowed})
        registry = toolbox.tools()
        steps = self.script[actor]
        while steps:
            step = steps.pop(0)
            if step[0] == "answer":
                answer = step[1](toolbox) if callable(step[1]) else step[1]
                _check(answer, answer_schema, "answer")
                return answer
            _, name, arguments = step
            if name not in allowed:
                raise AgentError(f"{actor} tried to use {name}, which it is not allowed")
            arguments = arguments(toolbox) if callable(arguments) else arguments
            content, failed = run_tool(toolbox, registry[name], arguments)
            self.seen.append({"actor": actor, "tool": name, "result": content, "error": failed})
        raise AgentError(f"script for {actor} ran out")


def default_llm() -> LLM:
    """Pick the provider: PRAXIS_LLM_PROVIDER, else ChatGPT when signed in, else Claude."""
    from praxis.agents import openai_llm

    provider = os.environ.get("PRAXIS_LLM_PROVIDER", "auto").lower()
    if provider == "openai" or (provider == "auto" and openai_llm.chatgpt_connected()):
        return openai_llm.OpenAILLM()
    if provider in ("auto", "anthropic", "claude"):
        return ClaudeLLM()
    raise AgentError(f"unknown PRAXIS_LLM_PROVIDER {provider!r}; use openai or anthropic")
