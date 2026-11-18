"""The Tuner: turn a noisy rule's alerts into a scoped, tested tuning proposal."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

from praxis import core
from praxis.agents.llm import LLM, AgentError
from praxis.agents.pack import COMMON, AuditTrail
from praxis.agents.toolbox import Toolbox
from praxis.content.loader import ContentRepo

TUNER = (
    COMMON
    + """
You are the Tuner. A rule is noisy for one client; find out why and propose the narrowest \
tuning that removes the noise without blinding the rule.

Look at the rule and at the client's alerts for it: totals, the most common values of key \
fields, and a few redacted samples. Benign noise usually has a clear signature, such as one \
parent process, one service account or one management tool. Real attacks rarely share it.

Tuning uses a closed set of operations. An exclusion names a field, an operator and a value. \
Make it as specific as the evidence allows: a full path beats a file name, and a file name \
beats a substring. Never exclude on something an attacker controls cheaply if a stronger \
signature is available. Each exclusion needs an example event, modelled on a real alert, \
that the untuned rule fires on and the tuned rule ignores. Give the tuning an expiry date so \
it is reviewed again.

Propose the override with the tool and read what comes back: the lab must pass (examples \
silenced, every positive test still firing) and the impact shows how many of the last 30 \
days' matches it removes. If the lab fails, the exclusion is too broad or the example is \
wrong: fix it. If the alerts look like real attacks, or there is no clear benign signature, \
do not tune: say so.

In your answer, say what you found, what you proposed, and whether the same exclusion \
belongs to this client only, to every client on this SIEM, or in the detection itself.
"""
)

TUNER_ANSWER: dict[str, Any] = {
    "type": "object",
    "properties": {
        "proposed": {"type": "boolean"},
        "findings": {"type": "string", "maxWords": 40, "maxSentenceWords": 25},
        "scope_advice": {"type": "string", "maxWords": 20, "maxSentenceWords": 25},
    },
    "required": ["proposed", "findings", "scope_advice"],
    "additionalProperties": False,
}
TUNER_TOOLS = ["read_detection", "alert_stats", "backtest", "propose_override"]


def propose_tuning(
    content_dir: Path,
    client_id: str,
    detection_id: str,
    llm: LLM,
    hint: str = "",
    progress: Callable[[str], None] = lambda message: None,
) -> tuple[dict[str, Any], AuditTrail]:
    repo = core.load_repo(content_dir)
    client = repo.clients[client_id]
    if not client.external_llm:
        raise AgentError(f"{client_id} does not allow external LLM use; no agent will run")
    trail = AuditTrail(client_id)
    box = Toolbox(content_dir, client_id, trail.recorder("ai:tuner"))
    progress("Tuner: reading the rule and its alerts")
    task = f"Client: {client_id}. Rule: {detection_id}. Work out why it is noisy and tune it."
    if hint:
        task += f" The analyst adds: {hint}"
    answer = llm.run(
        actor="tuner",
        system=TUNER,
        task=task,
        toolbox=box,
        allowed=TUNER_TOOLS,
        answer_schema=TUNER_ANSWER,
    )
    # Code has the last word: the tuning counts only if it loads and its lab passes.
    repo = core.load_repo(content_dir)
    tuned = (client_id, detection_id) in repo.client_tuning and not core.validate(repo)
    lab_ok = False
    if tuned:
        cases = [
            c for c in core.lab_test(repo, repo.detections[detection_id]) if c.scope == client_id
        ]
        lab_ok = bool(cases) and all(c.passed for c in cases)
        for each in repo.clients.values():
            core.write_lock(repo, each)
    result = {
        **answer,
        "proposed": bool(answer["proposed"] and tuned and lab_ok),
        "lab_passed": lab_ok,
        "promotable": promotable_exclusions(repo),
        "usage": trail.usage(),
    }
    return result, trail


def promotable_exclusions(repo: ContentRepo, minimum: int = 3) -> list[dict[str, Any]]:
    """The same exclusion on the same rule for several clients: lift it to a shared layer."""
    seen: dict[tuple[str, str, str, str], list[str]] = {}
    for (client_id, rule), tuning in repo.client_tuning.items():
        for exclusion in tuning.exclude:
            key = (rule, exclusion.field, exclusion.op, str(exclusion.value))
            seen.setdefault(key, []).append(client_id)
    return [
        {"rule": rule, "field": name, "op": op, "value": value, "clients": sorted(clients)}
        for (rule, name, op, value), clients in sorted(seen.items())
        if len(clients) >= minimum
    ]
