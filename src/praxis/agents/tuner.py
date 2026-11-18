"""The Tuner: turn a noisy rule's alerts into a scoped, tested tuning proposal."""

from __future__ import annotations

from collections.abc import Callable
from datetime import date
from pathlib import Path
from typing import Any

from praxis import core
from praxis.agents.llm import LLM, AgentError
from praxis.agents.pack import COMMON, AuditTrail
from praxis.agents.toolbox import Toolbox
from praxis.content.loader import ContentRepo
from praxis.platforms import get_platform

TUNER = (
    COMMON
    + """
You are the Tuner. A rule is noisy for one client; find out why and propose the narrowest \
tuning that removes the noise without blinding the rule.

Look at the rule and at the client's alerts for it: totals, the most common values of key \
fields, and a few redacted samples. Benign noise usually has a clear signature, such as one \
parent process, one service account or one management tool. Real attacks rarely share it.

Tuning uses a closed set of operations. An exclusion is a condition on a field, plus any \
number of further conditions under `also` that must all match too. Separate exclusions are \
alternatives: each one on its own suppresses alerts. So to make an exclusion narrower, add \
conditions under `also`. A second exclusion makes the tuning wider, and a single exclusion \
on something every alert shares, such as the binary the rule is about, blinds the rule.

Make the exclusion as specific as the evidence allows: a full path beats a file name, and a \
file name beats a substring. Prefer what an attacker cannot cheaply copy. User and host names \
in the samples are pseudonyms (`id-...`), not real values, so you cannot exclude on them. \
Each exclusion needs an example event, modelled on a real alert, that the untuned rule fires \
on and the tuned rule ignores. Cite the alert ids you were shown as evidence. Set an expiry \
date within the next year so the tuning is reviewed again.

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
    task = (
        f"Today is {date.today().isoformat()}. Client: {client_id}. Rule: {detection_id}. "
        "Work out why it is noisy and tune it."
    )
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
    impact = None
    if tuned:
        # Measured by code, after the agent: what this tuning removes on 30 days of data.
        name = client.platforms.enabled()[0]
        bundle = repo.detections[detection_id]
        platform, query = get_platform(name), bundle.implementations[name].query
        sources = bundle.meta.log_sources[name].indices
        before = platform.backtest(client, query, sources)["hits"]
        after = platform.backtest(
            client, query, sources, tuning=repo.tuning_for(detection_id, client, name)
        )["hits"]
        impact = {"matches_before": before, "matches_after": after, "days": 30}
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
        "impact": impact,
        "rule_name": repo.detections[detection_id].meta.name,
        "exclusions": [
            " and ".join(f"`{c.field}` {c.op} `{c.value}`" for c in e.conditions())
            for e in repo.client_tuning[(client_id, detection_id)].exclude
        ]
        if tuned
        else [],
        "promotable": promotable_exclusions(repo),
        "usage": trail.usage(),
    }
    return result, trail


def promotable_exclusions(repo: ContentRepo, minimum: int = 3) -> list[dict[str, Any]]:
    """The same exclusion on the same rule for several clients: lift it to a shared layer."""
    seen: dict[tuple[str, str, str, str], list[str]] = {}
    for (client_id, rule), tuning in repo.client_tuning.items():
        for exclusion in tuning.exclude:
            also = "; ".join(f"{c.field} {c.op} {c.value}" for c in exclusion.also)
            key = (
                rule,
                exclusion.field,
                exclusion.op,
                str(exclusion.value) + (f" and {also}" if also else ""),
            )
            seen.setdefault(key, []).append(client_id)
    return [
        {"rule": rule, "field": name, "op": op, "value": value, "clients": sorted(clients)}
        for (rule, name, op, value), clients in sorted(seen.items())
        if len(clients) >= minimum
    ]


def report(client_id: str, detection_id: str, result: dict[str, Any]) -> str:
    """The pull-request body for a tuning proposal."""
    impact = result["impact"] or {}
    removed = impact.get("matches_before", 0) - impact.get("matches_after", 0)
    lines = [
        f"Tuning for **{result['rule_name']}** ({detection_id}) at `{client_id}`, proposed by "
        "the Tuner agent.",
        "",
        f"> {result['findings'].strip()}",
        "",
        "**Suppress an alert when**",
        *[f"- {text}" for text in result["exclusions"]],
        "",
        f"**Impact:** removes {removed} of {impact.get('matches_before', 0)} matches over the "
        f"last {impact.get('days', 30)} days; {impact.get('matches_after', 0)} remain.",
        "**Lab:** the example is silenced and every positive test still fires.",
        f"**Scope:** {result['scope_advice'].strip()}",
        "",
        "<sub>Impact and lab results are measured by code. CI repeats the lab check.</sub>",
    ]
    return "\n".join(lines) + "\n"
