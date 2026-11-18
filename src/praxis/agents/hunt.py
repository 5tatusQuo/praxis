"""The Hunt Planner: a threat prompt in, tested hypotheses and read-only findings out."""

from __future__ import annotations

import re
from collections.abc import Callable
from datetime import date
from pathlib import Path
from typing import Any

import yaml

from praxis import core
from praxis.agents.llm import LLM, AgentError
from praxis.agents.pack import COMMON, AuditTrail
from praxis.agents.toolbox import Toolbox

HUNTER = (
    COMMON
    + """
You are the Hunt Planner. An analyst gives you a threat: an actor, a campaign or a way of \
working. Turn it into hunt hypotheses and test each one, read-only, against the clients in \
scope.

Ground the hunt in what the actor is reported to do: look the group up to get its ATT&CK \
techniques, and check each client's coverage so you spend effort where they can see but do \
not yet detect. A hypothesis is one specific, testable statement about behaviour ("help-desk \
tooling was used to reset MFA for a privileged account"), tied to a technique, with a native \
query that would surface it. Aim for a handful of sharp hypotheses over a long list.

Run every query against every client in scope and read what comes back. Hits are leads, not \
verdicts: say what you see and what an analyst should check next. No hits is also a finding. \
Note which hypotheses you could not test because the telemetry is missing.

Mark a hypothesis `durable` when its query describes behaviour that would stay suspicious \
next year and was quiet enough on these clients to run as a detection. Those are candidates \
for a hunt pack. Indicator sweeps and one-off checks are not durable.
"""
)

HUNT_ANSWER: dict[str, Any] = {
    "type": "object",
    "properties": {
        "summary": {"type": "string", "maxWords": 40, "maxSentenceWords": 25},
        "hypotheses": {
            "type": "array",
            "maxItems": 6,
            "items": {
                "type": "object",
                "properties": {
                    "title": {"type": "string", "maxWords": 10},
                    "technique": {"type": "string"},
                    "rationale": {"type": "string", "maxWords": 25, "maxSentenceWords": 25},
                    "query": {"type": "string"},
                    "indices": {"type": "array", "items": {"type": "string"}},
                    "assessment": {"type": "string", "maxWords": 30, "maxSentenceWords": 25},
                    "durable": {"type": "boolean"},
                },
                "required": [
                    "title", "technique", "rationale", "query", "indices", "assessment", "durable",
                ],
                "additionalProperties": False,
            },
        },
    },
    "required": ["summary", "hypotheses"],
    "additionalProperties": False,
}  # fmt: skip
HUNT_TOOLS = [
    "get_coverage", "list_detections", "attack_group", "search_catalog", "get_candidate",
    "run_hunt_query",
]  # fmt: skip


def select_clients(repo, clients: list[str] | None, sector: str | None) -> list[str]:
    """Explicit clients, or every client in a sector. LLM-disabled clients are left out."""
    if clients:
        unknown = sorted(set(clients) - set(repo.clients))
        if unknown:
            raise AgentError(f"unknown clients: {unknown}")
        chosen = clients
    elif sector:
        chosen = sorted(c.id for c in repo.clients.values() if c.sector == sector)
    else:
        raise AgentError("name the clients, or a sector to fan out to")
    allowed = [c for c in chosen if repo.clients[c].external_llm]
    if not allowed:
        raise AgentError("no client in scope allows external LLM use")
    return allowed


def run_hunt(
    content_dir: Path,
    prompt: str,
    client_ids: list[str],
    llm: LLM,
    progress: Callable[[str], None] = lambda message: None,
) -> tuple[dict[str, Any], AuditTrail]:
    repo = core.load_repo(content_dir)
    trail = AuditTrail(",".join(client_ids))
    box = Toolbox(content_dir, None, trail.recorder("ai:hunt-planner"), scope=set(client_ids))
    progress(f"Hunt Planner: planning across {', '.join(client_ids)}")
    sectors = sorted({repo.clients[c].sector for c in client_ids})
    answer = llm.run(
        actor="hunt-planner",
        system=HUNTER,
        task=(
            f"Threat: {prompt}\nClients in scope: {', '.join(client_ids)} "
            f"(sectors: {', '.join(sectors)}). Plan the hunt, run it, and report."
        ),
        toolbox=box,
        allowed=HUNT_TOOLS,
        answer_schema=HUNT_ANSWER,
    )
    # Results in the record come from the code's own log of the queries that ran.
    ran = box.hunt_results
    hypotheses = []
    for hypothesis in answer["hypotheses"]:
        results = {
            client: ran.get((client, hypothesis["query"].strip()))
            for client in client_ids
            if (client, hypothesis["query"].strip()) in ran
        }
        hypotheses.append({**hypothesis, "results": results, "tested": bool(results)})
    slug = re.sub(r"[^a-z0-9]+", "-", prompt.lower()).strip("-")[:48].strip("-")
    # Two hunts on one day can start with the same words; never overwrite a record.
    hunt_id, n = f"{date.today().isoformat()}-{slug}", 1
    while (content_dir / "hunts" / f"{hunt_id}.yml").exists():
        n += 1
        hunt_id = f"{date.today().isoformat()}-{slug}-{n}"
    hunt = {
        "id": hunt_id,
        "prompt": prompt,
        "created": date.today().isoformat(),
        "clients": client_ids,
        "summary": answer["summary"],
        "hypotheses": hypotheses,
        "agents": {"model": llm.name},
        "usage": trail.usage(),
    }
    path = content_dir / "hunts" / f"{hunt['id']}.yml"
    path.parent.mkdir(exist_ok=True)
    path.write_text(yaml.safe_dump(hunt, sort_keys=False, width=100))
    return hunt, trail


def report(hunt: dict[str, Any]) -> str:
    lines = [
        f"Hunt **{hunt['id']}** across {', '.join(f'`{c}`' for c in hunt['clients'])}, planned "
        f"and run read-only by the Hunt Planner agent ({hunt['agents']['model']}).",
        "",
        f"> {hunt['prompt']}",
        "",
        "## Summary",
        "",
        hunt["summary"].strip(),
        "",
        "## Hypotheses",
        "",
        "| Hypothesis | Technique | Hits per client | Durable |",
        "| --- | --- | --- | --- |",
    ]
    for h in hunt["hypotheses"]:
        hits = ", ".join(f"{c}: {r['hits']}" for c, r in h["results"].items()) or "not tested"
        lines.append(
            f"| {h['title']} | {h['technique']} | {hits} | {'yes' if h['durable'] else 'no'} |"
        )
    for h in hunt["hypotheses"]:
        lines += [
            "",
            f"**{h['title']}** ({h['technique']}): {h['assessment'].strip()}",
            "",
            "```",
            h["query"].strip(),
            "```",
        ]
    durable = [h["title"] for h in hunt["hypotheses"] if h["durable"]]
    lines += [
        "",
        "## Next step",
        "",
        (
            f"{len(durable)} hypothesis(es) look durable enough to become detections: "
            + "; ".join(durable)
            + ". Turn one into a detection with `./px detection write`, or let `./px pack plan` pick them up."
            if durable
            else "No hypothesis was marked durable; this hunt is a record of what was checked."
        ),
        "",
        "Hit counts were recorded by code from the queries that actually ran, read-only, with "
        f"each client's read identity. Record: `hunts/{hunt['id']}.yml`.",
    ]
    return "\n".join(lines) + "\n"
