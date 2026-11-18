"""Operator actions: everything a person, or an AI working for them, does by hand.

Each function edits content files in the working tree and returns plain data,
so the CLI and the MCP server can both call it. Nothing here deploys: a change
reaches a SIEM only when its pull request is merged.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path
from typing import Any

import yaml

from praxis import __version__, attack, core
from praxis.content.loader import ContentRepo

LIFECYCLES = ("draft", "staged", "production", "deprecated")


class OpsError(ValueError):
    """Something the operator asked for cannot be done as asked; the message says why."""


def _write_yaml(path: Path, data: dict[str, Any], header: str = "") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(header + yaml.safe_dump(data, sort_keys=False, width=88))


def _checked(content_dir: Path, touched: list[Path]) -> ContentRepo:
    """Reload the content; if what was just written is not valid, say so plainly."""
    repo = core.load_repo(content_dir)
    problems = [str(i) for i in core.validate(repo) if any(str(p) in str(i.path) for p in touched)]
    if problems:
        raise OpsError("; ".join(problems))
    return repo


# -- reference lookups -----------------------------------------------------------
def attack_groups(query: str) -> list[dict[str, Any]]:
    """ATT&CK groups matching a name, an alias, an id, or words in their description.

    The description is where ATT&CK says who a group targets, so a sector word
    such as "construction" or "healthcare" finds the groups reported against it.
    """
    wanted = query.strip().lower()
    found = []
    for gid, group in attack.bundle()["groups"].items():
        names = [gid, group["name"], *group.get("aliases", [])]
        description = group.get("description", "")
        by_name = any(wanted in n.lower() for n in names)
        at = _find_word(description.lower(), wanted)
        if not by_name and at < 0:
            continue
        found.append(
            {
                "id": gid,
                "name": group["name"],
                "techniques": len(group["techniques"]),
                "matched": "name" if by_name else "description",
                # The words around the match, so a false friend ("social
                # engineering" for "engineering") is easy to spot.
                "context": description[:160]
                if by_name or at < 0
                else "..." + description[max(0, at - 70) : at + len(wanted) + 70] + "...",
            }
        )
    return sorted(found, key=lambda g: (g["matched"] != "name", g["id"]))


# Phrases that hold a sector word but say nothing about who a group targets.
FALSE_FRIENDS = {"engineering": ("social ", "reverse ")}


def _find_word(text: str, wanted: str) -> int:
    """Where `wanted` first occurs in `text`, skipping false friends. -1 if nowhere."""
    at = text.find(wanted)
    while at >= 0:
        before = text[max(0, at - 10) : at]
        if not any(before.endswith(prefix) for prefix in FALSE_FRIENDS.get(wanted, ())):
            return at
        at = text.find(wanted, at + 1)
    return -1


def sector_remove(content_dir: Path, sector: str) -> Path:
    """Delete a sector's threat profile. Refused while a client is in that sector."""
    path = content_dir / "threat-profiles" / f"{sector}.yml"
    if not path.is_file():
        raise OpsError(f"sector {sector!r} has no threat profile; see `./px sector list`")
    users = sorted(c.id for c in core.load_repo(content_dir).clients.values() if c.sector == sector)
    if users:
        raise OpsError(
            f"sector {sector!r} is used by {', '.join(users)}; offboard those clients first"
        )
    path.unlink()
    return path


def pack_remove(content_dir: Path, pack_id: str) -> Path:
    """Delete a rule pack's record. Refused while its client exists: it is that client's history."""
    repo = core.load_repo(content_dir)
    pack = repo.rule_packs.get(pack_id)
    if pack is None:
        raise OpsError(f"there is no rule pack record {pack_id!r}; see `./px status`")
    if pack.client in repo.clients:
        raise OpsError(
            f"{pack_id} belongs to client {pack.client}, which still exists; a record is only "
            "removed after its client is offboarded"
        )
    path = content_dir / "rule-packs" / f"{pack_id}.yml"
    path.unlink()
    return path


def attack_technique(technique_id: str) -> dict[str, Any]:
    if not attack.is_technique(technique_id):
        raise OpsError(f"{technique_id} is not an ATT&CK technique id")
    entry = attack.bundle()["techniques"][technique_id]
    return {"id": technique_id, **entry}


def sources(repo: ContentRepo) -> list[dict[str, Any]]:
    """Log sources the data map knows, and so the lab can generate and coverage can score."""
    return [
        {
            "platform": platform,
            "source": source,
            "name": note.name,
            "data_components": sorted(note.data_components),
        }
        for (platform, source), note in sorted(repo.datamap.items())
    ]


def source_add(
    content_dir: Path,
    source: str,
    name: str,
    components: dict[str, list[str]],
    sample: dict[str, Any],
    what_it_is: str,
    platform: str = "elastic",
) -> Path:
    """Add a log source to the data map: what it shows and what a typical event looks like.

    After this the lab can generate the source and coverage can score it.
    """
    path = content_dir / "datamap-catalog" / platform / f"{source}.md"
    if path.exists():
        raise OpsError(f"{source} already has a schema note")
    front = {
        "platform": platform,
        "source": source,
        "name": name,
        "data_components": components,
        "sample": sample,
    }
    body = (
        f"## What it is\n\n{what_it_is.strip()}\n\n"
        "## Useful queries\n\nNone recorded yet.\n\n"
        "## Analyst notes\n\nNone recorded yet.\n"
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("---\n" + yaml.safe_dump(front, sort_keys=False, width=100) + "---\n" + body)
    try:
        _checked(content_dir, [path])
    except OpsError:
        path.unlink()
        raise
    return path


# -- sectors -----------------------------------------------------------------------
def sector_add(
    content_dir: Path,
    sector: str,
    description: str,
    groups: list[str],
    techniques: dict[str, float] | None = None,
    replace: bool = False,
) -> Path:
    """Write a sector's threat profile: the ATT&CK groups that matter to it."""
    path = content_dir / "threat-profiles" / f"{sector}.yml"
    if path.exists() and not replace:
        raise OpsError(f"sector {sector!r} already has a threat profile; pass replace to overwrite")
    known = attack.bundle()["groups"]
    unknown = [g for g in groups if g not in known]
    if unknown:
        raise OpsError(f"not ATT&CK group ids: {unknown}. Look them up with `praxis attack groups`")
    lines = "".join(f"  - {g}  # {known[g]['name']}\n" for g in groups)
    profile = {"sector": sector, "description": description}
    text = yaml.safe_dump(profile, sort_keys=False, width=88) + "groups:\n" + lines
    if techniques:
        text += yaml.safe_dump({"techniques": techniques}, sort_keys=False)
    text += "references:\n  - https://attack.mitre.org/groups/\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    _checked(content_dir, [path])
    return path


# -- clients -------------------------------------------------------------------------
def needed_sources(repo: ContentRepo, client_id: str, platform: str = "elastic") -> list[str]:
    """Every log source the client's subscribed detections read."""
    found: set[str] = set()
    for bundle in repo.detections_for(repo.clients[client_id]):
        source = bundle.meta.log_sources.get(platform)
        for pattern in source.indices if source else []:
            found.add(pattern.removesuffix("-*"))
    return sorted(found)


def lab_profile(repo: ContentRepo, client_id: str, endpoints: int) -> dict[str, Any]:
    """A lab telemetry profile covering every source the client's rules need.

    Sources the data map has no note for are left out: the lab cannot
    generate them, and a rule that reads only those will show as blind.
    """
    known = {source for (_platform, source) in repo.datamap}
    rows = [
        {
            "source": source,
            "hosts": endpoints,
            "events_per_day": 300 if "process" in source else 150,
        }
        for source in needed_sources(repo, client_id)
        if source in known
    ]
    return {"sources": rows}


def client_add(
    content_dir: Path,
    client_id: str,
    name: str,
    sector: str,
    endpoints: int,
    packs: list[str] | None = None,
    connection: str = "lab",
    lab_telemetry: bool = True,
) -> dict[str, Any]:
    """Create a client: its manifest and, for the lab, a synthetic telemetry profile."""
    folder = content_dir / "clients" / client_id
    if folder.exists():
        raise OpsError(f"client {client_id!r} already exists")
    repo = core.load_repo(content_dir)
    if sector not in repo.threat_profiles:
        raise OpsError(
            f"sector {sector!r} has no threat profile, so gaps could not be ranked. Create it "
            f"first with `praxis sector add {sector} ...`. Existing sectors: "
            f"{sorted(repo.threat_profiles)}"
        )
    packs = packs if packs is not None else ["baseline"]
    unknown = [p for p in packs if p not in repo.packs]
    if unknown:
        raise OpsError(f"unknown content packs {unknown}; known: {sorted(repo.packs)}")
    safe = re.sub(r"[^a-z0-9_]", "_", client_id)
    manifest = {
        "id": client_id,
        "name": name if "fictional" in name.lower() else f"{name} (fictional)",
        "sector": sector,
        "fictional": True,
        "assets": {"endpoints": endpoints},
        "platforms": {"elastic": {"connection": connection, "space": safe, "namespace": safe}},
        "packs": packs,
    }
    manifest_path = folder / "client.yml"
    _write_yaml(manifest_path, manifest)
    written = [manifest_path]
    try:
        repo = _checked(content_dir, written)
        profile = lab_profile(repo, client_id, endpoints) if lab_telemetry else {"sources": []}
        if profile["sources"]:
            profile_path = folder / "lab" / "telemetry.yml"
            _write_yaml(
                profile_path,
                profile,
                "# Synthetic telemetry for the lab: every source this client's rules read.\n",
            )
            written.append(profile_path)
            repo = _checked(content_dir, written)
    except OpsError:
        for path in reversed(written):
            path.unlink()
        for leftover in (folder / "lab", folder):
            if leftover.is_dir() and not any(leftover.iterdir()):
                leftover.rmdir()
        raise
    written.append(core.write_lock(repo, repo.clients[client_id]))
    return {
        "client": client_id,
        "files": [str(p.relative_to(content_dir)) for p in written],
        "detections": [b.id for b in repo.detections_for(repo.clients[client_id])],
        "next": [
            f"./px client provision {client_id}",
            f"./px lab seed {client_id}",
            f'./px change submit "Onboard {client_id}"',
            "./px change merge <number>",
        ],
    }


def lab_source(
    content_dir: Path,
    client_id: str,
    source: str,
    hosts: int | None = None,
    events_per_day: int = 200,
    silent_for_days: int = 0,
    remove: bool = False,
) -> dict[str, Any]:
    """Add, change or remove a source in a client's lab telemetry profile.

    This is how the lab models what a client really sends: a source only some
    hosts report to, or one that went quiet (`silent_for_days`).
    """
    repo = core.load_repo(content_dir)
    client = repo.clients.get(client_id)
    if client is None:
        raise OpsError(f"unknown client {client_id!r}")
    known = sorted(src for (_platform, src) in repo.datamap)
    if not remove and source not in known:
        raise OpsError(f"{source!r} is not in the data map. Known sources: {known}")
    path = content_dir / "clients" / client_id / "lab" / "telemetry.yml"
    profile = yaml.safe_load(path.read_text()) if path.is_file() else {"sources": []}
    rows = [row for row in profile["sources"] if row["source"] != source]
    if remove and len(rows) == len(profile["sources"]):
        raise OpsError(f"{client_id}'s lab profile has no source {source!r}")
    if not remove:
        row: dict[str, Any] = {
            "source": source,
            "hosts": hosts or (client.assets.endpoints if client.assets else 10),
            "events_per_day": events_per_day,
        }
        if silent_for_days:
            row["silent_for_days"] = silent_for_days
        rows.append(row)
    if not rows:
        raise OpsError("a lab profile needs at least one source")
    original = path.read_text() if path.is_file() else None
    _write_yaml(path, {"sources": rows}, "# Synthetic telemetry for the lab.\n")
    try:
        _checked(content_dir, [path])
    except OpsError:
        path.write_text(original) if original else path.unlink()
        raise
    return {
        "client": client_id,
        "sources": rows,
        "next": f"./px lab seed {client_id}, then ./px change submit and merge",
    }


def client_subscribe(
    content_dir: Path,
    client_id: str,
    packs: list[str] | None = None,
    detections: list[str] | None = None,
    remove: bool = False,
) -> dict[str, Any]:
    """Add packs or single detections to a client (or take them away), and refresh its lock."""
    path = content_dir / "clients" / client_id / "client.yml"
    if not path.is_file():
        raise OpsError(f"unknown client {client_id!r}")
    manifest = yaml.safe_load(path.read_text())
    original = path.read_text()
    for key, wanted in (("packs", packs or []), ("detections", detections or [])):
        current = list(manifest.get(key) or [])
        if remove:
            current = [x for x in current if x not in wanted]
        else:
            current += [x for x in wanted if x not in current]
        if current or key in manifest:
            manifest[key] = sorted(current) if key == "detections" else current
    _write_yaml(path, manifest)
    try:
        repo = _checked(content_dir, [path])
    except OpsError:
        path.write_text(original)
        raise
    client = repo.clients[client_id]
    profile = content_dir / "clients" / client_id / "lab" / "telemetry.yml"
    if not remove:
        # Keep the lab able to feed every rule the client now runs.
        existing = yaml.safe_load(profile.read_text()) if profile.is_file() else {"sources": []}
        have = {row["source"] for row in existing["sources"]}
        hosts = client.assets.endpoints if client.assets else 10
        added = [
            r for r in lab_profile(repo, client_id, hosts)["sources"] if r["source"] not in have
        ]
        if added:
            existing["sources"] += added
            _write_yaml(profile, existing, "# Synthetic telemetry for the lab.\n")
    core.write_lock(repo, client)
    return {
        "client": client_id,
        "packs": client.packs,
        "detections": [b.id for b in repo.detections_for(client)],
    }


def client_remove(content_dir: Path, client_id: str) -> dict[str, Any]:
    """Delete a client's folder from the content, and say what is deliberately kept.

    Its SIEM side is removed by deprovisioning. The shared library is left
    alone: records are history, and a detection may serve another client later.
    """
    folder = content_dir / "clients" / client_id
    if not (folder / "client.yml").is_file():
        raise OpsError(f"unknown client {client_id!r}")
    before = core.load_repo(content_dir)
    ran = {b.id for b in before.detections_for(before.clients[client_id])}
    removed = []
    for path in sorted(folder.rglob("*"), reverse=True):
        if path.is_file():
            removed.append(str(path.relative_to(content_dir)))
            path.unlink()
        else:
            path.rmdir()
    folder.rmdir()
    after = core.load_repo(content_dir)
    in_use = {b.id for c in after.clients.values() for b in after.detections_for(c)}
    in_packs = {d for p in after.packs.values() for d in p.detections}
    return {
        "removed_files": removed,
        "kept": {
            "detections_no_client_runs_now": sorted(ran - in_use - in_packs),
            "rule_pack_records": sorted(
                p.id for p in after.rule_packs.values() if p.client == client_id
            ),
            "hunt_records": sorted(h.id for h in after.hunts.values() if client_id in h.clients),
            "sector_profile": before.clients[client_id].sector,
        },
    }


def client_show(repo: ContentRepo, client_id: str) -> dict[str, Any]:
    client = repo.clients.get(client_id)
    if client is None:
        raise OpsError(f"unknown client {client_id!r}; known: {sorted(repo.clients)}")
    return {
        **client.model_dump(mode="json", exclude_none=True),
        "detections_running": [
            {
                "id": b.id,
                "name": b.meta.name,
                "lifecycle": b.meta.lifecycle,
                "tuned": (client_id, b.id) in repo.client_tuning,
            }
            for b in repo.detections_for(client)
        ],
        "lock_is_current": core.lock_is_current(repo, client),
        "has_lab_telemetry": client_id in repo.lab_telemetry,
        "has_threat_profile": client.sector in repo.threat_profiles,
    }


# -- detections ----------------------------------------------------------------------
def detection_lifecycle(content_dir: Path, detection_id: str, lifecycle: str) -> dict[str, Any]:
    """Move a detection between draft, staged (shadow), production and deprecated."""
    if lifecycle not in LIFECYCLES:
        raise OpsError(f"lifecycle must be one of {LIFECYCLES}")
    repo = core.load_repo(content_dir)
    bundle = repo.detections.get(detection_id)
    if bundle is None:
        raise OpsError(f"unknown detection {detection_id}")
    path = bundle.path / "detection.yml"
    text = path.read_text()
    updated, count = re.subn(r"(?m)^lifecycle: \w+$", f"lifecycle: {lifecycle}", text, count=1)
    if count != 1:
        raise OpsError(f"could not find the lifecycle line in {path}")
    path.write_text(updated)
    repo = _checked(content_dir, [path])
    for client in repo.clients.values():
        core.write_lock(repo, client)
    return {"detection": detection_id, "was": bundle.meta.lifecycle, "now": lifecycle}


def next_detection_id(content_dir: Path) -> str:
    numbers = [
        int(m.group(1))
        for p in (content_dir / "detections").glob("PRX-*")
        if (m := re.match(r"PRX-(\d{6})", p.name))
    ]
    return f"PRX-{max([0, *numbers]) + 1:06d}"


# -- status ----------------------------------------------------------------------------
def _git(args: list[str], cwd: Path) -> str:
    result = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True)
    return result.stdout.strip() if result.returncode == 0 else ""


def _pack_state(repo: ContentRepo, pack_id: str) -> str:
    """A pack's state in plain words. Git is the truth; the database may lag it."""
    pack = repo.rule_packs.get(pack_id)
    if pack is None:
        return "proposed, not merged"
    if pack.client not in repo.clients:
        return "record only: its client was offboarded"
    return "merged, in shadow" if pack.status == "proposed" else pack.status


def status(content_dir: Path) -> dict[str, Any]:
    """Where everything stands: content, working tree, and the server if it is reachable."""
    repo = core.load_repo(content_dir)
    issues = core.validate(repo)
    out: dict[str, Any] = {
        "praxis": __version__,
        "attack": attack.version(),
        "content": {
            "valid": not issues,
            "issues": [str(i) for i in issues][:20],
            "detections": {
                state: sorted(b.id for b in repo.detections.values() if b.meta.lifecycle == state)
                for state in LIFECYCLES
                if any(b.meta.lifecycle == state for b in repo.detections.values())
            },
            "next_detection_id": next_detection_id(content_dir),
            "content_packs": {p.id: p.detections for p in repo.packs.values()},
            "sectors": sorted(repo.threat_profiles),
            "rule_packs": {p.id: _pack_state(repo, p.id) for p in repo.rule_packs.values()},
            "hunts": sorted(repo.hunts),
        },
        "clients": {
            c.id: {
                "sector": c.sector,
                "packs": c.packs,
                "detections": [b.id for b in repo.detections_for(c)],
                "lock_is_current": core.lock_is_current(repo, c),
                "has_lab_telemetry": c.id in repo.lab_telemetry,
            }
            for c in repo.clients.values()
        },
        "git": {
            "branch": _git(["branch", "--show-current"], content_dir),
            "uncommitted_files": len(_git(["status", "--porcelain"], content_dir).splitlines()),
        },
    }
    api = os.environ.get("PRAXIS_API_URL")
    if not api:
        out["server"] = "not connected: run this through deploy/with-server.sh to include it"
        return out
    import httpx

    headers = {"Authorization": f"Bearer {os.environ.get('PRAXIS_API_TOKEN', '')}"}
    try:
        with httpx.Client(base_url=api, headers=headers, timeout=20) as http:
            fleet = http.get("/api/fleet").json()
            llm = http.get("/api/llm").json()["chatgpt"]
            packs = http.get("/api/packs").json()
        out["server"] = {
            "reachable": True,
            "model_sign_in": {
                "chatgpt_connected": llm["connected"],
                "plan_usage": llm["plan_usage"],
                "model": llm["model"],
            },
            "coverage": {
                row["client_id"]: {
                    "taken_at": row["taken_at"],
                    **{
                        k: row["summary"][k]
                        for k in ("covered", "detection_gap", "visibility_gap", "blind_rule")
                    },
                    "threat_weighted_pct": row["summary"]["weighted_coverage_pct"],
                    "rules": row["summary"]["rules"],
                }
                for row in fleet
                if row["client_id"] in repo.clients  # an offboarded client keeps only history
            },
            "rule_pack_proposals": [
                {
                    **{k: p[k] for k in ("id", "client_id", "verdict", "pr_url")},
                    "status": _pack_state(repo, p["id"]),
                }
                for p in packs
                if p["client_id"] in repo.clients
            ],
        }
        for client_id, entry in out["clients"].items():
            entry["deployed"] = client_id in out["server"]["coverage"]
    except Exception as error:  # status must still answer when the server is down
        out["server"] = {"reachable": False, "error": str(error)[:200]}
    return out
