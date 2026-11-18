"""Shipping a change: branch, pull request, checks, merge, deploy.

Thin, non-interactive wrappers over `git` and the GitHub CLI, so a person or an
AI can ship a change with three commands and read the outcome as data. Merging
is what deploys, so `merge` also waits for the deploy and reports its result.
"""

from __future__ import annotations

import json
import re
import subprocess
import time
from pathlib import Path
from typing import Any

from praxis.agents.gitops import GitError, repo_root

MAIN = "main"
DEPLOY_WORKFLOW = "praxis-cd.yml"


def _run(args: list[str], cwd: Path, check: bool = True, stdin: str | None = None) -> str:
    result = subprocess.run(args, cwd=cwd, capture_output=True, text=True, input=stdin)
    if check and result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()[:500]
        raise GitError(f"`{' '.join(args[:4])}` failed: {detail}")
    return result.stdout.strip()


def _json(args: list[str], cwd: Path) -> Any:
    out = _run(args, cwd, check=False)
    return json.loads(out) if out else []


def submit(path: Path, title: str, body: str = "") -> dict[str, Any]:
    """Commit everything in the working tree to a branch and open a pull request."""
    root = repo_root(path)
    if not _run(["git", "status", "--porcelain"], root):
        raise GitError("there is nothing to submit: the working tree has no changes")
    branch = _run(["git", "branch", "--show-current"], root)
    if branch == MAIN:
        slug = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")[:48] or "change"
        branch = f"change/{slug}"
        _run(["git", "checkout", "-q", "-b", branch], root)
    _run(["git", "add", "-A"], root)
    _run(["git", "commit", "-q", "-m", title + (f"\n\n{body}" if body else "")], root)
    _run(["git", "push", "-q", "-u", "origin", branch], root)
    existing = _json(["gh", "pr", "list", "--head", branch, "--json", "number,url"], root)
    if existing:
        return {"branch": branch, "pull_request": existing[0]["number"], "url": existing[0]["url"]}
    url = _run(
        ["gh", "pr", "create", "--title", title, "--body-file", "-", "--head", branch],
        root,
        stdin=body or title,
    ).splitlines()[-1]
    return {
        "branch": branch,
        "pull_request": int(url.rstrip("/").rsplit("/", 1)[-1]),
        "url": url,
        "next": "praxis change merge <number> waits for the checks, merges and reports the deploy",
    }


def _checks(root: Path, number: int) -> list[dict[str, str]]:
    return _json(["gh", "pr", "checks", str(number), "--json", "name,bucket"], root)


def status(path: Path, number: int | None = None) -> Any:
    """Checks of one pull request, or the list of open pull requests."""
    root = repo_root(path)
    if number is None:
        return _json(["gh", "pr", "list", "--json", "number,title,headRefName,url,author"], root)
    view = _json(["gh", "pr", "view", str(number), "--json", "state,title,headRefName,url"], root)
    if not view:
        raise GitError(f"there is no pull request {number}")
    return {**view, "checks": {c["name"]: c["bucket"] for c in _checks(root, number)}}


def merge(path: Path, number: int, wait: int = 900) -> dict[str, Any]:
    """Wait for checks, merge, then wait for the deploy the merge triggers."""
    root = repo_root(path)
    deadline = time.monotonic() + wait
    view = _json(["gh", "pr", "view", str(number), "--json", "state,headRefName"], root)
    if not view:
        raise GitError(f"there is no pull request {number}")
    if view["state"] != "OPEN":
        raise GitError(f"pull request {number} is {view['state'].lower()}, not open")
    checks: list[dict[str, str]] = []
    while time.monotonic() < deadline:
        checks = _checks(root, number)
        if checks and not any(c["bucket"] == "pending" for c in checks):
            break
        time.sleep(8)
    summary = {c["name"]: c["bucket"] for c in checks}
    failed = [name for name, bucket in summary.items() if bucket not in ("pass", "skipping")]
    if not checks or failed:
        reason = (
            "checks did not finish in time"
            if not checks or "pending" in summary.values()
            else "a check failed"
        )
        return {"ok": False, "merged": False, "reason": reason, "checks": summary}
    _run(["gh", "pr", "merge", str(number), "--merge", "--delete-branch"], root)
    _run(["git", "checkout", "-q", MAIN], root)
    _run(["git", "pull", "-q"], root)
    sha = _run(["git", "rev-parse", "HEAD"], root)
    result: dict[str, Any] = {"ok": True, "merged": True, "commit": sha[:7], "checks": summary}

    run = None
    for _ in range(10):  # the deploy run appears a few seconds after the merge, if at all
        runs = _json(
            ["gh", "run", "list", "--workflow", DEPLOY_WORKFLOW, "--commit", sha,
             "--json", "databaseId,status,conclusion,url"],
            root,
        )  # fmt: skip
        if runs:
            run = runs[0]
            break
        time.sleep(4)
    if run is None:
        result["deploy"] = "none: this change touched nothing that deploys"
        return result
    while run["status"] != "completed" and time.monotonic() < deadline:
        time.sleep(10)
        run = _json(
            [
                "gh",
                "run",
                "view",
                str(run["databaseId"]),
                "--json",
                "databaseId,status,conclusion,url",
            ],
            root,
        )
    log = _run(["gh", "run", "view", str(run["databaseId"]), "--log"], root, check=False)
    lines = []
    for line in log.splitlines():
        text = line.split("Z ", 1)[-1].strip()
        if re.match(
            r"^│ PRX-\d{6} │ (created|updated|unchanged|deleted|succeeded|failed|timeout|no telemetry|drift|missing|disabled)",
            text,
        ):
            job = line.split("\t", 1)[0]
            cells = [c.strip() for c in text.strip("│").split("│")]
            lines.append(f"{job}: {cells[0]} {cells[1]}")
    result["deploy"] = {
        "status": run["status"],
        "conclusion": run.get("conclusion") or "still running",
        "url": run["url"],
        "rules": lines,
    }
    result["ok"] = run.get("conclusion") == "success"
    return result
