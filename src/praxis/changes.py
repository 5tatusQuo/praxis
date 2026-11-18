"""Shipping a change: branch, pull request, checks, merge, deploy.

Thin, non-interactive wrappers over `git` and the GitHub CLI, so a person or an
AI can ship a change with three commands and read the outcome as data. Merging
is what deploys, so `merge` also waits for the deploy and reports its result.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
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


def _say(message: str) -> None:
    """Progress for whoever is waiting. On stderr, so --json output stays clean."""
    print(f"[praxis] {message}", file=sys.stderr, flush=True)


def home(path: Path) -> dict[str, Any]:
    """Go back to an up-to-date `main`. Refuses to leave uncommitted work behind."""
    root = repo_root(path)
    dirty = _run(["git", "status", "--porcelain"], root)
    if dirty:
        raise GitError(
            "there are uncommitted changes; ship them with `./px change submit` or discard "
            "them before going back to main"
        )
    was = _run(["git", "branch", "--show-current"], root)
    _run(["git", "checkout", "-q", MAIN], root)
    _run(["git", "pull", "-q", "--ff-only"], root)
    return {
        "was_on": was,
        "now_on": MAIN,
        "commit": _run(["git", "rev-parse", "--short", "HEAD"], root),
    }


def submit(path: Path, title: str, body: str = "", everything: bool = False) -> dict[str, Any]:
    """Commit the content changes to a branch and open a pull request.

    Only files under the content folder are included, so scratch files next to
    them (a spec, an events file) never end up in a pull request. `everything`
    includes the whole working tree.
    """
    root = repo_root(path)
    scope = ["."] if everything else [str(path.resolve().relative_to(root))]
    changed = _run(["git", "status", "--porcelain", "--", *scope], root)
    others = [
        line[3:]
        for line in _run(["git", "status", "--porcelain"], root).splitlines()
        if line not in changed.splitlines()
    ]
    if not changed:
        hint = (
            f" Other changes exist outside it ({', '.join(others[:5])}); pass --all to include them."
            if others
            else ""
        )
        raise GitError(f"there is nothing to submit under {scope[0]}/.{hint}")
    branch = _run(["git", "branch", "--show-current"], root)
    if branch == MAIN:
        slug = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")[:48] or "change"
        branch = f"change/{slug}"
        _run(["git", "checkout", "-q", "-b", branch], root)
    _run(["git", "add", "-A", "--", *scope], root)
    _run(["git", "commit", "-q", "-m", title + (f"\n\n{body}" if body else "")], root)
    _run(["git", "push", "-q", "-u", "origin", branch], root)
    existing = _json(["gh", "pr", "list", "--head", branch, "--json", "number,url"], root)
    if existing:
        number, url = existing[0]["number"], existing[0]["url"]
    else:
        url = _run(
            ["gh", "pr", "create", "--title", title, "--body-file", "-", "--head", branch],
            root,
            stdin=body or title,
        ).splitlines()[-1]
        number = int(url.rstrip("/").rsplit("/", 1)[-1])
    result: dict[str, Any] = {
        "branch": branch,
        "pull_request": number,
        "url": url,
        "next": f"./px change merge {number}",
    }
    if others:
        result["not_included"] = others
    return result


def _checks(root: Path, number: int) -> list[dict[str, str]]:
    return _json(["gh", "pr", "checks", str(number), "--json", "name,bucket"], root)


def status(path: Path, number: int | None = None) -> Any:
    """Checks of one pull request, or the list of open pull requests."""
    root = repo_root(path)
    if number is None:
        rows = _json(["gh", "pr", "list", "--json", "number,title,headRefName,url"], root)
        return [{**row, "opened_by_an_agent": row["headRefName"].startswith("ai/")} for row in rows]
    return show(path, number, with_body=False)


def show(path: Path, number: int, with_body: bool = True) -> dict[str, Any]:
    """One pull request: what it says, which files it changes, and its checks."""
    root = repo_root(path)
    fields = "state,title,headRefName,baseRefName,url,files" + (",body" if with_body else "")
    view = _json(["gh", "pr", "view", str(number), "--json", fields], root)
    if not view:
        raise GitError(f"there is no pull request {number}")
    view["opened_by_an_agent"] = view["headRefName"].startswith("ai/")
    view["files"] = [f["path"] for f in view.get("files", [])]
    view["checks"] = {c["name"]: c["bucket"] for c in _checks(root, number)} or (
        "none reported yet; they start within a minute, and ./px change merge waits for them"
        if view["state"] == "OPEN"
        else {}
    )
    unfinished = isinstance(view["checks"], dict) and (
        "pending" in view["checks"].values() or len(view["checks"]) < 4
    )
    if view["state"] == "OPEN" and unfinished:
        view["checks_note"] = (
            "not all checks have finished; the lab check starts after the others pass. "
            "./px change merge waits for every check and does not merge if one fails"
        )
    return view


def diff(path: Path, number: int) -> str:
    """The exact lines a pull request adds and removes."""
    root = repo_root(path)
    return _run(["gh", "pr", "diff", str(number)], root)


def close(path: Path, number: int, reason: str) -> dict[str, Any]:
    """Close a pull request without merging it, with a comment saying why."""
    root = repo_root(path)
    _run(["gh", "pr", "close", str(number), "--delete-branch", "--comment", reason], root)
    return {"pull_request": number, "closed": True}


def merge(path: Path, number: int, wait: int = 1500) -> dict[str, Any]:
    """Wait for checks, merge, then wait for the deploy the merge triggers."""
    root = repo_root(path)
    deadline = time.monotonic() + wait
    view = _json(["gh", "pr", "view", str(number), "--json", "state,headRefName,baseRefName"], root)
    if not view:
        raise GitError(f"there is no pull request {number}")
    if view["state"] == "MERGED":
        # Already merged (an earlier run stopped waiting): report its deploy.
        merged = _json(["gh", "pr", "view", str(number), "--json", "mergeCommit"], root)
        sha = merged["mergeCommit"]["oid"]
        result = {"ok": True, "merged": True, "commit": sha[:7], "note": "was already merged"}
        return _await_deploy(root, sha, deadline, result)
    if view["state"] != "OPEN":
        raise GitError(f"pull request {number} is {view['state'].lower()}, not open")
    if view["baseRefName"] != MAIN:
        raise GitError(f"pull request {number} targets {view['baseRefName']}, not {MAIN}")
    # If main moved since the pull request was opened, test it against today's
    # main first: two pull requests can each be fine and still clash in packs.lock.
    state = _json(["gh", "pr", "view", str(number), "--json", "mergeStateStatus"], root)
    if state and state.get("mergeStateStatus") == "BEHIND":
        _say("main has moved; updating the pull request's branch and re-running its checks")
        _run(["gh", "pr", "update-branch", str(number)], root, check=False)
        time.sleep(15)
    _say(f"pull request {number}: waiting for its checks")
    checks: list[dict[str, str]] = []
    while time.monotonic() < deadline:
        checks = _checks(root, number)
        if checks and not any(c["bucket"] == "pending" for c in checks):
            break
        time.sleep(8)
    summary = {c["name"]: c["bucket"] for c in checks}
    failed = [name for name, bucket in summary.items() if bucket not in ("pass", "skipping")]
    if not checks or failed:
        pending = not checks or "pending" in summary.values()
        reason = "checks did not finish in time" if pending else f"failed: {', '.join(failed)}"
        return {
            "ok": False,
            "merged": False,
            "reason": reason,
            "checks": summary,
            "next": f"./px change show {number} for details; fix, then ./px change submit again",
        }
    _say("checks passed; merging")
    _run(["gh", "pr", "merge", str(number), "--merge", "--delete-branch"], root)
    if not _run(["git", "status", "--porcelain"], root):
        _run(["git", "checkout", "-q", MAIN], root)
        _run(["git", "pull", "-q", "--ff-only"], root)
    _run(["git", "fetch", "-q", "origin", MAIN], root)
    sha = _run(["git", "rev-parse", f"origin/{MAIN}"], root)
    result: dict[str, Any] = {"ok": True, "merged": True, "commit": sha[:7], "checks": summary}
    return _await_deploy(root, sha, deadline, result, number)


def _await_deploy(
    root: Path, sha: str, deadline: float, result: dict[str, Any], number: int | None = None
) -> dict[str, Any]:
    """Wait for the deploy that a merge commit triggers, and add its outcome to `result`."""
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
    _say("merged; waiting for the deploy (it redeploys only the clients this change affects)")
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
    pattern = re.compile(
        r"^│ PRX-\d{6} │ (created|updated|unchanged|deleted|succeeded|failed|timeout|"
        r"no telemetry|drift|missing|disabled)"
    )
    for line in log.splitlines():
        text = line.split("Z ", 1)[-1].strip()
        if pattern.match(text):
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
    if run["status"] != "completed":
        result["next"] = (
            "The change is merged; its deploy has not finished (the runner may be busy). "
            "Run the same ./px change merge command again to wait for it and see its result."
        )
    return result
