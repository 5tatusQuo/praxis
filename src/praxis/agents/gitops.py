"""Git plumbing for agent output: a feature branch and a pull request, nothing more."""

from __future__ import annotations

import subprocess
from pathlib import Path

AGENT_BRANCH_PREFIX = "ai/"


class GitError(RuntimeError):
    pass


def _run(args: list[str], cwd: Path, stdin: str | None = None) -> str:
    result = subprocess.run(args, cwd=cwd, capture_output=True, text=True, input=stdin)
    if result.returncode != 0:
        raise GitError(f"{' '.join(args[:3])} failed: {result.stderr.strip()[:400]}")
    return result.stdout.strip()


def repo_root(path: Path) -> Path:
    return Path(_run(["git", "rev-parse", "--show-toplevel"], path))


def start_branch(root: Path, branch: str) -> None:
    """Create the agent's branch from a clean tree. Agents never work on main."""
    if not branch.startswith(AGENT_BRANCH_PREFIX):
        raise GitError(f"agent branches must start with {AGENT_BRANCH_PREFIX!r}")
    if _run(["git", "status", "--porcelain"], root):
        raise GitError(
            "the working tree has uncommitted changes. Ship them with `./px change submit` "
            "or discard them, then run this again"
        )
    on = current_branch(root)
    if on != "main":
        raise GitError(
            f"you are on branch {on!r}; agent commands start from main, so that each proposal "
            "stands alone. Run `./px change home`, then run this again"
        )
    _run(["git", "pull", "-q", "--ff-only"], root)
    _run(["git", "checkout", "-q", "-b", branch], root)


def abandon_branch(root: Path, branch: str, back_to: str) -> None:
    """Drop an agent branch that produced nothing worth a pull request."""
    _run(["git", "checkout", "-q", "--", "."], root)
    _run(["git", "clean", "-fdq", "--", "content"], root)
    _run(["git", "checkout", "-q", back_to], root)
    _run(["git", "branch", "-q", "-D", branch], root)


def current_branch(root: Path) -> str:
    return _run(["git", "branch", "--show-current"], root)


def open_pull_request(root: Path, branch: str, title: str, body: str, message: str) -> str:
    """Commit everything under the tree, push the branch and open a pull request."""
    if not branch.startswith(AGENT_BRANCH_PREFIX) or current_branch(root) != branch:
        raise GitError("refusing to commit: not on the agent's own branch")
    _run(["git", "add", "-A"], root)
    _run(["git", "commit", "-q", "-m", message], root)
    _run(["git", "push", "-q", "-u", "origin", branch], root)
    url = _run(
        ["gh", "pr", "create", "--title", title, "--body-file", "-", "--head", branch],
        root,
        stdin=body,
    ).splitlines()[-1]
    # Leave the operator where they started: on main, ready for the next command.
    _run(["git", "checkout", "-q", "main"], root)
    return url
