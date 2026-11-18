"""Shipping changes: which clients a change touches, and where agent commands may start."""

from __future__ import annotations

import subprocess

import pytest

from praxis import changes, core
from praxis.agents import gitops
from tests.conftest import CLIENT, write_yaml


def git(repo, *args):
    return subprocess.run(
        ["git", *args], cwd=repo, check=True, capture_output=True, text=True
    ).stdout


@pytest.fixture
def checkout(content):
    """The fixture content inside a real git repository, on main."""
    root = content.parent
    second = {**CLIENT, "id": "second", "packs": []}
    second["platforms"] = {
        "elastic": {"connection": "lab", "space": "second", "namespace": "second"}
    }
    write_yaml(content / "clients" / "second" / "client.yml", second)
    git(root, "init", "-q", "-b", "main")
    git(root, "config", "user.email", "t@example.invalid")
    git(root, "config", "user.name", "t")
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "start")
    return root


def affected(content, root):
    return core.affected_clients(core.load_repo(content), "HEAD~1")


def commit(root, message="change"):
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", message)


def test_only_clients_a_change_touches_are_redeployed(checkout, content):
    (content / "detections" / "PRX-000900-test-detection" / "elastic.eql").write_text(
        'process where process.name == "evil2.exe"\n'
    )
    commit(checkout)
    assert affected(content, checkout) == ["testco"], "only the client that runs the detection"

    tuning = content / "clients" / "second" / "notes.txt"
    tuning.write_text("x")
    commit(checkout)
    assert affected(content, checkout) == ["second"]

    (content / "hunts").mkdir()
    (content / "hunts" / "record.txt").write_text("x")
    (checkout / "README.md").write_text("docs")
    commit(checkout)
    assert affected(content, checkout) == [], "records and docs change no rule"

    (checkout / "src").mkdir()
    (checkout / "src" / "code.py").write_text("x = 1")
    commit(checkout)
    assert affected(content, checkout) == ["second", "testco"], "platform code affects everyone"
    assert core.affected_clients(core.load_repo(content), "not-a-ref") == ["second", "testco"]


def test_agent_commands_start_from_a_clean_main(checkout, monkeypatch):
    monkeypatch.setattr(
        gitops,
        "_run",
        lambda args, cwd, stdin=None: (
            "" if args[:2] == ["git", "pull"] else _real(args, cwd, stdin)
        ),
    )
    git(checkout, "checkout", "-q", "-b", "ai/earlier")
    with pytest.raises(gitops.GitError, match="change home"):
        gitops.start_branch(checkout, "ai/next")
    git(checkout, "checkout", "-q", "main")
    (checkout / "stray.txt").write_text("x")
    with pytest.raises(gitops.GitError, match="uncommitted changes"):
        gitops.start_branch(checkout, "ai/next")
    (checkout / "stray.txt").unlink()
    gitops.start_branch(checkout, "ai/next")
    assert gitops.current_branch(checkout) == "ai/next"
    with pytest.raises(gitops.GitError, match="must start with"):
        gitops.start_branch(checkout, "feature/x")


_real = gitops._run


def test_submit_only_takes_content_files(checkout, content, monkeypatch):
    calls = []

    def fake(args, cwd, check=True, stdin=None):
        if args[0] == "gh" or args[:2] == ["git", "push"]:
            calls.append(args)
            return "[]" if args[:3] == ["gh", "pr", "list"] else "https://example.invalid/pull/7"
        return changes_run(args, cwd, check, stdin)

    changes_run = changes._run
    monkeypatch.setattr(changes, "_run", fake)
    (checkout / "spec.yml").write_text("scratch")
    with pytest.raises(gitops.GitError, match="nothing to submit under content"):
        changes.submit(content, "Nothing yet")
    (content / "clients" / "second" / "notes.txt").write_text("x")
    result = changes.submit(content, "Add notes")
    assert result["pull_request"] == 7 and result["branch"] == "change/add-notes"
    assert result["not_included"] == ["spec.yml"]
    assert "spec.yml" in git(checkout, "status", "--porcelain"), "the scratch file is left alone"
    assert "notes.txt" in git(checkout, "show", "--stat", "HEAD")
