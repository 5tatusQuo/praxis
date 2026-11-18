"""The guides name every command, so an AI operator never has to guess one."""

import re
from pathlib import Path

import typer

from praxis.cli import app

ROOT = Path(__file__).resolve().parents[1]


def _commands(command, path=()):
    subs = getattr(command, "commands", None)
    if subs:
        for name, sub in subs.items():
            yield from _commands(sub, (*path, name))
    else:
        yield " ".join(path)


def test_every_command_is_named_in_the_guides():
    guides = (ROOT / "docs" / "runbook.md").read_text() + (ROOT / "CLAUDE.md").read_text()
    missing = [
        name
        for name in _commands(typer.main.get_command(app))
        if not re.search(rf"(px|praxis) {re.escape(name)}(?![\w-])", guides)
        and f"`{name}`" not in guides
    ]
    assert not missing, f"name these in docs/runbook.md: {missing}"
