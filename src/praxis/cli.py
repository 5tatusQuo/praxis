"""The `praxis` command line."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from praxis import core, lab
from praxis.platforms import get_platform
from praxis.settings import get_settings, load_env_files
from praxis.visibility.engine import top_gaps
from praxis.visibility.navigator import coverage_layer

app = typer.Typer(no_args_is_help=True, help="PRAXIS: detection engineering platform.")
lab_app = typer.Typer(
    no_args_is_help=True,
    help="The lab: seed telemetry, shape what a client sends, replay events, test rules.",
)
admin_app = typer.Typer(no_args_is_help=True, help="Onboarding tasks that need admin access.")
app.add_typer(lab_app, name="lab")
app.add_typer(admin_app, name="admin")
# A wide, fixed width when output is piped (as it is for an AI assistant), so
# tables are not squeezed and cells are not cut off.
AGENT_FOOTER = "\n<sub>Opened by PRAXIS for its agents. A person reviews and merges it; merging deploys.</sub>\n"
console = Console(width=None if sys.stdout.isatty() else 180)
err = Console(stderr=True)


BANNER = r"""
   ____        ____
  /::::\______/ ** \     P R A X I S
  \::::/      \ ** /     theory into practice
   ‾‾‾‾        ‾‾‾‾
"""


@app.callback()
def _main() -> None:
    load_env_files()


@app.command()
def version() -> None:
    """Show the PRAXIS version and the ATT&CK release it ships."""
    from praxis import __version__, attack

    console.print(f"[yellow]{BANNER}[/yellow]", highlight=False)
    console.print(f"praxis {__version__} · ATT&CK {attack.version()}")


def _repo(strict: bool = True):
    repo = core.load_repo()
    if strict and repo.issues:
        for issue in repo.issues:
            err.print(f"[red]error[/red] {issue}")
        raise typer.Exit(1)
    return repo


def _client(repo, client_id: str):
    client = repo.clients.get(client_id)
    if client is None:
        err.print(f"[red]unknown client {client_id!r}[/red]; known: {sorted(repo.clients)}")
        raise typer.Exit(2)
    return client


@app.command()
def validate(
    base: Annotated[
        str | None,
        typer.Option(help="Git ref to compare with: query changes must update the docs."),
    ] = None,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Check schemas, references, ATT&CK ids, README template and tuning hooks."""
    repo = _repo(strict=False)
    issues = core.validate(repo)
    if base:
        issues += core.docs_follow_queries(repo, base)
    if as_json:
        print(json.dumps({"valid": not issues, "issues": [str(i) for i in issues]}, indent=2))
        raise typer.Exit(1 if issues else 0)
    for issue in issues:
        err.print(f"[red]error[/red] {issue}")
    if issues:
        raise typer.Exit(1)
    console.print(
        f"[green]ok[/green] {len(repo.detections)} detections, {len(repo.packs)} packs, "
        f"{len(repo.clients)} clients"
    )


@app.command()
def clients(
    as_json: Annotated[bool, typer.Option("--json")] = False,
    changed_since: Annotated[
        str | None, typer.Option(help="Only clients a change since this git ref affects.")
    ] = None,
) -> None:
    """List clients (use --json to feed a CI matrix)."""
    repo = _repo()
    if as_json:
        names = (
            core.affected_clients(repo, changed_since) if changed_since else sorted(repo.clients)
        )
        print(json.dumps(names))
        return
    table = Table("client", "sector", "platforms", "packs", "detections")
    for client in repo.clients.values():
        table.add_row(
            client.id,
            client.sector,
            ", ".join(client.platforms.enabled()),
            ", ".join(client.packs),
            str(len(repo.detections_for(client))),
        )
    console.print(table)


@app.command()
def render(
    client_id: Annotated[str | None, typer.Option("--client")] = None,
    out: Annotated[Path | None, typer.Option(help="Write envelopes here as JSON files.")] = None,
) -> None:
    """Render the platform envelope for every client x platform x detection."""
    repo = _repo()
    targets = [_client(repo, client_id)] if client_id else list(repo.clients.values())
    table = Table("client", "platform", "detection", "tuning", "hash")
    for client in targets:
        for platform_name in client.platforms.enabled():
            for rule in core.render_client(repo, client, platform_name):
                table.add_row(
                    client.id,
                    platform_name,
                    rule.detection_id,
                    "tuned" if rule.tuning_digest else "",
                    rule.content_hash[:16],
                )
                if out:
                    path = out / client.id / platform_name / f"{rule.detection_id}.json"
                    path.parent.mkdir(parents=True, exist_ok=True)
                    rendered = {"rule": rule.envelope, **rule.extras}
                    path.write_text(json.dumps(rendered, indent=2) + "\n")
    console.print(table)


@lab_app.command("test")
def lab_test(
    detection_ids: Annotated[list[str] | None, typer.Argument()] = None,
    changed_since: Annotated[
        str | None,
        typer.Option(help="Only the detections changed since this Git commit (used by CI)."),
    ] = None,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Replay test events in the lab SIEM, raw and under every client's tuning."""
    repo = _repo()
    wanted = detection_ids or sorted(repo.detections)
    if changed_since and not detection_ids:
        from praxis import ops

        changed = ops.changed_detections(get_settings().content_dir, changed_since)
        if changed is None:
            err.print("replaying every detection: the change reaches beyond the content folder")
        else:
            wanted = [d for d in changed if d in repo.detections]
            err.print(
                f"replaying the detections this change affects: {', '.join(wanted) or 'none'}"
            )
    failed = False
    rows = []
    table = Table("detection", "platform", "scope", "case", "expected", "fired", "result")
    for det_id in wanted:
        bundle = repo.detections.get(det_id)
        if bundle is None:
            err.print(f"[red]unknown detection {det_id}[/red]")
            raise typer.Exit(2)
        for case in core.lab_test(repo, bundle):
            failed |= not case.passed
            rows.append(
                {
                    "detection": det_id, "scope": case.scope, "case": case.name,
                    "expected_to_fire": case.expected, "fired": case.fired,
                    "passed": case.passed, "error": case.error,
                }
            )  # fmt: skip
            table.add_row(
                det_id,
                case.platform,
                case.scope,
                case.name,
                "fire" if case.expected else "stay quiet",
                "error" if case.error else ("yes" if case.fired else "no"),
                "[green]pass[/green]" if case.passed else f"[red]FAIL[/red] {case.error or ''}",
            )
    if as_json:
        print(json.dumps({"passed": not failed, "cases": rows}, indent=2))
    else:
        console.print(table)
    if failed:
        raise typer.Exit(1)


@lab_app.command("replay")
def lab_replay(
    detection_id: str,
    client_id: Annotated[str, typer.Option("--client")],
    kind: Annotated[
        str, typer.Option(help="positive, negative, or examples (the client's tuning examples)")
    ] = "positive",
    from_client: Annotated[
        str | None,
        typer.Option(help="With --kind examples: replay another client's tuning examples."),
    ] = None,
    file: Annotated[
        Path | None,
        typer.Option(help="Replay the event(s) in this JSON file instead of the test events."),
    ] = None,
    repeat: Annotated[int, typer.Option(help="Write the events this many times.")] = 1,
) -> None:
    """Write events into a fictional client's telemetry, as if they had just happened.

    Use it to see a deployed rule fire, or with --file and --repeat to simulate
    a noisy benign pattern before tuning it.
    """
    repo = _repo()
    client = _client(repo, client_id)
    bundle = repo.detections.get(detection_id)
    if bundle is None:
        err.print(f"[red]error[/red] unknown detection {detection_id}")
        raise typer.Exit(1)
    for platform_name in client.platforms.enabled():
        if platform_name not in bundle.implementations:
            continue
        if file is not None:
            loaded = json.loads(file.read_text())
            events = loaded if isinstance(loaded, list) else [loaded]
            label = f"events from {file.name}"
        elif kind == "examples":
            source = _client(repo, from_client) if from_client else client
            events = repo.tuning_examples(detection_id, source, platform_name)
            label = "tuning example events"
        else:
            cases = bundle.positive if kind == "positive" else bundle.negative
            events = [event for case in cases for event in case.events]
            label = f"{kind} test events"
        count = get_platform(platform_name).replay(bundle, client, events * repeat)
        console.print(f"{platform_name}: wrote {count} {label} for {client.id}")
    console.print(
        f"Rules run every few minutes. Wait for the alerts with: "
        f"./px alerts {client.id} --rule {detection_id} --wait-for <count>"
    )


@lab_app.command("source")
def lab_source(
    client_id: str,
    source: Annotated[str, typer.Argument(help="A source from `./px sources`.")],
    hosts: Annotated[int | None, typer.Option(help="Hosts reporting; default: all.")] = None,
    events_per_day: int = 200,
    silent_for_days: Annotated[
        int, typer.Option(help="The source stopped sending this many days ago.")
    ] = 0,
    remove: Annotated[bool, typer.Option(help="Take the source out of the profile.")] = False,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Add, change or remove a log source in a client's lab telemetry profile."""
    from praxis import ops

    result = _op(
        lambda: ops.lab_source(
            get_settings().content_dir,
            client_id,
            source,
            hosts,
            events_per_day,
            silent_for_days,
            remove,
        )
    )
    _out(result, as_json)


@lab_app.command("seed")
def lab_seed(client_ids: Annotated[list[str] | None, typer.Argument()] = None) -> None:
    """Top up a fictional client's synthetic telemetry (clients/<id>/lab/telemetry.yml)."""
    repo = _repo()
    for client_id in client_ids or sorted(repo.lab_telemetry):
        if _client(repo, client_id).id not in repo.lab_telemetry:
            console.print(f"{client_id}: no lab telemetry profile, nothing to seed")
            continue
        written = lab.seed(repo, _client(repo, client_id))
        for source, count in written.items():
            console.print(f"{client_id}: {source} +{count} events")


def _print_snapshot(snapshot: dict) -> None:
    summary = snapshot["summary"]
    weighted = summary["weighted_coverage_pct"]
    console.print(
        f"[bold]{snapshot['client']}[/bold] at {snapshot['taken_at']} "
        f"(ATT&CK {snapshot['attack_version']})\n"
        f"covered {summary['covered']} | detection gaps {summary['detection_gap']} | "
        f"visibility gaps {summary['visibility_gap']} | blind rules {summary['blind_rule']} "
        f"of {summary['techniques']} techniques\n"
        f"coverage {summary['coverage_pct']}% | threat-weighted "
        f"{'n/a' if weighted is None else f'{weighted}%'} | visible {summary['visible_pct']}%"
    )
    console.print(
        "[dim]A rule on a sub-technique also covers its parent technique, so the covered count "
        "can be higher than the techniques listed against the rules.[/dim]"
    )
    components = Table("data component", "score", "source", "detail", title="visibility (0-4)")
    for c in snapshot["components"]:
        d = c["detail"]
        missing = [k for k, ok in c["factors"].items() if not ok]
        detail = (
            f"silent: no events in 24h; {c.get('techniques_not_visible', 0)} techniques are "
            "not visible because of it"
            if c["silent"]
            else (
                f"{d['hosts']}/{d['expected_hosts']} hosts, fields {d['field_population']:.0%}"
                + (f", missing: {', '.join(missing)}" if missing else "")
                + (
                    f"; {c['techniques_using']} techniques rely on it at reduced confidence"
                    if missing and c.get("techniques_using")
                    else ""
                )
            )
        )
        components.add_row(c["name"], str(c["score"]), c["source"], detail)
    console.print(components)
    rules = Table("rule", "name", "status", "last run", "alerts 30d", "techniques", title="rules")
    for r in snapshot["rules"]:
        colour = {"healthy": "green", "blind": "red"}.get(r["status"], "yellow")
        rules.add_row(
            r["id"],
            r.get("name", ""),
            f"[{colour}]{r['status']}[/{colour}]",
            r["last_status"] or "never",
            str(r["alerts_30d"]),
            ", ".join(r["techniques"]),
        )
    console.print(rules)
    # A gap may already have a detection in the library that this client does not run.
    running = {r["id"] for r in snapshot["rules"]}
    shelf: dict[str, list[str]] = {}
    for bundle in _repo().detections.values():
        if bundle.id in running or bundle.meta.lifecycle == "deprecated":
            continue
        for ref in bundle.meta.attack:
            # A rule on a sub-technique also covers its parent.
            for technique in {ref.technique, ref.technique.split(".")[0]}:
                shelf.setdefault(technique, []).append(bundle.id)
    gaps = Table(
        "technique", "name", "weight", "visibility", "in the library", title="top detection gaps"
    )
    for t in top_gaps(snapshot, "detection_gap", 10):
        have = sorted(set(shelf.get(t["id"], [])))
        gaps.add_row(
            t["id"], t["name"], f"{t['weight']:.2f}", str(t["visibility"]), ", ".join(have) or "-"
        )
    console.print(gaps)
    console.print(
        "[dim]'in the library': detections for that technique this client does not run yet; "
        "add one with ./px detection assign. Visibility gaps are mostly techniques whose data "
        "sources this client does not send at all.[/dim]"
    )
    unmapped = [s["table"] for s in snapshot["sources"] if not s["mapped"]]
    if unmapped:
        console.print(f"[yellow]tables with no datamap-catalog note:[/yellow] {unmapped}")


@app.command()
def coverage(
    client_id: str,
    out: Annotated[
        Path | None,
        typer.Option(help="Write snapshot.json, navigator-layer.json and tables.csv here."),
    ] = None,
    store: Annotated[bool, typer.Option(help="Save the snapshot to the database.")] = False,
    as_json: Annotated[bool, typer.Option("--json")] = False,
    summary: Annotated[
        bool, typer.Option(help="Only the headline numbers and each rule's status.")
    ] = False,
) -> None:
    """Collect telemetry and rule health (read-only) and classify every ATT&CK technique."""
    repo = _repo()
    client = _client(repo, client_id)
    inventory, snapshot = core.coverage(repo, client)
    if out:
        out.mkdir(parents=True, exist_ok=True)
        (out / "snapshot.json").write_text(json.dumps(snapshot, indent=1) + "\n")
        (out / "inventory.json").write_text(json.dumps(inventory.to_dict(), indent=1) + "\n")
        (out / "navigator-layer.json").write_text(json.dumps(coverage_layer(snapshot)) + "\n")
        (out / "tables.csv").write_text(core.datamap_csv(inventory))
    if store:
        from praxis import db

        with db.connect() as conn:
            snapshot_id = db.save_snapshot(conn, snapshot, inventory.to_dict())
        err.print(f"stored snapshot {snapshot_id}")
    if summary:
        data = {
            "client": snapshot["client"],
            "taken_at": snapshot["taken_at"],
            **snapshot["summary"],
            "rule_status": {
                r["id"]: {
                    "name": r.get("name", ""),
                    "status": r["status"],
                    "alerts_30d": r["alerts_30d"],
                }
                for r in snapshot["rules"]
            },
        }
        _out(data, as_json)
    elif as_json:
        print(json.dumps(snapshot))
    else:
        _print_snapshot(snapshot)


@app.command()
def drift(client_id: str) -> None:
    """Compare what packs.lock pins with what the client's SIEM runs (read-only)."""
    repo = _repo()
    problems = core.drift(repo, _client(repo, client_id))
    for problem in problems:
        err.print(f"[red]drift[/red] {problem}")
    if problems:
        raise typer.Exit(1)
    console.print(f"[green]ok[/green] {client_id}: the SIEM matches packs.lock")


@app.command()
def expiry(
    within: Annotated[
        int, typer.Option(help="Also list items expiring within this many days.")
    ] = 30,
) -> None:
    """List tuning and detections that have expired or are about to. Expired items fail."""
    repo = _repo()
    rows = core.expiring(repo, within)
    table = Table("item", "expires", "state")
    for row in rows:
        colour = "red" if row["expired"] else "yellow"
        state = "EXPIRED" if row["expired"] else "expiring"
        table.add_row(row["item"], row["expires"], f"[{colour}]{state}[/{colour}]")
    console.print(table if rows else "nothing expires soon")
    if any(row["expired"] for row in rows):
        raise typer.Exit(1)


@app.command()
def lock(
    check: Annotated[bool, typer.Option(help="Fail if any packs.lock is out of date.")] = False,
) -> None:
    """Write each client's packs.lock: the exact rule versions and hashes it runs."""
    repo = _repo()
    stale = []
    for client in repo.clients.values():
        if check:
            if not core.lock_is_current(repo, client):
                stale.append(client.id)
        else:
            console.print(f"wrote {core.write_lock(repo, client)}")
    if stale:
        err.print(
            f"[red]packs.lock is out of date for: {', '.join(stale)}[/red]; run `praxis lock`"
        )
        raise typer.Exit(1)
    if check:
        console.print("[green]ok[/green] every packs.lock matches the render")


@app.command("connection")
def connection_check(
    client_id: str, as_json: Annotated[bool, typer.Option("--json")] = False
) -> None:
    """Check a client's read and deploy identities against its SIEMs."""
    repo = _repo()
    client = _client(repo, client_id)
    failed = False
    rows = []
    table = Table("platform", "identity", "result", "detail")
    for platform_name in client.platforms.enabled():
        for check in get_platform(platform_name).check_connection(client):
            failed |= not check.ok
            result = "[green]ok[/green]" if check.ok else "[red]FAIL[/red]"
            table.add_row(platform_name, check.role, result, check.detail)
            rows.append(
                {
                    "platform": platform_name,
                    "identity": check.role,
                    "ok": check.ok,
                    "detail": check.detail,
                }
            )
    if as_json:
        print(json.dumps({"ok": not failed, "checks": rows}, indent=2))
    else:
        console.print(table)
    if failed:
        raise typer.Exit(1)


@app.command()
def release(
    client_id: str,
    smoke: Annotated[bool, typer.Option(help="Check each rule's first run after deploy.")] = True,
    force: Annotated[
        bool, typer.Option(help="Rewrite every rule even if unchanged: undoes console edits.")
    ] = False,
) -> None:
    """Deploy a client's rendered rules to its SIEMs, then smoke-check them. CD runs this."""
    repo = _repo()
    if core.validate(repo):
        err.print("[red]content does not validate; run `praxis validate`[/red]")
        raise typer.Exit(1)
    client = _client(repo, client_id)
    if not core.lock_is_current(repo, client):
        err.print(f"[red]{client.id}/packs.lock does not pin this render; run `praxis lock`[/red]")
        raise typer.Exit(1)
    failed = False
    for platform_name in client.platforms.enabled():
        platform = get_platform(platform_name)
        rules = core.render_client(repo, client, platform_name)
        table = Table("detection", "action", "hash", title=f"{client.id} on {platform_name}")
        for action in platform.deploy(rules, client, force):
            table.add_row(action.detection_id, action.action, (action.content_hash or "")[:16])
        console.print(table)
        if smoke:
            checks = Table("detection", "status", "detail", title="smoke check")
            for result in platform.smoke(rules, client):
                failed |= not result.ok
                colour = "green" if result.ok else "red"
                checks.add_row(
                    result.detection_id, f"[{colour}]{result.status}[/{colour}]", result.detail
                )
            console.print(checks)
    if failed:
        raise typer.Exit(1)


@app.command()
def deploy(
    mode: Annotated[str, typer.Option(help="full (PRAXIS + Elastic) or connect (PRAXIS only)")],
    down: Annotated[bool, typer.Option(help="Stop the stack instead of starting it.")] = False,
) -> None:
    """Start the PRAXIS stack with Docker Compose on this machine."""
    profiles = {"full": ["core", "elk"], "connect": ["core"]}.get(mode)
    if profiles is None:
        err.print("[red]--mode must be full or connect[/red]")
        raise typer.Exit(2)
    deploy_dir = get_settings().deploy_dir
    if deploy_dir is None:
        err.print("[red]deploy_dir is not set[/red]")
        raise typer.Exit(2)
    command = ["docker", "compose"]
    for profile in profiles:
        command += ["--profile", profile]
    command += ["down"] if down else ["up", "-d", "--wait"]
    raise typer.Exit(subprocess.run(command, cwd=deploy_dir).returncode)


@admin_app.command("provision")
def admin_provision(
    client_id: str,
    env_out: Annotated[
        Path | None, typer.Option(help="Write the new API keys to this env file (mode 600).")
    ] = None,
    rotate: Annotated[
        bool, typer.Option(help="Replace keys that already exist (the old ones stop working).")
    ] = False,
) -> None:
    """Create a client's space and its lab, read and deploy identities in its SIEMs."""
    repo = _repo()
    client = _client(repo, client_id)
    lines: list[str] = []
    for platform_name in client.platforms.enabled():
        lines += get_platform(platform_name).provision(client, rotate)
    if not lines:
        console.print("nothing to do: space and keys already exist (use --rotate to replace keys)")
        return
    text = "\n".join(lines) + "\n"
    if env_out:
        env_out.touch(mode=0o600)
        env_out.chmod(0o600)
        with env_out.open("a") as handle:
            handle.write(text)
        console.print(f"wrote {len(lines)} keys to {env_out}")
    else:
        print(text, end="")


pack_app = typer.Typer(no_args_is_help=True, help="Monthly rule packs, curated by agents.")
app.add_typer(pack_app, name="pack")


def _store_run(pack: dict | None, trail, pr_url: str | None) -> None:
    """Keep the proposal and its audit trail in the database (best effort)."""
    from praxis import db

    try:
        with db.connect() as conn:
            db.migrate(conn)
            if pack:
                db.save_pack(conn, pack, pr_url)
            db.save_audit(conn, trail.events)
    except Exception as error:  # the pull request is the record; the database is a convenience
        err.print(f"[yellow]could not store the run in the database: {error}[/yellow]")


@pack_app.command("plan")
def pack_plan(
    client_id: str,
    month: Annotated[str, typer.Option(help="YYYY-MM")],
    budget: Annotated[
        int, typer.Option(help="At most this many detections; the agents may propose fewer.")
    ] = 15,
    pr: Annotated[bool, typer.Option(help="Push the branch and open a pull request.")] = True,
) -> None:
    """Curator, Platform Engineer and Reviewer agents build a candidate pack on a branch."""
    from praxis.agents import gitops
    from praxis.agents import pack as packs
    from praxis.agents.llm import AgentError, default_llm

    repo = _repo()
    _client(repo, client_id)
    content_dir = get_settings().content_dir
    root = gitops.repo_root(content_dir)
    start = gitops.current_branch(root)
    branch = f"ai/pack-{client_id}-{month}"
    gitops.start_branch(root, branch)
    try:
        pack, trail = packs.plan_pack(
            content_dir,
            client_id,
            month,
            default_llm(),
            budget,
            lambda m: console.print(f"[dim]{m}[/dim]"),
        )
    except (AgentError, Exception) as error:
        gitops.abandon_branch(root, branch, start)
        err.print(f"[red]pack planning failed:[/red] {error}")
        raise typer.Exit(1) from error
    if not pack["picks"]:
        gitops.abandon_branch(root, branch, start)
        _store_run(None, trail, None)
        err.print("[yellow]no pick survived the guardrails and tests; nothing to propose[/yellow]")
        for rejected in pack["rejected"]:
            err.print(f"  {rejected['candidate']}: {rejected['reason']}")
        raise typer.Exit(1)
    from praxis import db

    with db.connect() as conn:
        snapshot = db.latest_snapshot(conn, client_id)
    body = packs.report(pack, snapshot)
    pr_url = None
    if pr:
        body += AGENT_FOOTER
        pr_url = gitops.open_pull_request(
            root,
            branch,
            f"Rule pack {pack['id']}: {len(pack['picks'])} detections for {client_id}",
            body,
            f"Rule pack {pack['id']} proposed by ai:curator\n\n"
            f"{len(pack['picks'])} staged detections for {client_id}, written by "
            "ai:platform-engineer-elastic and reviewed by ai:reviewer.",
        )
        console.print(f"pull request: {pr_url}")
    else:
        console.print(body)
        console.print(f"[dim]left on branch {branch}, not committed[/dim]")
    _store_run(pack, trail, pr_url)
    verdict = (pack["review"] or {}).get("verdict", "n/a")
    console.print(f"{pack['id']}: {len(pack['picks'])} picks, reviewer verdict {verdict}")
    number = pr_url.rstrip("/").rsplit("/", 1)[-1] if pr_url else "<number>"
    if verdict == "fail":
        console.print(
            "The Reviewer agent found a blocker; it is in the pull request's description. "
            "Do not merge this pack as it is.\n"
            f'Next: ./px change show {number}, then ./px change close {number} --reason "..." '
            "and run ./px pack plan again for a new proposal.",
            markup=False,
        )
    elif pr_url:
        console.print(
            f"Next: ./px change show {number} --diff, then ask the person before merging it.",
            markup=False,
        )


@pack_app.command("rescore")
def pack_rescore(pack_id: str) -> None:
    """Measure a proposed pack again (tests, scores, backtests) and print its report."""
    from praxis import db
    from praxis.agents import pack as packs

    pack = packs.rescore(get_settings().content_dir, pack_id)
    with db.connect() as conn:
        snapshot = db.latest_snapshot(conn, pack["client"])
    print(packs.report(pack, snapshot))


@pack_app.command("promote")
def pack_promote(
    pack_id: str,
    drop: Annotated[
        list[str] | None, typer.Option(help="Detection that did not hold up in shadow; repeatable.")
    ] = None,
) -> None:
    """Take a pack out of shadow mode: staged detections become production rules.

    Edits the working tree only. Commit it on a branch and open a pull request.
    """
    from praxis.agents import pack as packs

    pack = packs.promote(get_settings().content_dir, pack_id, drop)
    for pick in pack["picks"]:
        console.print(f"{pick['detection']} {pick.get('name', '')}: {pick['outcome']}")


@pack_app.command("restyle")
def pack_restyle(pack_id: str) -> None:
    """Rewrite a proposed pack's text to the current template and review it again."""
    from praxis import db
    from praxis.agents import pack as packs
    from praxis.agents.llm import default_llm

    pack = packs.restyle(get_settings().content_dir, pack_id, default_llm())
    with db.connect() as conn:
        snapshot = db.latest_snapshot(conn, pack["client"])
    print(packs.report(pack, snapshot))


@app.command()
def tune(
    detection_id: str,
    client_id: Annotated[str, typer.Option("--client")],
    hint: Annotated[str, typer.Option(help="What the analyst noticed, e.g. an alert id.")] = "",
    pr: Annotated[bool, typer.Option(help="Push the branch and open a pull request.")] = True,
) -> None:
    """The Tuner agent studies a noisy rule's alerts and proposes a tested override."""
    from praxis.agents import gitops, tuner
    from praxis.agents.llm import default_llm

    repo = _repo()
    _client(repo, client_id)
    content_dir = get_settings().content_dir
    root = gitops.repo_root(content_dir)
    start = gitops.current_branch(root)
    branch = f"ai/tune-{client_id}-{detection_id.lower()}"
    gitops.start_branch(root, branch)
    try:
        result, trail = tuner.propose_tuning(
            content_dir,
            client_id,
            detection_id,
            default_llm(),
            hint,
            lambda m: console.print(f"[dim]{m}[/dim]"),
        )
    except Exception as error:
        gitops.abandon_branch(root, branch, start)
        err.print(f"[red]tuning failed:[/red] {error}")
        raise typer.Exit(1) from error
    console.print(result["findings"], markup=False)
    console.print("Scope: " + result["scope_advice"], markup=False)
    if result["impact"]:
        impact = result["impact"]
        removed = impact["matches_before"] - impact["matches_after"]
        console.print(
            f"[bold]Impact, measured:[/bold] removes {removed} of {impact['matches_before']} "
            f"matches over the last {impact['days']} days; {impact['matches_after']} remain."
        )
        for text in result["exclusions"]:
            console.print(f"[bold]Suppress when:[/bold] {text}", highlight=False)
    if not result["proposed"]:
        gitops.abandon_branch(root, branch, start)
        _store_run(None, trail, None)
        console.print("[yellow]no tuning proposed[/yellow]")
        return
    if pr:
        body = tuner.report(client_id, detection_id, result) + AGENT_FOOTER
        url = gitops.open_pull_request(
            root,
            branch,
            f"Tune {result['rule_name']} ({detection_id}) for {client_id}",
            body,
            f"Tune {detection_id} for {client_id} (proposed by ai:tuner)",
        )
        console.print(f"pull request: {url}")
    _store_run(None, trail, None)


@app.command()
def hunt(
    prompt: str,
    clients: Annotated[str | None, typer.Option(help="Comma-separated client ids.")] = None,
    sector: Annotated[str | None, typer.Option(help="Fan out to every client in a sector.")] = None,
    pr: Annotated[bool, typer.Option(help="Push the branch and open a pull request.")] = True,
) -> None:
    """The Hunt Planner turns a threat prompt into hypotheses and runs them read-only."""
    from praxis.agents import gitops
    from praxis.agents import hunt as hunts
    from praxis.agents.llm import default_llm

    repo = _repo()
    content_dir = get_settings().content_dir
    try:
        scope = hunts.select_clients(repo, clients.split(",") if clients else None, sector)
    except Exception as error:
        err.print(f"[red]{error}[/red]")
        raise typer.Exit(2) from error
    root = gitops.repo_root(content_dir)
    start = gitops.current_branch(root)
    import re
    from datetime import date

    slug = re.sub(r"[^a-z0-9]+", "-", prompt.lower()).strip("-")[:40].strip("-")
    branch = f"ai/hunt-{date.today().isoformat()}-{slug}"
    gitops.start_branch(root, branch)
    try:
        record, trail = hunts.run_hunt(
            content_dir, prompt, scope, default_llm(), lambda m: console.print(f"[dim]{m}[/dim]")
        )
    except Exception as error:
        gitops.abandon_branch(root, branch, start)
        err.print(f"[red]hunt failed:[/red] {error}")
        raise typer.Exit(1) from error
    body = hunts.report(record)
    console.print(body, markup=False, highlight=False)
    url = None
    if pr:
        url = gitops.open_pull_request(
            root,
            branch,
            "Hunt: " + (prompt if len(prompt) <= 70 else prompt[:70].rsplit(" ", 1)[0] + "..."),
            body + AGENT_FOOTER,
            f"Hunt record {record['id']} (ai:hunt-planner)",
        )
        console.print(f"pull request: {url}")
    from praxis import db

    try:
        with db.connect() as conn:
            db.migrate(conn)
            db.save_hunt(conn, record, url)
            db.save_audit(conn, trail.events)
    except Exception as error:
        err.print(f"[yellow]could not store the hunt in the database: {error}[/yellow]")


@app.command()
def mcp() -> None:
    """Serve the PRAXIS tools over MCP (stdio), for Claude Code and other MCP clients."""
    from praxis.mcp_server import serve

    serve()


catalog_app = typer.Typer(no_args_is_help=True, help="The candidate catalog of upstream rules.")
app.add_typer(catalog_app, name="catalog")


@catalog_app.command("sync")
def catalog_sync(
    store: Annotated[bool, typer.Option(help="Replace the catalog in the database.")] = True,
) -> None:
    """Fetch the pinned upstream sources, normalise, fingerprint and score every rule."""
    from praxis.catalog import sync

    repo = _repo()
    candidates = sync.build(repo, get_settings().sources_cache)
    drafted = sum(1 for c in candidates if c.drafts)
    passing = sum(1 for c in candidates if c.quality["passes"])
    console.print(
        f"{len(candidates)} candidates, {drafted} with a first-draft query, "
        f"{passing} pass the quality threshold"
    )
    if store:
        from praxis import db

        with db.connect() as conn:
            db.migrate(conn)
            db.replace_catalog(conn, [c.to_dict() for c in candidates])
        console.print("catalog stored")


@app.command()
def tuning(
    detection_id: str,
    client_id: Annotated[str, typer.Option("--client")],
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """A client's tuning for one rule: the exclusions in plain words, and what they suppress."""
    repo = _repo()
    client = _client(repo, client_id)
    bundle = repo.detections.get(detection_id)
    if bundle is None or bundle not in repo.detections_for(client):
        err.print(
            f"[red]error[/red] {client_id} does not run {detection_id}; "
            f"see ./px client show {client_id}"
        )
        raise typer.Exit(1)
    name = client.platforms.enabled()[0]
    resolved = repo.tuning_for(detection_id, client, name)
    if resolved.is_empty:
        _out({"rule": detection_id, "client": client_id, "tuned": False}, as_json)
        return
    platform = get_platform(name)
    query, sources = bundle.implementations[name].query, bundle.meta.log_sources[name].indices
    before = platform.backtest(client, query, sources)["hits"]
    after = platform.backtest(client, query, sources, tuning=resolved)["hits"]
    own = repo.client_tuning.get((client_id, detection_id))
    _out(
        {
            "rule": detection_id,
            "name": bundle.meta.name,
            "client": client_id,
            "tuned": True,
            "reason": " ".join(own.reason.split()) if own else "shared platform tuning",
            "expires": str(resolved.expires) if resolved.expires else None,
            "suppressed_when_any_line_matches": [
                " AND ".join(f"{c.field} {c.op} {c.value}" for c in e.conditions())
                for e in resolved.exclude
            ],
            "last_30_days": {
                "matches_without_tuning": before,
                "matches_with_tuning": after,
                "suppressed": before - after,
            },
        },
        as_json,
    )


@app.command("tuning-promotions")
def tuning_promotions(minimum: int = 3) -> None:
    """Exclusions repeated across clients that belong in a shared layer instead."""
    from praxis.agents.tuner import promotable_exclusions

    rows = promotable_exclusions(_repo(), minimum)
    table = Table("rule", "field", "op", "value", "clients")
    for row in rows:
        table.add_row(row["rule"], row["field"], row["op"], row["value"], ", ".join(row["clients"]))
    console.print(table if rows else f"no exclusion is shared by {minimum} or more clients")


@catalog_app.command("search")
def catalog_search(
    text: Annotated[str | None, typer.Argument()] = None,
    technique: Annotated[str | None, typer.Option()] = None,
    limit: int = 15,
) -> None:
    """Search the catalog by meaning and/or ATT&CK technique."""
    from praxis import db

    with db.connect() as conn:
        rows = db.search_catalog(conn, technique=technique, text=text, limit=limit)
    table = Table("id", "score", "tier", "status", "techniques", "title", "flags")
    for row in rows:
        table.add_row(
            row["id"],
            str(row["score"]),
            row["tier"],
            row["status"],
            ", ".join(row["techniques"]),
            row["title"],
            "; ".join(f.split(":")[0] for f in row["flags"]),
        )
    console.print(table)


@app.command("db-migrate")
def db_migrate() -> None:
    """Apply database migrations."""
    from praxis import db

    with db.connect() as conn:
        applied = db.migrate(conn)
    console.print(f"applied: {applied or 'nothing new'}")


@app.command("schema")
def schema_export(out: Path = Path("schemas")) -> None:
    """Export JSON Schemas for the content files (for editors and pre-commit)."""
    from praxis.content.models import Client, ContentPack, Detection

    out.mkdir(parents=True, exist_ok=True)
    for name, model in (
        ("detection", Detection),
        ("content-pack", ContentPack),
        ("client", Client),
    ):
        path = out / f"{name}.schema.json"
        path.write_text(json.dumps(model.model_json_schema(), indent=2) + "\n")
        console.print(f"wrote {path}")


# -- operator commands: every runbook step, for a person or an AI ---------------------------
client_app = typer.Typer(no_args_is_help=True, help="Clients: create, inspect, connect, remove.")
sector_app = typer.Typer(no_args_is_help=True, help="Sector threat profiles.")
attack_app = typer.Typer(no_args_is_help=True, help="Look things up in MITRE ATT&CK.")
detection_app = typer.Typer(no_args_is_help=True, help="Detections: write, assign, promote.")
change_app = typer.Typer(no_args_is_help=True, help="Ship changes: pull request, checks, merge.")
for _name, _app in (
    ("client", client_app),
    ("sector", sector_app),
    ("attack", attack_app),
    ("detection", detection_app),
    ("change", change_app),
):
    app.add_typer(_app, name=_name)


def _out(data, as_json: bool) -> None:
    """Data for a machine (--json) or the same data as YAML for a person."""
    import yaml

    if as_json:
        print(json.dumps(data, indent=2, default=str))
    else:
        text = yaml.safe_dump(data, sort_keys=False, width=100).rstrip()
        console.print(text, highlight=False, markup=False)


def _op(action):
    """Run an operator action; turn its errors into one clear line and exit code 1."""
    from praxis import ops
    from praxis.agents.gitops import GitError
    from praxis.agents.toolbox import ToolError

    try:
        return action()
    except (ops.OpsError, GitError, ToolError, ValueError) as error:
        err.print(f"[red]error[/red] {error}")
        raise typer.Exit(1) from error


def _server(*args: str) -> None:
    """Run a step that needs keys which never leave the server (deploy/remote.sh)."""
    deploy_dir = get_settings().deploy_dir
    if deploy_dir is None or not (deploy_dir / "remote.sh").is_file():
        err.print("[red]error[/red] deploy/remote.sh not found; set deploy_dir in praxis.toml")
        raise typer.Exit(1)
    raise typer.Exit(subprocess.run([str(deploy_dir / "remote.sh"), *args]).returncode)


@app.command()
def status(as_json: Annotated[bool, typer.Option("--json")] = False) -> None:
    """Where everything stands: content, clients, working tree and, if reachable, the server."""
    from praxis import ops

    _out(ops.status(get_settings().content_dir), as_json)


@app.command()
def alerts(
    client_id: str,
    rule: Annotated[str | None, typer.Option(help="Only this detection.")] = None,
    wait_for: Annotated[
        int | None, typer.Option(help="Wait until the rule has at least this many alerts.")
    ] = None,
    timeout: Annotated[int, typer.Option(help="Seconds to wait at most.")] = 480,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """A client's alerts over the last 30 days, per rule; optionally wait for them to arrive."""
    import time

    repo = _repo()
    client = _client(repo, client_id)
    wanted = [rule] if rule else [b.id for b in repo.detections_for(client)]
    if wait_for is not None and not rule:
        err.print("[red]error[/red] --wait-for needs --rule")
        raise typer.Exit(1)
    platform = get_platform(client.platforms.enabled()[0])
    deadline = time.monotonic() + timeout
    while True:
        rows = []
        for detection_id in wanted:
            stats = platform.alert_stats(client, detection_id)
            name = (
                repo.detections[detection_id].meta.name if detection_id in repo.detections else ""
            )
            rows.append(
                {
                    "rule": detection_id,
                    "name": name,
                    "alerts_30d": stats["alerts"],
                    "top_values": stats["top_values"],
                }
            )
        if wait_for is None or rows[0]["alerts_30d"] >= wait_for:
            break
        if time.monotonic() > deadline:
            _out(rows, as_json)
            err.print(
                f"[red]error[/red] {rule} has {rows[0]['alerts_30d']} alerts after {timeout}s, fewer "
                f"than {wait_for}. A rule runs every few minutes, so new events can take one "
                f"interval to raise alerts: repeat the command with a longer --timeout. If it "
                f"stays at this number, check the rule is deployed and enabled: "
                f"./px coverage {client_id}"
            )
            raise typer.Exit(1)
        err.print(f"[dim]{rule}: {rows[0]['alerts_30d']} alerts so far; waiting[/dim]")
        time.sleep(20)
    _out(rows, as_json)


@pack_app.command("sync")
def pack_sync() -> None:
    """Copy each rule pack's state from Git into the database the dashboard reads."""
    from praxis import db

    repo = _repo()
    with db.connect() as conn:
        db.migrate(conn)
        known = {p["id"]: p for p in db.list_packs(conn)}
        for pack in repo.rule_packs.values():
            body = pack.model_dump(mode="json")
            db.save_pack(conn, body, (known.get(pack.id) or {}).get("pr_url"))
    console.print(f"synced {len(repo.rule_packs)} rule packs")


@app.command("sources")
def sources_list(as_json: Annotated[bool, typer.Option("--json")] = False) -> None:
    """Log sources the data map knows: what the lab can generate and coverage can score."""
    from praxis import ops

    _out(ops.sources(_repo()), as_json)


@app.command("source-add")
def source_add(
    spec: Annotated[Path, typer.Argument(help="YAML or JSON file; see --help for its fields.")],
) -> None:
    """Add a log source to the data map from a spec file.

    Fields: source (e.g. logs-endpoint.events.dns), name, what_it_is (a few
    sentences), components (ATT&CK data component -> list of fields an analyst
    needs), sample (one representative ECS event).
    """
    import yaml

    from praxis import ops

    data = yaml.safe_load(spec.read_text())
    path = _op(lambda: ops.source_add(get_settings().content_dir, **data))
    console.print(f"wrote {path}")


@client_app.command("add")
def client_add(
    client_id: Annotated[str, typer.Argument(help="Lower case, letters, digits, hyphens.")],
    name: Annotated[str, typer.Option(help="Display name. Invented: never a real company.")],
    sector: Annotated[str, typer.Option(help="Must have a threat profile; see `sector list`.")],
    endpoints: Annotated[int, typer.Option(help="Hosts expected to report.")],
    pack: Annotated[list[str] | None, typer.Option(help="Content pack; repeatable.")] = None,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Create a client: manifest, lab telemetry profile for its rules, and packs.lock."""
    from praxis import ops

    result = _op(
        lambda: ops.client_add(get_settings().content_dir, client_id, name, sector, endpoints, pack)
    )
    _out(result, as_json)


@client_app.command("list")
def client_list(as_json: Annotated[bool, typer.Option("--json")] = False) -> None:
    """Every client with its sector, packs and detections."""
    from praxis import ops

    _out(ops.status(get_settings().content_dir)["clients"], as_json)


@client_app.command("show")
def client_show(client_id: str, as_json: Annotated[bool, typer.Option("--json")] = False) -> None:
    """One client's manifest, the detections it runs, tuning and lock state."""
    from praxis import ops

    _out(_op(lambda: ops.client_show(_repo(), client_id)), as_json)


@client_app.command("subscribe")
def client_subscribe(
    client_id: str,
    pack: Annotated[list[str] | None, typer.Option(help="Content pack; repeatable.")] = None,
    detection: Annotated[list[str] | None, typer.Option(help="Detection id; repeatable.")] = None,
    remove: Annotated[bool, typer.Option(help="Take them away instead of adding.")] = False,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Give a client content packs or single detections (or take them away)."""
    from praxis import ops

    if not pack and not detection:
        err.print("[red]error[/red] name at least one --pack or --detection")
        raise typer.Exit(1)
    result = _op(
        lambda: ops.client_subscribe(get_settings().content_dir, client_id, pack, detection, remove)
    )
    _out(result, as_json)


@client_app.command("provision")
def client_provision(
    client_id: str,
    rotate: Annotated[bool, typer.Option(help="Replace existing keys.")] = False,
) -> None:
    """Connect a client to its SIEM: space, scoped keys, and a check that they work.

    Runs on the server, where the admin identity lives. Safe to repeat.
    """
    _client(_repo(), client_id)
    _server("provision", client_id, *(["--rotate"] if rotate else []))


@client_app.command("check")
def client_check(client_id: str) -> None:
    """Prove the client's read and deploy identities work (runs on the server)."""
    _client(_repo(), client_id)
    _server("check", client_id)


@client_app.command("offboard")
def client_offboard(
    client_id: str,
    yes: Annotated[bool, typer.Option("--yes", help="Required. This cannot be undone.")] = False,
    delete_space: Annotated[bool, typer.Option(help="Also delete the Kibana space.")] = False,
    delete_data: Annotated[bool, typer.Option(help="Also delete the client's telemetry.")] = False,
) -> None:
    """Remove a client from its SIEM (rules, keys) and from the content. Cannot be undone.

    Commit the content change and merge it afterwards, as with any change.
    """
    from praxis import ops

    _client(_repo(), client_id)
    if not yes:
        err.print(
            f"[red]error[/red] this deletes {client_id}'s rules and keys in the SIEM"
            + (", its Kibana space" if delete_space else "")
            + (", its telemetry" if delete_data else "")
            + ". Ask the person you work for, then repeat with --yes."
        )
        raise typer.Exit(1)
    deploy_dir = get_settings().deploy_dir
    flags = (["--delete-space"] if delete_space else []) + (
        ["--delete-data"] if delete_data else []
    )
    code = subprocess.run(
        [str(deploy_dir / "remote.sh"), "deprovision", client_id, *flags]
    ).returncode
    if code != 0:
        raise typer.Exit(code)
    result = _op(lambda: ops.client_remove(get_settings().content_dir, client_id))
    kept = result["kept"]
    lines = [
        f"removed {len(result['removed_files'])} content files for {client_id}",
        "Kept on purpose, in the shared library:",
        f"  sector profile: {kept['sector_profile']} (./px sector remove deletes it)",
        f"  rule pack records (history): {', '.join(kept['rule_pack_records']) or 'none'}"
        " (./px pack remove deletes one)",
        f"  hunt records (history): {', '.join(kept['hunt_records']) or 'none'}"
        " (./px hunt-remove deletes one)",
        "  detections no client runs now: "
        + (", ".join(kept["detections_no_client_runs_now"]) or "none"),
    ]
    if kept["detections_no_client_runs_now"]:
        lines.append(
            "  Give one to another client with ./px detection assign, or retire it with "
            "./px detection deprecate."
        )
    from praxis import changes

    for row in changes.status(get_settings().content_dir):
        if re.search(rf"(^|[-/]){re.escape(client_id)}($|-)", row["headRefName"]):
            lines.append(
                f"Open pull request {row['number']} ({row['title']}) is for this client; close it: "
                f'./px change close {row["number"]} --reason "client offboarded"'
            )
    lines.append(
        f'Next: ./px change submit "Offboard {client_id}", then ./px change merge <number>'
    )
    console.print("\n".join(lines), markup=False, highlight=False)


@sector_app.command("list")
def sector_list(as_json: Annotated[bool, typer.Option("--json")] = False) -> None:
    """Sectors with a threat profile, and the groups each one tracks."""
    from praxis import attack

    groups = attack.bundle()["groups"]
    data = {
        sector: {
            "description": p.description.strip(),
            "groups": {g: groups[g]["name"] for g in p.groups},
        }
        for sector, p in _repo().threat_profiles.items()
    }
    _out(data, as_json)


@sector_app.command("add")
def sector_add(
    sector: Annotated[str, typer.Argument(help="Lower case slug, e.g. construction.")],
    description: Annotated[str, typer.Option(help="One or two sentences on who targets it.")],
    group: Annotated[list[str], typer.Option(help="ATT&CK group id (G1024); repeatable.")],
    technique: Annotated[
        list[str] | None, typer.Option(help="Extra weight, as T1490=0.3; repeatable.")
    ] = None,
    replace: Annotated[bool, typer.Option(help="Overwrite an existing profile.")] = False,
) -> None:
    """Create a sector's threat profile. Find group ids with `praxis attack groups`."""
    from praxis import ops

    weights = {}
    for item in technique or []:
        name, _, value = item.partition("=")
        weights[name.strip()] = float(value)
    path = _op(
        lambda: ops.sector_add(
            get_settings().content_dir, sector, description, group, weights, replace
        )
    )
    console.print(f"wrote {path}")


@sector_app.command("remove")
def sector_remove(sector: str) -> None:
    """Delete a sector's threat profile. Refused while a client is in that sector."""
    from praxis import ops

    path = _op(lambda: ops.sector_remove(get_settings().content_dir, sector))
    console.print(
        f'removed {path}\nNext: ./px change submit "Remove sector {sector}" '
        "(one submit ships every change you have made)",
        markup=False,
    )


@app.command("hunt-remove")
def hunt_remove(hunt_id: str) -> None:
    """Delete the record of a hunt whose clients were all offboarded."""
    from praxis import ops

    path = _op(lambda: ops.hunt_remove(get_settings().content_dir, hunt_id))
    console.print(
        f'removed {path}\nNext: ./px change submit "Remove hunt record {hunt_id}" '
        "(one submit ships every change you have made)",
        markup=False,
    )


@pack_app.command("remove")
def pack_remove(pack_id: str) -> None:
    """Delete the record of a rule pack whose client was offboarded."""
    from praxis import ops

    path = _op(lambda: ops.pack_remove(get_settings().content_dir, pack_id))
    console.print(
        f'removed {path}\nNext: ./px change submit "Remove pack record {pack_id}" '
        "(one submit ships every change you have made)",
        markup=False,
    )


@attack_app.command("groups")
def attack_groups(query: str, as_json: Annotated[bool, typer.Option("--json")] = False) -> None:
    """Find ATT&CK groups by name or id, e.g. `praxis attack groups akira`.

    ATT&CK lists threat actors here. Ransomware families and tools (LockBit,
    Qilin, Cobalt Strike) are software in ATT&CK, not groups, so they do not appear.
    """
    from praxis import ops

    found = ops.attack_groups(query)
    if not found and not as_json:
        # Not an error: an empty answer to a search. Exit code 0.
        console.print(
            f"no ATT&CK group matches {query!r}. Groups are threat actors (for example Akira, "
            "Play, APT41); ransomware families and tools are listed as software, not groups. "
            "Browse https://attack.mitre.org/groups/ for names.",
            markup=False,
        )
        return
    _out(found, as_json)


@attack_app.command("technique")
def attack_technique(
    technique_id: str, as_json: Annotated[bool, typer.Option("--json")] = False
) -> None:
    """A technique's name, tactics (TA ids) and data components."""
    from praxis import ops

    _out(_op(lambda: ops.attack_technique(technique_id)), as_json)


@detection_app.command("list")
def detection_list(as_json: Annotated[bool, typer.Option("--json")] = False) -> None:
    """Every detection in the library and who runs it."""
    from praxis.agents.toolbox import Toolbox

    _out(Toolbox(get_settings().content_dir).list_detections(), as_json)


@detection_app.command("show")
def detection_show(
    detection_id: str, as_json: Annotated[bool, typer.Option("--json")] = False
) -> None:
    """One detection's metadata, README, query and test names."""
    from praxis.agents.toolbox import Toolbox

    _out(_op(lambda: Toolbox(get_settings().content_dir).read_detection(detection_id)), as_json)


@detection_app.command("write")
def detection_write(
    spec: Annotated[
        Path | None, typer.Argument(help="JSON or YAML file with the detection; - for stdin.")
    ] = None,
    schema: Annotated[bool, typer.Option(help="Print the spec's JSON schema and stop.")] = False,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Create a detection from one spec file: metadata, query, README text and test events.

    PRAXIS assigns the id, lays out the folder and writes the README on the
    template. The detection starts `staged` (shadow mode). Next: `lab test`,
    then `detection assign`.
    """
    import sys

    import yaml

    from praxis.agents.llm import _check, model_schema
    from praxis.agents.toolbox import Toolbox

    box = Toolbox(get_settings().content_dir, owner="detection-engineering")
    tool = box.tools()["write_detection"]
    if schema:
        print(json.dumps(model_schema(tool.schema), indent=2))
        return
    if spec is None:
        err.print("[red]error[/red] give a spec file, or --schema to see its format")
        raise typer.Exit(1)
    text = sys.stdin.read() if str(spec) == "-" else spec.read_text()
    data = yaml.safe_load(text)
    data.pop("detection_id", None)

    def write():
        _check(data, tool.schema, "spec")
        return box.write_detection(**data)

    result = _op(write)
    if result["validation_errors"]:
        result["next"] = "fix the spec for each validation error, then run this command again"
    else:
        result["next"] = (
            f"./px lab test {result['detection_id']}, then "
            f"./px detection assign {result['detection_id']} --client <id>"
        )
    _out(result, as_json)
    if result["validation_errors"]:
        raise typer.Exit(1)


@detection_app.command("assign")
def detection_assign(
    detection_id: str,
    client: Annotated[list[str] | None, typer.Option(help="Client id; repeatable.")] = None,
    content_pack: Annotated[
        str | None, typer.Option(help="Add it to a standing pack, for every subscriber.")
    ] = None,
) -> None:
    """Give a detection to clients, or add it to a content pack such as baseline."""
    import yaml

    from praxis import ops

    content_dir = get_settings().content_dir
    if not client and not content_pack:
        err.print("[red]error[/red] name at least one --client or a --content-pack")
        raise typer.Exit(1)
    for client_id in client or []:
        _op(lambda c=client_id: ops.client_subscribe(content_dir, c, detections=[detection_id]))
        console.print(f"{client_id} now runs {detection_id}")
    if content_pack:
        path = content_dir / "content-packs" / f"{content_pack}.yml"
        if not path.is_file():
            err.print(f"[red]error[/red] unknown content pack {content_pack!r}")
            raise typer.Exit(1)
        pack = yaml.safe_load(path.read_text())
        if detection_id not in pack["detections"]:
            pack["detections"].append(detection_id)
            path.write_text(yaml.safe_dump(pack, sort_keys=False))
        repo = _repo()
        for each in repo.clients.values():
            core.write_lock(repo, each)
        console.print(f"{detection_id} is in content pack {content_pack}")


def _lifecycle(detection_id: str, lifecycle: str) -> None:
    from praxis import ops

    result = _op(
        lambda: ops.detection_lifecycle(get_settings().content_dir, detection_id, lifecycle)
    )
    console.print(f"{detection_id}: {result['was']} -> {result['now']}")


@detection_app.command("promote")
def detection_promote(detection_id: str) -> None:
    """Take a staged detection out of shadow mode: its alerts reach the SOC."""
    _lifecycle(detection_id, "production")


@detection_app.command("stage")
def detection_stage(detection_id: str) -> None:
    """Put a detection in shadow mode: it runs, quietly."""
    _lifecycle(detection_id, "staged")


@detection_app.command("deprecate")
def detection_deprecate(detection_id: str) -> None:
    """Retire a detection: the next deploy removes it from every SIEM."""
    _lifecycle(detection_id, "deprecated")


@change_app.command("submit")
def change_submit(
    title: Annotated[str, typer.Argument(help="What the change does, as a short sentence.")],
    body: Annotated[str, typer.Option(help="More detail for the reviewer.")] = "",
    everything: Annotated[
        bool, typer.Option("--all", help="Include changes outside the content folder too.")
    ] = False,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Put the content changes on a branch and open a pull request.

    Only files under the content folder are included, so a spec or events
    file you keep next to it is never submitted.
    """
    from praxis import changes

    result = _op(lambda: changes.submit(get_settings().content_dir, title, body, everything))
    _out(result, as_json)


@change_app.command("status")
def change_status(
    number: Annotated[int | None, typer.Argument(help="Pull request number.")] = None,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """A pull request's checks, or every open pull request."""
    from praxis import changes

    _out(_op(lambda: changes.status(get_settings().content_dir, number)), as_json)


@change_app.command("home")
def change_home(as_json: Annotated[bool, typer.Option("--json")] = False) -> None:
    """Go back to an up-to-date main branch."""
    from praxis import changes

    _out(_op(lambda: changes.home(get_settings().content_dir)), as_json)


@change_app.command("show")
def change_show(
    number: int,
    diff: Annotated[
        bool, typer.Option("--diff", help="Also print the exact lines it adds and removes.")
    ] = False,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Read a pull request: its description, the files it changes, and its checks."""
    from praxis import changes

    result = _op(lambda: changes.show(get_settings().content_dir, number))
    if diff:
        result["diff"] = _op(lambda: changes.diff(get_settings().content_dir, number))
    if as_json:
        _out(result, True)
        return
    body, lines = result.pop("body", ""), result.pop("diff", "")
    _out(result, False)
    console.print("\n" + body, highlight=False, markup=False)
    if lines:
        print("\n" + lines)


@change_app.command("close")
def change_close(
    number: int,
    reason: Annotated[str, typer.Option(help="Why it is being closed; posted as a comment.")],
) -> None:
    """Close a pull request without merging it."""
    from praxis import changes

    _out(_op(lambda: changes.close(get_settings().content_dir, number, reason)), False)


@change_app.command("merge")
def change_merge(
    number: int,
    wait: Annotated[int, typer.Option(help="Seconds to wait for checks and the deploy.")] = 1500,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Wait for a pull request's checks, merge it, and wait for the deploy to finish.

    Merging deploys. Exit code 1 if a check or the deploy fails.
    """
    from praxis import changes

    result = _op(lambda: changes.merge(get_settings().content_dir, number, wait))
    _out(result, as_json)
    if not result["ok"]:
        raise typer.Exit(1)


@admin_app.command("deprovision")
def admin_deprovision(
    client_id: str,
    yes: Annotated[bool, typer.Option("--yes")] = False,
    delete_space: bool = False,
    delete_data: bool = False,
) -> None:
    """Server side of offboarding. Use `praxis client offboard` instead."""
    if not yes:
        err.print("[red]error[/red] pass --yes; this cannot be undone")
        raise typer.Exit(1)
    repo = _repo()
    client = _client(repo, client_id)
    for platform_name in client.platforms.enabled():
        for item in get_platform(platform_name).deprovision(client, delete_space, delete_data):
            verified = item.startswith("verified")
            console.print(item if verified else f"removed {item}", markup=False)


if __name__ == "__main__":
    app()
