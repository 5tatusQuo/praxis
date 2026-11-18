"""The `praxis` command line."""

from __future__ import annotations

import json
import subprocess
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
lab_app = typer.Typer(no_args_is_help=True, help="Lab SIEM: replay test events.")
admin_app = typer.Typer(no_args_is_help=True, help="Onboarding tasks that need admin access.")
app.add_typer(lab_app, name="lab")
app.add_typer(admin_app, name="admin")
console = Console()
err = Console(stderr=True)


@app.callback()
def _main() -> None:
    load_env_files()


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
) -> None:
    """Check schemas, references, ATT&CK ids, README template and tuning hooks."""
    repo = _repo(strict=False)
    issues = core.validate(repo)
    if base:
        issues += core.docs_follow_queries(repo, base)
    for issue in issues:
        err.print(f"[red]error[/red] {issue}")
    if issues:
        raise typer.Exit(1)
    console.print(
        f"[green]ok[/green] {len(repo.detections)} detections, {len(repo.packs)} packs, "
        f"{len(repo.clients)} clients"
    )


@app.command()
def clients(as_json: Annotated[bool, typer.Option("--json")] = False) -> None:
    """List clients (use --json to feed a CI matrix)."""
    repo = _repo()
    if as_json:
        print(json.dumps(sorted(repo.clients)))
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
) -> None:
    """Replay test events in the lab SIEM, raw and under every client's tuning."""
    repo = _repo()
    wanted = detection_ids or sorted(repo.detections)
    failed = False
    table = Table("detection", "platform", "scope", "case", "expected", "fired", "result")
    for det_id in wanted:
        bundle = repo.detections.get(det_id)
        if bundle is None:
            err.print(f"[red]unknown detection {det_id}[/red]")
            raise typer.Exit(2)
        for case in core.lab_test(repo, bundle):
            failed |= not case.passed
            table.add_row(
                det_id,
                case.platform,
                case.scope,
                case.name,
                "fire" if case.expected else "stay quiet",
                "error" if case.error else ("yes" if case.fired else "no"),
                "[green]pass[/green]" if case.passed else f"[red]FAIL[/red] {case.error or ''}",
            )
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
) -> None:
    """Write a detection's test events into a fictional client's telemetry."""
    repo = _repo()
    client = _client(repo, client_id)
    bundle = repo.detections[detection_id]
    for platform_name in client.platforms.enabled():
        if platform_name not in bundle.implementations:
            continue
        if kind == "examples":
            source = _client(repo, from_client) if from_client else client
            events = repo.tuning_examples(detection_id, source, platform_name)
        else:
            cases = bundle.positive if kind == "positive" else bundle.negative
            events = [event for case in cases for event in case.events]
        count = get_platform(platform_name).replay(bundle, client, events)
        console.print(f"{platform_name}: wrote {count} {kind} events for {client.id}")


@lab_app.command("seed")
def lab_seed(client_ids: Annotated[list[str] | None, typer.Argument()] = None) -> None:
    """Top up a fictional client's synthetic telemetry (clients/<id>/lab/telemetry.yml)."""
    repo = _repo()
    for client_id in client_ids or sorted(repo.lab_telemetry):
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
    components = Table("data component", "score", "source", "detail", title="visibility (0-4)")
    for c in snapshot["components"]:
        d = c["detail"]
        missing = [k for k, ok in c["factors"].items() if not ok]
        detail = (
            "silent: no events in 24h"
            if c["silent"]
            else (
                f"{d['hosts']}/{d['expected_hosts']} hosts, fields {d['field_population']:.0%}"
                + (f", missing: {', '.join(missing)}" if missing else "")
            )
        )
        components.add_row(c["name"], str(c["score"]), c["source"], detail)
    console.print(components)
    rules = Table("rule", "status", "last run", "alerts 30d", "techniques", title="rules")
    for r in snapshot["rules"]:
        colour = {"healthy": "green", "blind": "red"}.get(r["status"], "yellow")
        rules.add_row(
            r["id"],
            f"[{colour}]{r['status']}[/{colour}]",
            r["last_status"] or "never",
            str(r["alerts_30d"]),
            ", ".join(r["techniques"]),
        )
    console.print(rules)
    gaps = Table("technique", "name", "weight", "visibility", title="top detection gaps")
    for t in top_gaps(snapshot, "detection_gap", 10):
        gaps.add_row(t["id"], t["name"], f"{t['weight']:.2f}", str(t["visibility"]))
    console.print(gaps)
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
    if as_json:
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
def connection_check(client_id: str) -> None:
    """Connect mode: check a client's read and deploy identities against its SIEMs."""
    repo = _repo()
    client = _client(repo, client_id)
    failed = False
    table = Table("platform", "identity", "result", "detail")
    for platform_name in client.platforms.enabled():
        for check in get_platform(platform_name).check_connection(client):
            failed |= not check.ok
            result = "[green]ok[/green]" if check.ok else "[red]FAIL[/red]"
            table.add_row(platform_name, check.role, result, check.detail)
    console.print(table)
    if failed:
        raise typer.Exit(1)


@app.command()
def release(
    client_id: str,
    smoke: Annotated[bool, typer.Option(help="Check each rule's first run after deploy.")] = True,
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
        for action in platform.deploy(rules, client):
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


if __name__ == "__main__":
    app()
