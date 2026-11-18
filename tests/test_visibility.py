from __future__ import annotations

import pytest

from praxis import attack, core
from praxis.content.models import LabSource
from praxis.lab import generate
from praxis.visibility.engine import (
    Thresholds,
    build_snapshot,
    diff_snapshots,
    rule_status,
    score_components,
    threat_weights,
    top_gaps,
)
from praxis.visibility.inventory import Inventory, RuleHealth, SourceInventory
from praxis.visibility.navigator import coverage_layer
from tests.conftest import write_yaml

NOTE = """---
platform: elastic
source: logs-endpoint.events.process
name: Process events
data_components:
  Process Creation: [process.name, process.command_line]
sample:
  event: {category: [process]}
  process: {name: a.exe, command_line: a.exe}
---
## What it is

Process events.

## Useful queries

None.

## Analyst notes

None.
"""
TABLE = "logs-endpoint.events.process-testco"


def source(**changes) -> SourceInventory:
    base = dict(
        platform="elastic",
        source="logs-endpoint.events.process",
        table=TABLE,
        events_14d=1000,
        events_24h=70,
        days_with_data=14,
        hosts=10,
        last_event="2026-01-01T00:00:00Z",
        field_population={"process.name": 1.0, "process.command_line": 1.0},
    )
    return SourceInventory(**{**base, **changes})


def rule(**changes) -> RuleHealth:
    base = dict(
        detection_id="PRX-000900",
        platform="elastic",
        enabled=True,
        last_status="succeeded",
        last_run="2026-01-01T00:00:00Z",
        alerts_30d=0,
        deployed_hash="x",
        tables=[TABLE],
    )
    return RuleHealth(**{**base, **changes})


@pytest.fixture
def vrepo(content):
    note = content / "datamap-catalog" / "elastic" / "logs-endpoint.events.process.md"
    note.parent.mkdir(parents=True)
    note.write_text(NOTE)
    write_yaml(
        content / "threat-profiles" / "retail.yml",
        {
            "sector": "retail",
            "description": "test",
            "groups": ["G0046", "G0037"],
            "techniques": {"T1490": 0.4},
        },
    )
    repo = core.load_repo(content)
    assert core.validate(repo) == []
    return repo


def inventory(sources, rules) -> Inventory:
    return Inventory("testco", "2026-01-01T00:00:00Z", sources, rules)


def component(repo, src) -> dict:
    client = repo.clients["testco"]
    (result,) = score_components(repo, client, inventory([src], []), Thresholds())
    return result


def test_component_scores_one_point_per_factor(vrepo):
    assert component(vrepo, source())["score"] == 4
    assert component(vrepo, source(days_with_data=9))["score"] == 3
    low_fields = {"process.name": 1.0, "process.command_line": 0.5}
    assert component(vrepo, source(field_population=low_fields))["score"] == 3
    vrepo.clients["testco"].assets = type("A", (), {"endpoints": 20})()
    half = component(vrepo, source())
    assert half["score"] == 3 and half["factors"]["host_coverage"] is False


def test_silent_source_scores_zero(vrepo):
    silent = component(vrepo, source(events_24h=0))
    assert silent["score"] == 0 and silent["silent"] is True


def test_rule_status():
    live = {TABLE}
    assert rule_status(rule(), live) == "healthy"
    assert rule_status(rule(enabled=False), live) == "disabled"
    assert rule_status(rule(last_status="failed"), live) == "blind"
    assert rule_status(rule(last_status=None), live) == "blind"
    assert rule_status(rule(), set()) == "blind", "its data source is silent"


def classes(snapshot) -> dict[str, str]:
    return {t["id"]: t["class"] for t in snapshot["techniques"]}


def test_classification(vrepo):
    client = vrepo.clients["testco"]
    snap = build_snapshot(vrepo, client, inventory([source()], [rule()]))
    found = classes(snap)
    # The fixture detection maps to T1059.001; its parent is covered with it.
    assert found["T1059.001"] == "covered" and found["T1059"] == "covered"
    process_only = next(
        t
        for t, v in attack.bundle()["techniques"].items()
        if "Process Creation" in v["data_components"] and not t.startswith("T1059")
    )
    assert found[process_only] == "detection_gap"
    unseen = next(
        t
        for t, v in attack.bundle()["techniques"].items()
        if v["data_components"] and "Process Creation" not in v["data_components"]
    )
    assert found[unseen] == "visibility_gap"
    summary = snap["summary"]
    assert (
        sum(summary[k] for k in ("covered", "detection_gap", "visibility_gap", "blind_rule"))
        == (summary["techniques"])
    )
    assert summary["rules"] == {"healthy": 1, "blind": 0, "disabled": 0}


def test_blind_rule_when_source_goes_silent(vrepo):
    client = vrepo.clients["testco"]
    snap = build_snapshot(vrepo, client, inventory([source(events_24h=0)], [rule()]))
    assert classes(snap)["T1059.001"] == "blind_rule"
    assert snap["summary"]["covered"] == 0 and snap["summary"]["rules"]["blind"] == 1
    assert snap["summary"]["detection_gap"] == 0, "nothing is visible when the source is silent"


def test_disabled_rule_gives_no_coverage(vrepo):
    client = vrepo.clients["testco"]
    snap = build_snapshot(vrepo, client, inventory([source()], [rule(enabled=False)]))
    assert classes(snap)["T1059.001"] == "detection_gap"


def test_threat_weights_and_gap_order(vrepo):
    client = vrepo.clients["testco"]
    weights = threat_weights(vrepo, client)
    groups = attack.bundle()["groups"]
    both = set(groups["G0046"]["techniques"]) & set(groups["G0037"]["techniques"])
    only_one = set(groups["G0046"]["techniques"]) - set(groups["G0037"]["techniques"])
    assert weights[sorted(both)[0]] == 1.0 and weights[sorted(only_one)[0]] == 0.5
    assert weights["T1490"] >= 0.4
    snap = build_snapshot(vrepo, client, inventory([source()], []))
    gaps = top_gaps(snap, "detection_gap", 5)
    assert [g["weight"] for g in gaps] == sorted((g["weight"] for g in gaps), reverse=True)
    assert snap["summary"]["weighted_coverage_pct"] == 0.0


def test_snapshot_is_deterministic_and_diffable(vrepo):
    client = vrepo.clients["testco"]
    first = build_snapshot(vrepo, client, inventory([source()], [rule()]))
    again = build_snapshot(vrepo, client, inventory([source()], [rule()]))
    assert first == again
    later = build_snapshot(vrepo, client, inventory([source()], [rule(last_status="failed")]))
    changes = {c["id"]: (c["from"], c["to"]) for c in diff_snapshots(first, later)}
    assert changes["T1059.001"] == ("covered", "blind_rule")


def test_navigator_layer(vrepo):
    client = vrepo.clients["testco"]
    layer = coverage_layer(build_snapshot(vrepo, client, inventory([source()], [rule()])))
    assert layer["domain"] == "enterprise-attack"
    covered = [t for t in layer["techniques"] if t["techniqueID"] == "T1059.001"]
    assert covered and covered[0]["color"] == "#2EC4B6" and covered[0]["tactic"] == "execution"
    assert len(layer["legendItems"]) == 4


def test_unmapped_table_is_reported(vrepo):
    client = vrepo.clients["testco"]
    odd = source(source="logs-custom.app", table="logs-custom.app-testco")
    snap = build_snapshot(vrepo, client, inventory([source(), odd], []))
    assert [s["table"] for s in snap["sources"] if not s["mapped"]] == ["logs-custom.app-testco"]


def test_lab_generator_is_deterministic_and_respects_profile(vrepo):
    from datetime import UTC, datetime, timedelta

    client = vrepo.clients["testco"]
    spec = LabSource(
        source="logs-endpoint.events.process",
        hosts=3,
        events_per_day=100,
        sparse_fields={"process.command_line": 0.5},
    )
    end = datetime(2026, 1, 15, tzinfo=UTC)
    sample = vrepo.datamap[("elastic", spec.source)].sample
    events = generate(client, spec, sample, end - timedelta(days=2), end)
    assert events == generate(client, spec, sample, end - timedelta(days=2), end)
    assert len(events) == 200
    assert {e["host"]["name"] for e in events} == {f"testco-host-00{i}" for i in (1, 2, 3)}
    with_field = sum(1 for e in events if "command_line" in e["process"])
    assert 60 < with_field < 140
    assert all(e["labels"]["praxis_lab"] == "seed" for e in events)


def test_bad_visibility_content_is_rejected(vrepo, content):
    write_yaml(
        content / "threat-profiles" / "retail.yml",
        {"sector": "retail", "description": "x", "groups": ["G9999"]},
    )
    assert "G9999 is not an ATT&CK group" in str(core.validate(core.load_repo(content)))
