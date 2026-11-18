"""Operator actions: what a person or their AI assistant does to run a client."""

from __future__ import annotations

import pytest
import yaml

from praxis import core, ops
from praxis.agents.toolbox import Toolbox
from tests.conftest import write_yaml


@pytest.fixture
def base(content):
    note = content / "datamap-catalog" / "elastic" / "logs-endpoint.events.process.md"
    note.parent.mkdir(parents=True)
    from tests.test_visibility import NOTE

    note.write_text(NOTE)
    return content


def test_sector_add_checks_group_ids(base):
    with pytest.raises(ops.OpsError, match="not ATT&CK group ids"):
        ops.sector_add(base, "construction", "Builders.", ["G9999"])
    path = ops.sector_add(base, "construction", "Ransomware crews.", ["G1024"], {"T1490": 0.3})
    text = path.read_text()
    assert "G1024  # Akira" in text and "T1490: 0.3" in text
    assert core.validate(core.load_repo(base)) == []
    with pytest.raises(ops.OpsError, match="already has a threat profile"):
        ops.sector_add(base, "construction", "Again.", ["G1024"])
    assert ops.attack_groups("akira") == [{"id": "G1024", "name": "Akira", "techniques": 24}]


def test_client_add_writes_everything_and_says_what_is_next(base):
    with pytest.raises(ops.OpsError, match="has no threat profile"):
        ops.client_add(base, "ironbridge", "Ironbridge Construction", "construction", 40)
    assert not (base / "clients" / "ironbridge").exists(), "a refused client leaves nothing behind"
    ops.sector_add(base, "construction", "Ransomware crews.", ["G1024"])
    result = ops.client_add(base, "ironbridge", "Ironbridge Construction", "construction", 40)
    assert result["detections"] == ["PRX-000900"]
    assert "./px client provision ironbridge" in result["next"]
    repo = core.load_repo(base)
    assert core.validate(repo) == []
    client = repo.clients["ironbridge"]
    assert (
        client.name.endswith("(fictional)") and client.fictional and client.assets.endpoints == 40
    )
    assert core.lock_is_current(repo, client)
    profile = repo.lab_telemetry["ironbridge"]
    assert [s.source for s in profile.sources] == ["logs-endpoint.events.process"], (
        "the lab profile covers the sources the client's rules read"
    )
    with pytest.raises(ops.OpsError, match="already exists"):
        ops.client_add(base, "ironbridge", "Again", "construction", 1)
    with pytest.raises(ops.OpsError, match="unknown content packs"):
        ops.client_add(base, "other", "Other", "construction", 1, ["nope"])


def test_subscribe_lifecycle_and_remove(base):
    ops.sector_add(base, "construction", "Ransomware crews.", ["G1024"])
    ops.client_add(base, "ironbridge", "Ironbridge", "construction", 40, packs=[])
    assert ops.client_show(core.load_repo(base), "ironbridge")["detections_running"] == []
    result = ops.client_subscribe(base, "ironbridge", detections=["PRX-000900"])
    assert result["detections"] == ["PRX-000900"]
    with pytest.raises(ops.OpsError, match="unknown detection"):
        ops.client_subscribe(base, "ironbridge", detections=["PRX-999999"])
    assert yaml.safe_load((base / "clients/ironbridge/client.yml").read_text())["detections"] == [
        "PRX-000900"
    ], "a refused change is rolled back"

    assert ops.detection_lifecycle(base, "PRX-000900", "staged") == {
        "detection": "PRX-000900",
        "was": "production",
        "now": "staged",
    }
    repo = core.load_repo(base)
    assert core.lock_is_current(repo, repo.clients["ironbridge"])
    with pytest.raises(ops.OpsError, match="lifecycle must be one of"):
        ops.detection_lifecycle(base, "PRX-000900", "live")

    ops.client_subscribe(base, "ironbridge", detections=["PRX-000900"], remove=True)
    assert ops.client_show(core.load_repo(base), "ironbridge")["detections_running"] == []
    assert ops.client_remove(base, "ironbridge")
    assert "ironbridge" not in core.load_repo(base).clients


def test_status_is_one_place_to_orient(base):
    report = ops.status(base)
    assert report["content"]["valid"] and report["content"]["next_detection_id"] == "PRX-000901"
    assert report["clients"]["testco"]["detections"] == ["PRX-000900"]
    assert "not connected" in report["server"]
    write_yaml(base / "content-packs" / "baseline.yml", {"id": "baseline", "name": "x"})
    assert not ops.status(base)["content"]["valid"]


def test_operator_tools_are_on_the_mcp_surface_but_not_given_to_agents(base):
    from praxis.agents import hunt, pack, tuner

    box = Toolbox(base)
    operator = {"status", "client_add", "client_subscribe", "sector_add", "detection_lifecycle"}
    assert operator <= set(box.tools())
    for allowed in (
        pack.CURATOR_TOOLS,
        pack.ENGINEER_TOOLS,
        pack.REVIEWER_TOOLS,
        tuner.TUNER_TOOLS,
        hunt.HUNT_TOOLS,
    ):
        assert not operator & set(allowed), (
            "PRAXIS's own agents cannot create clients or promote rules"
        )
    text, failed = box.call(
        "client_add", {"client_id": "x", "name": "X", "sector": "none", "endpoints": 1}
    )
    assert failed and "has no threat profile" in text
