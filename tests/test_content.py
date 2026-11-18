from __future__ import annotations

import yaml

from praxis import core
from praxis.content.docs import lint_readme
from praxis.settings import get_settings
from tests.conftest import DETECTION, README, write_yaml


def messages(issues) -> str:
    return "\n".join(str(i) for i in issues)


def test_fixture_repo_is_valid(repo):
    assert core.validate(repo) == []
    assert list(repo.detections) == ["PRX-000900"]
    assert [b.id for b in repo.detections_for(repo.clients["testco"])] == ["PRX-000900"]


def test_shipped_content_is_valid():
    repo = core.load_repo(get_settings().content_dir)
    assert messages(core.validate(repo)) == ""
    assert repo.detections, "the shipped content should contain detections"
    assert all(c.fictional for c in repo.clients.values())


def test_unknown_field_is_rejected(content):
    path = content / "detections" / "PRX-000900-test-detection" / "detection.yml"
    write_yaml(path, {**DETECTION, "surprise": 1})
    assert "surprise" in messages(core.load_repo(content).issues)


def test_folder_must_match_id(content):
    folder = content / "detections" / "PRX-000900-test-detection"
    folder.rename(folder.with_name("PRX-000901-wrong"))
    assert "folder name must start with" in messages(core.load_repo(content).issues)


def test_tests_are_required(content):
    case = content / "detections" / "PRX-000900-test-detection" / "tests" / "positive" / "case.json"
    case.unlink()
    assert "tests/positive" in messages(core.load_repo(content).issues)


def test_pack_with_unknown_detection(content):
    path = content / "content-packs" / "baseline.yml"
    pack = yaml.safe_load(path.read_text())
    pack["detections"].append("PRX-999999")
    write_yaml(path, pack)
    assert "unknown detection PRX-999999" in messages(core.load_repo(content).issues)


def test_attack_ids_are_checked(content):
    path = content / "detections" / "PRX-000900-test-detection" / "detection.yml"
    write_yaml(path, {**DETECTION, "attack": [{"technique": "T1059.001", "tactic": "TA0006"}]})
    assert "does not belong to tactic" in messages(core.validate(core.load_repo(content)))
    write_yaml(path, {**DETECTION, "attack": [{"technique": "T9999", "tactic": "TA0002"}]})
    assert "not in ATT&CK" in messages(core.validate(core.load_repo(content)))


def test_unknown_data_component(content):
    path = content / "detections" / "PRX-000900-test-detection" / "detection.yml"
    write_yaml(path, {**DETECTION, "data_components": ["Vibes"]})
    assert "unknown ATT&CK data component" in messages(core.validate(core.load_repo(content)))


def test_ioc_rules_need_expiry(content):
    path = content / "detections" / "PRX-000900-test-detection" / "detection.yml"
    write_yaml(path, {**DETECTION, "pyramid_tier": "hash"})
    assert "must set `expires`" in messages(core.load_repo(content).issues)


def test_lookback_must_cover_interval(content):
    path = content / "detections" / "PRX-000900-test-detection" / "detection.yml"
    write_yaml(path, {**DETECTION, "schedule": {"interval": "10m", "lookback": "5m"}})
    assert "lookback must be >=" in messages(core.load_repo(content).issues)


def test_readme_template():
    assert lint_readme(README, "PRX-000900") == []
    assert lint_readme(README.replace("## SOC triage", "## Triage"), "PRX-000900")
    assert lint_readme(README.replace("PRX-000900", "PRX-000111"), "PRX-000900")
    todo = README.replace("It matches a process", "TODO It matches a process")
    assert "placeholder" in " ".join(lint_readme(todo, "PRX-000900"))


def test_elastic_query_must_not_name_indices(content):
    query = content / "detections" / "PRX-000900-test-detection" / "elastic.eql"
    query.write_text('process where _index == "logs-x-acme" and process.name == "evil.exe"')
    assert "must not name indices" in messages(core.validate(core.load_repo(content)))


def test_elastic_index_pattern_shape(content):
    path = content / "detections" / "PRX-000900-test-detection" / "detection.yml"
    write_yaml(path, {**DETECTION, "log_sources": {"elastic": {"indices": ["winlogbeat-*"]}}})
    assert "data-stream pattern" in messages(core.validate(core.load_repo(content)))


def test_env_files_fill_missing_variables(tmp_path, monkeypatch):
    import os

    from praxis.settings import load_env_files

    env_file = tmp_path / "lab.env"
    env_file.write_text("# comment\nPRAXIS_TEST_A=from-file\nPRAXIS_TEST_B=b=1\n")
    monkeypatch.setenv("PRAXIS_ENV_FILE", str(env_file))
    monkeypatch.setenv("PRAXIS_TEST_A", "already-set")
    monkeypatch.delenv("PRAXIS_TEST_B", raising=False)
    load_env_files()
    assert os.environ["PRAXIS_TEST_A"] == "already-set"
    assert os.environ.pop("PRAXIS_TEST_B") == "b=1"
