from __future__ import annotations

import json

import httpx
import pytest

from praxis import core
from praxis.content.tuning import ResolvedTuning
from praxis.platforms import get_platform
from praxis.platforms.elastic import connection as connection_module
from praxis.platforms.elastic.connection import ElasticConnection
from praxis.platforms.elastic.render import deployed_hash
from tests.conftest import write_yaml


def render(repo):
    return core.render_client(repo, repo.clients["testco"], "elastic")


def test_render_envelope(repo):
    (rule,) = render(repo)
    env = rule.envelope
    assert env["rule_id"] == "PRX-000900"
    assert env["type"] == "eql" and env["language"] == "eql"
    assert env["index"] == ["logs-endpoint.events.process-testco"]
    assert env["interval"] == "5m" and env["from"] == "now-6m"
    assert env["threat"][0]["tactic"] == {
        "id": "TA0002",
        "name": "Execution",
        "reference": "https://attack.mitre.org/tactics/TA0002/",
    }
    technique = env["threat"][0]["technique"][0]
    assert technique["id"] == "T1059" and technique["subtechnique"][0]["id"] == "T1059.001"
    assert "Nothing to triage" in env["note"]
    assert deployed_hash(env) == rule.content_hash[:16]


def test_render_is_stable_and_client_specific(repo, content):
    first, second = render(repo)[0], render(core.load_repo(content))[0]
    assert first.content_hash == second.content_hash
    other = repo.clients["testco"].model_copy(deep=True)
    other.platforms.elastic.namespace = "other"
    rendered = get_platform("elastic").render(
        repo.detections["PRX-000900"], other, ResolvedTuning()
    )
    assert rendered.content_hash != first.content_hash


def test_drafts_are_not_rendered(repo):
    repo.detections["PRX-000900"].meta.lifecycle = "draft"
    assert render(repo) == []


class FakeKibana:
    """Just enough of the Detection Engine API to exercise deploy and smoke."""

    def __init__(self):
        self.rules: dict[str, dict] = {}
        self.lists: dict[str, list[dict]] = {}
        self.toggles: list[bool] = []
        self.calls: list[tuple[str, str]] = []

    def exception_lists(self, request: httpx.Request) -> httpx.Response:
        list_id = request.url.params.get("list_id")
        if request.url.path.endswith("/items/_find"):
            if list_id not in self.lists:
                return httpx.Response(404, json={"message": "not found"})
            return httpx.Response(200, json={"total": len(self.lists[list_id])})
        if request.method == "DELETE":
            found = self.lists.pop(list_id, None) is not None
            return httpx.Response(200 if found else 404, json={})
        body = json.loads(request.content)
        if request.url.path.endswith("/items"):
            self.lists[body["list_id"]].append(body)
        else:
            self.lists[body["list_id"]] = []
        return httpx.Response(200, json={**body, "id": f"so-{body['list_id']}"})

    def handler(self, request: httpx.Request) -> httpx.Response:
        assert request.headers["authorization"] == "ApiKey deploy-key"
        self.calls.append((request.method, request.url.path))
        if request.url.path.startswith("/s/testco/api/exception_lists"):
            return self.exception_lists(request)
        assert request.url.path.startswith("/s/testco/api/detection_engine/rules")
        if request.url.path.endswith("/_find"):
            data = list(self.rules.values())
            return httpx.Response(200, json={"data": data, "total": len(data)})
        rule_id = request.url.params.get("rule_id")
        if request.method == "GET":
            if rule_id not in self.rules:
                return httpx.Response(404, json={"message": "not found"})
            return httpx.Response(200, json=self.rules[rule_id])
        if request.method == "DELETE":
            return httpx.Response(200, json=self.rules.pop(rule_id))
        body = json.loads(request.content)
        if request.method == "PATCH":
            self.rules[body["rule_id"]].update(body)
            self.toggles.append(body["enabled"])
            return httpx.Response(200, json=self.rules[body["rule_id"]])
        self.rules[body["rule_id"]] = {
            **body,
            "updated_at": "2026-01-01T00:00:00.000Z",
            "execution_summary": {
                "last_execution": {
                    "date": "2026-01-01T00:00:05.000Z",
                    "status": "succeeded",
                    "message": "ok",
                }
            },
        }
        return httpx.Response(200, json=self.rules[body["rule_id"]])


@pytest.fixture
def kibana(monkeypatch):
    fake = FakeKibana()

    def from_env(name, role, client_id=None):
        assert (name, role, client_id) == ("lab", "deploy", "testco")
        client = httpx.Client(
            base_url="http://kibana.test",
            headers={"Authorization": "ApiKey deploy-key"},
            transport=httpx.MockTransport(fake.handler),
        )
        return ElasticConnection(name=name, role=role, es=client, kibana=client)

    monkeypatch.setattr(connection_module.ElasticConnection, "from_env", staticmethod(from_env))
    return fake


def test_deploy_creates_then_is_idempotent_then_updates(repo, kibana):
    platform, client = get_platform("elastic"), repo.clients["testco"]
    rules = render(repo)
    assert [a.action for a in platform.deploy(rules, client)] == ["created"]
    assert [a.action for a in platform.deploy(rules, client)] == ["unchanged"]
    repo.detections["PRX-000900"].meta.severity = "high"
    changed = render(repo)
    assert kibana.toggles == []
    assert [a.action for a in platform.deploy(changed, client)] == ["updated"]
    assert kibana.rules["PRX-000900"]["severity"] == "high"
    assert kibana.toggles == [False, True], "an updated rule is re-enabled so it runs now"
    assert all(r.ok for r in platform.smoke(changed, client))


def test_deploy_removes_rules_it_no_longer_renders(repo, kibana):
    platform, client = get_platform("elastic"), repo.clients["testco"]
    platform.deploy(render(repo), client)
    kibana.rules["manual"] = {"rule_id": "manual", "tags": ["made-in-console"]}
    actions = platform.deploy([], client)
    assert [(a.detection_id, a.action) for a in actions] == [("PRX-000900", "deleted")]
    assert list(kibana.rules) == ["manual"], "rules PRAXIS does not manage are left alone"


def test_smoke_flags_missing_drifted_and_failed(repo, kibana):
    platform, client = get_platform("elastic"), repo.clients["testco"]
    rules = render(repo)
    assert platform.smoke(rules, client)[0].status == "missing"
    platform.deploy(rules, client)
    kibana.rules["PRX-000900"]["execution_summary"]["last_execution"]["status"] = "failed"
    assert not platform.smoke(rules, client)[0].ok
    kibana.rules["PRX-000900"]["tags"] = ["PRAXIS", "praxis-hash:0000000000000000"]
    assert platform.smoke(rules, client)[0].status == "drift"


# -- tuning ---------------------------------------------------------------------
TUNING = {
    "rule": "PRX-000900",
    "reason": "The fixture updater runs evil.exe from a known folder.",
    "evidence": ["ALERT-1"],
    "author": "human:tests",
    "expires": "2027-01-31",
    "exclude": [
        {"field": "process.parent.executable", "op": "endswith", "value": "\\Upd\\upd*.exe"}
    ],
    "examples": [{"process": {"name": "evil.exe", "parent": {"executable": "C:\\Upd\\upd*.exe"}}}],
}


def tuned_repo(content, tuning=TUNING):
    write_yaml(content / "clients" / "testco" / "tuning" / "PRX-000900.yml", tuning)
    return core.load_repo(content)


def test_exclusion_renders_an_exception_list(content):
    repo = tuned_repo(content)
    assert core.validate(repo) == []
    (rule,) = render(repo)
    assert rule.envelope["exceptions_list"] == [
        {"list_id": "praxis-testco-prx-000900", "type": "detection", "namespace_type": "single"}
    ]
    (item,) = rule.extras["exception_items"]
    # Backslashes and the literal `*` are escaped for Elasticsearch's wildcard query.
    assert item["entries"] == [
        {
            "field": "process.parent.executable",
            "operator": "included",
            "type": "wildcard",
            "value": "*\\\\Upd\\\\upd\\*.exe",
        }
    ]
    assert item["expire_time"] == "2027-01-31T23:59:59.000Z"
    assert "praxis-tuned" in rule.envelope["tags"]
    assert rule.tuning_digest


def test_tuning_changes_the_hash_only_for_that_client(repo, content):
    untuned = render(repo)[0]
    tuned = render(tuned_repo(content))[0]
    assert tuned.content_hash != untuned.content_hash
    assert untuned.tuning_digest is None and untuned.extras == {}


def test_scalar_overrides_and_disable(content):
    tuning = {
        "rule": "PRX-000900",
        "reason": "Crown-jewel hosts: page the on-call lead.",
        "author": "human:tests",
        "severity": "critical",
        "risk_score": 99,
        "schedule": {"interval": "1m", "lookback": "2m"},
    }
    env = render(tuned_repo(content, tuning))[0].envelope
    assert (env["severity"], env["risk_score"]) == ("critical", 99)
    assert (env["interval"], env["from"]) == ("1m", "now-2m")
    off = {"rule": "PRX-000900", "reason": "Too noisy until the parser is fixed.", "author": "x"}
    off |= {"enabled": False, "expires": "2027-01-31"}
    assert render(tuned_repo(content, off))[0].envelope["enabled"] is False


def test_platform_overlay_applies_to_every_client_and_client_wins(content):
    overlay = {**TUNING, "severity": "low", "risk_score": 21}
    write_yaml(content / "overlays" / "platform" / "elastic" / "PRX-000900.yml", overlay)
    repo = core.load_repo(content)
    assert core.validate(repo) == []
    rule = render(repo)[0]
    assert rule.envelope["severity"] == "low" and len(rule.extras["exception_items"]) == 1
    client_tuning = {"rule": "PRX-000900", "reason": "Client wants it louder than the overlay."}
    client_tuning |= {"author": "human:tests", "severity": "high", "risk_score": 73}
    rule = render(tuned_repo(content, client_tuning))[0]
    assert rule.envelope["severity"] == "high", "the client layer wins over the platform overlay"
    assert len(rule.extras["exception_items"]) == 1, "exclusions from every layer add up"


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"evidence": []}, "must cite an alert or ticket"),
        ({"examples": []}, "needs at least one event"),
        ({"exclude": [{"field": "a", "op": "in", "value": "x"}]}, "takes a list"),
        ({"exclude": [{"field": "a", "op": "regex", "value": "x"}]}, "exclude.0.op"),
        ({"rule": "PRX-000901"}, "file name must be"),
    ],
)
def test_bad_tuning_is_rejected(content, change, message):
    repo = tuned_repo(content, {**TUNING, **change})
    assert message in "\n".join(str(i) for i in repo.issues)


def test_disable_needs_expiry_and_empty_tuning_is_rejected(content):
    off = {"rule": "PRX-000900", "reason": "Too noisy until the parser is fixed.", "author": "x"}
    assert "needs an `expires` date" in str(tuned_repo(content, {**off, "enabled": False}).issues)
    assert "changes nothing" in str(tuned_repo(content, off).issues)


def test_deploy_syncs_exception_list(content, kibana):
    platform = get_platform("elastic")
    repo = tuned_repo(content)
    client, rules = repo.clients["testco"], render(repo)
    assert [a.action for a in platform.deploy(rules, client)] == ["created"]
    assert len(kibana.lists["praxis-testco-prx-000900"]) == 1
    reference = kibana.rules["PRX-000900"]["exceptions_list"][0]
    assert reference["id"] == "so-praxis-testco-prx-000900"
    assert all(r.ok for r in platform.smoke(rules, client))
    kibana.lists["praxis-testco-prx-000900"].clear()
    assert platform.smoke(rules, client)[0].status == "drift", "console edits are caught"
    # Removing the tuning removes the list.
    (content / "clients" / "testco" / "tuning" / "PRX-000900.yml").unlink()
    repo = core.load_repo(content)
    assert [a.action for a in platform.deploy(render(repo), client)] == ["updated"]
    assert kibana.lists == {}


def test_lab_orchestration_checks_tuning(content, monkeypatch):
    repo = tuned_repo(content)
    seen = []

    def lab_fires(self, bundle, events, tuning):
        seen.append(tuning is not None)
        # Pretend the exclusion silences only the tuning example.
        return not (tuning and "parent" in events[0].get("process", {}))

    monkeypatch.setattr(type(get_platform("elastic")), "lab_fires", lab_fires)
    results = core.lab_test(repo, repo.detections["PRX-000900"])
    by_name = {(r.scope, r.name): r for r in results}
    assert by_name[("testco", "case (tuned)")].passed
    assert by_name[("testco", "tuning example 1 (untuned)")].passed
    assert by_name[("testco", "tuning example 1 (tuned)")].passed
    # The fake fires on everything untuned, so the base negative case must fail.
    assert [r.passed for r in results if r.scope == "base"] == [True, False]


def test_lock_roundtrip(content):
    repo = tuned_repo(content)
    client = repo.clients["testco"]
    assert not core.lock_is_current(repo, client)
    core.write_lock(repo, client)
    assert core.lock_is_current(core.load_repo(content), client)
    lock = core.build_lock(repo, client)["platforms"]["elastic"]["PRX-000900"]
    assert lock["version"] == 1 and len(lock["hash"]) == 64 and lock["tuning"]
    repo.detections["PRX-000900"].meta.severity = "low"
    assert not core.lock_is_current(repo, client)


def test_exclusion_with_also_renders_one_item_with_several_entries(content):
    tuning = {
        **TUNING,
        "exclude": [
            {
                "field": "process.parent.executable",
                "op": "endswith",
                "value": "\\Upd\\upd.exe",
                "also": [{"field": "process.command_line", "op": "contains", "value": "--quiet"}],
            }
        ],
    }
    (rule,) = render(tuned_repo(content, tuning))
    (item,) = rule.extras["exception_items"]
    assert [e["field"] for e in item["entries"]] == [
        "process.parent.executable",
        "process.command_line",
    ]


def test_backtest_counts_every_match_not_just_the_samples(repo, monkeypatch):
    from praxis.platforms.elastic import platform as module

    events = [{"_source": {"process": {"name": f"p{i}"}}} for i in range(32)]

    def handler(request):
        assert json.loads(request.content)["size"] == module.BACKTEST_LIMIT
        return httpx.Response(200, json={"hits": {"total": {"value": 32}, "events": events}})

    client = httpx.Client(base_url="http://es.test", transport=httpx.MockTransport(handler))
    monkeypatch.setattr(
        connection_module.ElasticConnection,
        "from_env",
        staticmethod(
            lambda name, role, client_id=None: ElasticConnection(name, role, client, client)
        ),
    )
    result = get_platform("elastic").backtest(
        repo.clients["testco"], "process where true", ["logs-x-*"]
    )
    assert result["hits"] == 32 and result["capped"] is False and len(result["samples"]) == 5


def test_a_rule_with_no_telemetry_does_not_fail_the_deploy(repo, kibana):
    platform, client = get_platform("elastic"), repo.clients["testco"]
    rules = render(repo)
    platform.deploy(rules, client)
    kibana.rules["PRX-000900"]["execution_summary"]["last_execution"] = {
        "date": "2026-01-01T00:00:05.000Z",
        "status": "partial failure",
        "message": "Unable to find matching indices for rule X. This warning will persist...",
    }
    (result,) = platform.smoke(rules, client)
    assert result.ok and result.status == "no telemetry"
    kibana.rules["PRX-000900"]["execution_summary"]["last_execution"]["message"] = "shard failure"
    assert not platform.smoke(rules, client)[0].ok, "any other partial failure still fails"


def test_force_rewrites_an_unchanged_rule(repo, kibana):
    platform, client = get_platform("elastic"), repo.clients["testco"]
    rules = render(repo)
    platform.deploy(rules, client)
    kibana.rules["PRX-000900"]["query"] = "process where false"  # a console edit keeps the hash tag
    assert [a.action for a in platform.deploy(rules, client)] == ["unchanged"]
    assert [a.action for a in platform.deploy(rules, client, force=True)] == ["updated"]
    assert kibana.rules["PRX-000900"]["query"] == rules[0].envelope["query"]


def test_drift_sees_console_edits(repo, monkeypatch):
    (rule,) = render(repo)
    live = {**rule.envelope}

    def connect(name, role, client_id=None):
        transport = httpx.MockTransport(lambda request: httpx.Response(200, json=live))
        client = httpx.Client(base_url="http://kibana.test", transport=transport)
        return ElasticConnection(name, role, client, client)

    monkeypatch.setattr(connection_module.ElasticConnection, "from_env", staticmethod(connect))
    platform, target = get_platform("elastic"), repo.clients["testco"]
    assert platform.live_differences(rule, target) == []
    live["query"] = "process where false"
    live["enabled"] = False
    assert platform.live_differences(rule, target) == ["query was changed", "enabled was changed"]


def test_connection_check_explains_a_missing_deploy_key(repo, monkeypatch):
    for name in ("ES_URL", "KIBANA_URL", "READ_API_KEY", "DEPLOY_API_KEY", "DEPLOY_API_KEY_TESTCO"):
        monkeypatch.delenv(f"PRAXIS_ELASTIC_LAB_{name}", raising=False)
    checks = {c.role: c for c in get_platform("elastic").check_connection(repo.clients["testco"])}
    assert checks["deploy"].ok and "deploy/remote.sh check testco" in checks["deploy"].detail
    assert not checks["read"].ok, "a missing read key is a real failure"
