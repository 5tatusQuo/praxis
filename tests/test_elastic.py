from __future__ import annotations

import json

import httpx
import pytest

from praxis import core
from praxis.platforms import get_platform
from praxis.platforms.elastic import connection as connection_module
from praxis.platforms.elastic.connection import ElasticConnection
from praxis.platforms.elastic.render import deployed_hash


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
    assert get_platform("elastic").render(repo.detections["PRX-000900"], other).content_hash != (
        first.content_hash
    )


def test_drafts_are_not_rendered(repo):
    repo.detections["PRX-000900"].meta.lifecycle = "draft"
    assert render(repo) == []


class FakeKibana:
    """Just enough of the Detection Engine API to exercise deploy and smoke."""

    def __init__(self):
        self.rules: dict[str, dict] = {}
        self.calls: list[tuple[str, str]] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        assert request.url.path.startswith("/s/testco/api/detection_engine/rules")
        assert request.headers["authorization"] == "ApiKey deploy-key"
        self.calls.append((request.method, request.url.path))
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
    assert [a.action for a in platform.deploy(changed, client)] == ["updated"]
    assert kibana.rules["PRX-000900"]["severity"] == "high"
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
