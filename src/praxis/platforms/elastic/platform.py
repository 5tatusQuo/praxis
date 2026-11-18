"""Elastic: EQL rules deployed through the Kibana Detection Engine API."""

from __future__ import annotations

import json
import re
import secrets
import time
from datetime import UTC, datetime, timedelta
from typing import Any

from praxis.content.loader import DetectionBundle, TestCase
from praxis.content.models import ELASTIC_INDEX_RE, Client
from praxis.platforms.base import (
    CaseResult,
    DeployAction,
    LabResult,
    Platform,
    RenderedRule,
    SmokeResult,
)
from praxis.platforms.elastic.connection import ApiError, ElasticConnection, call
from praxis.platforms.elastic.provision import provision
from praxis.platforms.elastic.render import (
    MANAGED_TAG,
    deployed_hash,
    render_rule,
    resolve_indices,
)
from praxis.settings import get_settings

LAB_NAMESPACE_PREFIX = "praxislab"
_HARD_CODED_INDEX = re.compile(r"\b_index\b|\bfrom\s+(logs|metrics|traces)-", re.IGNORECASE)


def _stamp(events: list[dict], end: datetime) -> list[dict]:
    """Give events fresh timestamps one second apart, keeping their order."""
    stamped = []
    for offset, event in enumerate(events):
        when = end - timedelta(seconds=len(events) - offset)
        stamped.append({**event, "@timestamp": when.isoformat().replace("+00:00", "Z")})
    return stamped


def _bulk_index(conn: ElasticConnection, index: str, events: list[dict]) -> None:
    lines = []
    for event in events:
        lines.append(json.dumps({"create": {}}))
        lines.append(json.dumps(event))
    result = call(
        conn.es,
        "POST",
        f"/{index}/_bulk",
        params={"refresh": "true"},
        content="\n".join(lines) + "\n",
        headers={"Content-Type": "application/x-ndjson"},
    )
    if result.get("errors"):
        failures = [i["create"]["error"] for i in result["items"] if "error" in i["create"]]
        raise RuntimeError(f"bulk index into {index} failed: {failures[:2]}")


class ElasticPlatform(Platform):
    name = "elastic"
    languages = {"eql": "eql"}

    # -- static checks -----------------------------------------------------
    def check(self, bundle: DetectionBundle) -> list[str]:
        problems = []
        impl = bundle.implementations[self.name]
        for pattern in bundle.meta.log_sources[self.name].indices:
            if not ELASTIC_INDEX_RE.match(pattern):
                problems.append(
                    f"log_sources.elastic index {pattern!r} must be a data-stream pattern "
                    "ending in '-*' (the namespace is filled in per client)"
                )
        if not impl.query:
            problems.append(f"{impl.path.name} is empty")
        if _HARD_CODED_INDEX.search(impl.query):
            problems.append(
                f"{impl.path.name} must not name indices; list them in detection.yml log_sources"
            )
        # Tuning hook: none needed in the query. Client tuning is rendered as an
        # exception list attached to the rule, so every Elastic rule is tunable.
        return problems

    # -- render ------------------------------------------------------------
    def render(self, bundle: DetectionBundle, client: Client) -> RenderedRule:
        return render_rule(bundle, client)

    # -- lab ---------------------------------------------------------------
    def _lab(self) -> ElasticConnection:
        return ElasticConnection.from_env(get_settings().lab_connection, "lab")

    def _search(self, conn: ElasticConnection, bundle: DetectionBundle, namespace: str) -> bool:
        impl = bundle.implementations[self.name]
        indices = resolve_indices(bundle.meta.log_sources[self.name].indices, namespace)
        result = call(
            conn.es,
            "POST",
            f"/{','.join(indices)}/_eql/search",
            params={"ignore_unavailable": "true"},
            json={"query": impl.query, "size": 1},
        )
        return result["hits"]["total"]["value"] > 0

    def _run_case(
        self, conn: ElasticConnection, bundle: DetectionBundle, case: TestCase, kind: str
    ) -> CaseResult:
        # Each case gets its own throwaway namespace, so cases never see each
        # other's events and clean-up is one data-stream delete.
        namespace = f"{LAB_NAMESPACE_PREFIX}{secrets.token_hex(5)}"
        indices = resolve_indices(bundle.meta.log_sources[self.name].indices, namespace)
        try:
            _bulk_index(conn, indices[0], _stamp(case.events, datetime.now(UTC)))
            fired = self._search(conn, bundle, namespace)
            return CaseResult(name=case.name, kind=kind, fired=fired)
        except (ApiError, RuntimeError) as err:
            return CaseResult(name=case.name, kind=kind, fired=False, error=str(err))
        finally:
            call(conn.es, "DELETE", f"/_data_stream/*-*-{namespace}", ok=(404,))

    def lab_test(self, bundle: DetectionBundle) -> LabResult:
        result = LabResult(detection_id=bundle.id, platform=self.name)
        with self._lab() as conn:
            for kind, cases in (("positive", bundle.positive), ("negative", bundle.negative)):
                for case in cases:
                    result.cases.append(self._run_case(conn, bundle, case, kind))
        return result

    def replay(self, bundle: DetectionBundle, client: Client, kind: str) -> int:
        target = client.platforms.elastic
        index = resolve_indices(bundle.meta.log_sources[self.name].indices, target.namespace)[0]
        cases = bundle.positive if kind == "positive" else bundle.negative
        count = 0
        with ElasticConnection.from_env(target.connection, "lab") as conn:
            for case in cases:
                _bulk_index(conn, index, _stamp(case.events, datetime.now(UTC)))
                count += len(case.events)
        return count

    def provision(self, client: Client, rotate: bool = False) -> list[str]:
        return provision(client, rotate)

    # -- deploy ------------------------------------------------------------
    @staticmethod
    def _rules_url(client: Client) -> str:
        return f"/s/{client.platforms.elastic.space}/api/detection_engine/rules"

    def _managed_rules(self, conn: ElasticConnection, client: Client) -> dict[str, dict[str, Any]]:
        rules: dict[str, dict[str, Any]] = {}
        page = 1
        while True:
            result = call(
                conn.kibana,
                "GET",
                f"{self._rules_url(client)}/_find",
                params={"page": page, "per_page": 500},
            )
            for rule in result["data"]:
                if MANAGED_TAG in rule.get("tags", []):
                    rules[rule["rule_id"]] = rule
            if page * 500 >= result["total"]:
                return rules
            page += 1

    def deploy(self, rules: list[RenderedRule], client: Client) -> list[DeployAction]:
        actions: list[DeployAction] = []
        with ElasticConnection.from_env(
            client.platforms.elastic.connection, "deploy", client.id
        ) as conn:
            existing = self._managed_rules(conn, client)
            url = self._rules_url(client)
            for rule in rules:
                current = existing.pop(rule.detection_id, None)
                short = rule.content_hash[:16]
                if current is None:
                    call(conn.kibana, "POST", url, json=rule.envelope)
                    action = "created"
                elif deployed_hash(current) == short and current.get("enabled"):
                    action = "unchanged"
                else:
                    call(conn.kibana, "PUT", url, json=rule.envelope)
                    action = "updated"
                actions.append(DeployAction(rule.detection_id, action, rule.content_hash))
            # Whatever PRAXIS manages in this space but no longer renders is removed.
            for rule_id in existing:
                call(conn.kibana, "DELETE", url, params={"rule_id": rule_id})
                actions.append(DeployAction(rule_id, "deleted"))
        return actions

    def smoke(
        self, rules: list[RenderedRule], client: Client, timeout: int = 240
    ) -> list[SmokeResult]:
        results: dict[str, SmokeResult] = {}
        deadline = time.monotonic() + timeout
        with ElasticConnection.from_env(
            client.platforms.elastic.connection, "deploy", client.id
        ) as conn:
            pending = {r.detection_id: r for r in rules}
            while pending:
                for rule_id, rendered in list(pending.items()):
                    result = self._smoke_one(conn, client, rendered)
                    if result is not None:
                        results[rule_id] = result
                        del pending[rule_id]
                if not pending:
                    break
                if time.monotonic() > deadline:
                    for rule_id in pending:
                        results[rule_id] = SmokeResult(
                            rule_id, False, "timeout", "no completed run since deploy"
                        )
                    break
                time.sleep(5)
        return [results[r.detection_id] for r in rules]

    def _smoke_one(
        self, conn: ElasticConnection, client: Client, rendered: RenderedRule
    ) -> SmokeResult | None:
        """None means 'not finished yet, ask again'."""
        rule_id = rendered.detection_id
        try:
            rule = call(conn.kibana, "GET", self._rules_url(client), params={"rule_id": rule_id})
        except ApiError as err:
            if err.status == 404:
                return SmokeResult(rule_id, False, "missing", "rule is not in the SIEM")
            raise
        if deployed_hash(rule) != rendered.content_hash[:16]:
            return SmokeResult(rule_id, False, "drift", "deployed hash differs from render")
        if not rule.get("enabled"):
            return SmokeResult(rule_id, False, "disabled", "rule is not enabled")
        last = (rule.get("execution_summary") or {}).get("last_execution")
        if (
            not last
            or last["date"] < rule["updated_at"]
            or last["status"]
            in (
                "running",
                "going to run",
            )
        ):
            return None
        return SmokeResult(
            rule_id, last["status"] == "succeeded", last["status"], last.get("message", "")
        )
