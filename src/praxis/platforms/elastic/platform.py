"""Elastic: EQL rules deployed through the Kibana Detection Engine API."""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import time
from datetime import UTC, datetime, timedelta
from typing import Any

from praxis.content.loader import DetectionBundle
from praxis.content.models import ELASTIC_INDEX_RE, Client
from praxis.content.tuning import ResolvedTuning
from praxis.platforms.base import (
    ConnectionCheck,
    DeployAction,
    Platform,
    RenderedRule,
    SmokeResult,
)
from praxis.platforms.elastic.connection import ApiError, ElasticConnection, call
from praxis.platforms.elastic.provision import provision
from praxis.platforms.elastic.render import (
    MANAGED_TAG,
    SHADOW_TAG,
    deployed_hash,
    exception_filter,
    exception_list_id,
    render_rule,
    resolve_indices,
)
from praxis.settings import get_settings
from praxis.visibility.inventory import RuleHealth, SourceInventory

LAB_NAMESPACE_PREFIX = "praxislab"
BACKTEST_LIMIT = 1000  # most matches a backtest counts; more than this is simply 'too noisy'
_HARD_CODED_INDEX = re.compile(r"\b_index\b|\bfrom\s+(logs|metrics|traces)-", re.IGNORECASE)
_SINGLE = {"namespace_type": "single"}
SEED_LABEL = {"term": {"labels.praxis_lab": "seed"}}


# Only these fields of an event are ever shown to an LLM, and the ones naming
# people or machines are replaced by stable pseudonyms.
_SAMPLE_FIELDS = (
    "event.category",
    "event.type",
    "process.name",
    "process.executable",
    "process.command_line",
    "process.pe.original_file_name",
    "process.parent.name",
    "process.parent.executable",
    "registry.path",
    "registry.data.strings",
    "file.path",
    "destination.port",
    "user.name",
    "host.name",
)
_PSEUDONYMISED = ("user.name", "host.name")


def pseudonym(value: object) -> str:
    return "id-" + hashlib.sha256(str(value).encode()).hexdigest()[:8]


def redact(event: dict) -> dict:
    """Keep the allow-listed fields of an event; pseudonymise users and hosts."""
    out: dict[str, Any] = {}
    for dotted in _SAMPLE_FIELDS:
        node: Any = event
        for part in dotted.split("."):
            node = node.get(part) if isinstance(node, dict) else None
        if node is None:
            continue
        value = pseudonym(node) if dotted in _PSEUDONYMISED else node
        target = out
        parts = dotted.split(".")
        for part in parts[:-1]:
            target = target.setdefault(part, {})
        target[parts[-1]] = value
    return out


def telemetry_pattern(namespace: str) -> str:
    """Every telemetry data stream of one namespace, and nothing else."""
    return ",".join(f"{kind}-*-{namespace}" for kind in ("logs", "metrics", "traces"))


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
    def render(
        self, bundle: DetectionBundle, client: Client, tuning: ResolvedTuning
    ) -> RenderedRule:
        return render_rule(bundle, client, tuning)

    # -- lab ---------------------------------------------------------------
    def lab_fires(
        self, bundle: DetectionBundle, events: list[dict], tuning: ResolvedTuning | None
    ) -> bool:
        # Each replay gets its own throwaway namespace, so replays never see
        # each other's events and clean-up is one data-stream delete.
        namespace = f"{LAB_NAMESPACE_PREFIX}{secrets.token_hex(5)}"
        indices = resolve_indices(bundle.meta.log_sources[self.name].indices, namespace)
        body: dict[str, Any] = {"query": bundle.implementations[self.name].query, "size": 1}
        exclusions = exception_filter(tuning) if tuning else None
        if exclusions:
            body["filter"] = exclusions
        with ElasticConnection.from_env(get_settings().lab_connection, "lab") as conn:
            try:
                _bulk_index(conn, indices[0], _stamp(events, datetime.now(UTC)))
                result = call(
                    conn.es,
                    "POST",
                    f"/{','.join(indices)}/_eql/search",
                    params={"ignore_unavailable": "true"},
                    json=body,
                )
                return result["hits"]["total"]["value"] > 0
            finally:
                call(conn.es, "DELETE", f"/_data_stream/*-*-{namespace}", ok=(404,))

    def replay(self, bundle: DetectionBundle, client: Client, events: list[dict]) -> int:
        target = client.platforms.elastic
        index = resolve_indices(bundle.meta.log_sources[self.name].indices, target.namespace)[0]
        with ElasticConnection.from_env(target.connection, "lab") as conn:
            _bulk_index(conn, index, _stamp(events, datetime.now(UTC)))
        return len(events)

    def write_telemetry(self, client: Client, source: str, events: list[dict]) -> int:
        target = client.platforms.elastic
        with ElasticConnection.from_env(target.connection, "lab") as conn:
            for start in range(0, len(events), 2000):
                _bulk_index(conn, f"{source}-{target.namespace}", events[start : start + 2000])
        return len(events)

    def last_seeded_event(self, client: Client, source: str) -> str | None:
        target = client.platforms.elastic
        with ElasticConnection.from_env(target.connection, "lab") as conn:
            result = call(
                conn.es,
                "POST",
                f"/{source}-{target.namespace}/_search",
                params={"ignore_unavailable": "true", "allow_no_indices": "true"},
                json={
                    "size": 0,
                    "query": SEED_LABEL,
                    "aggs": {"last": {"max": {"field": "@timestamp"}}},
                },
            )
        return (result.get("aggregations") or {}).get("last", {}).get("value_as_string")

    # -- collectors (read identity only) --------------------------------------
    def _read_conn(self, client: Client) -> ElasticConnection:
        return ElasticConnection.from_env(client.platforms.elastic.connection, "read", client.id)

    def collect_sources(
        self, client: Client, fields: dict[str, list[str]]
    ) -> list[SourceInventory]:
        namespace = client.platforms.elastic.namespace
        window = {"range": {"@timestamp": {"gte": "now-14d", "lte": "now"}}}
        search = {"ignore_unavailable": "true", "allow_no_indices": "true"}
        sources = []
        with self._read_conn(client) as conn:
            streams = call(
                conn.es, "GET", f"/_data_stream/{telemetry_pattern(namespace)}", ok=(404,)
            )
            for stream in sorted(s["name"] for s in (streams or {}).get("data_streams", [])):
                table = stream
                source = stream.removesuffix(f"-{namespace}")
                wanted = fields.get(source, [])
                aggs: dict[str, Any] = {
                    "days": {
                        "date_histogram": {
                            "field": "@timestamp",
                            "fixed_interval": "1d",
                            "min_doc_count": 1,
                        }
                    },
                    "hosts": {"cardinality": {"field": "host.name"}},
                    "last": {"max": {"field": "@timestamp"}},
                    "recent": {"filter": {"range": {"@timestamp": {"gte": "now-24h"}}}},
                }
                for i, name in enumerate(wanted):
                    aggs[f"f{i}"] = {"filter": {"exists": {"field": name}}}
                result = call(
                    conn.es,
                    "POST",
                    f"/{table}/_search",
                    params=search,
                    json={"size": 0, "track_total_hits": True, "query": window, "aggs": aggs},
                )
                total = result["hits"]["total"]["value"]
                found = result.get("aggregations") or {}
                if not total:
                    continue
                sources.append(
                    SourceInventory(
                        platform=self.name,
                        source=source,
                        table=table,
                        events_14d=total,
                        events_24h=found["recent"]["doc_count"],
                        days_with_data=min(len(found["days"]["buckets"]), 14),
                        hosts=found["hosts"]["value"],
                        last_event=found["last"].get("value_as_string"),
                        field_population={
                            name: round(found[f"f{i}"]["doc_count"] / total, 4)
                            for i, name in enumerate(wanted)
                        },
                    )
                )
        return sorted(sources, key=lambda s: s.source)

    def backtest(
        self,
        client: Client,
        query: str,
        sources: list[str],
        days: int = 30,
        tuning: ResolvedTuning | None = None,
    ) -> dict[str, Any]:
        indices = resolve_indices(sources, client.platforms.elastic.namespace)
        filters: list[dict[str, Any]] = [{"range": {"@timestamp": {"gte": f"now-{days}d"}}}]
        exclusions = exception_filter(tuning) if tuning else None
        if exclusions:
            filters.append(exclusions)
        with self._read_conn(client) as conn:
            result = call(
                conn.es,
                "POST",
                f"/{','.join(indices)}/_eql/search",
                params={"ignore_unavailable": "true"},
                # An EQL search counts only the matches it returns, so ask for
                # enough of them to count; `capped` says when there were more.
                json={
                    "query": query,
                    "size": BACKTEST_LIMIT,
                    "filter": {"bool": {"filter": filters}},
                },
            )
        hits = result["hits"]
        matches = hits.get("events") or hits.get("sequences") or []
        events = hits.get("events") or [e for s in hits.get("sequences", []) for e in s["events"]]
        return {
            "hits": len(matches),
            "capped": len(matches) >= BACKTEST_LIMIT,
            "days": days,
            "samples": [redact(e["_source"]) for e in events[:5]],
        }

    def alert_stats(self, client: Client, detection_id: str, days: int = 30) -> dict[str, Any]:
        space = client.platforms.elastic.space
        group_by = (
            "process.parent.executable",
            "process.executable",
            "process.name",
            "user.name",
            "host.name",
            "registry.path",
        )
        with self._read_conn(client) as conn:
            result = call(
                conn.es,
                "POST",
                f"/.alerts-security.alerts-{space}/_search",
                params={"ignore_unavailable": "true", "allow_no_indices": "true"},
                json={
                    "size": 5,
                    "track_total_hits": True,
                    "sort": [{"@timestamp": "desc"}],
                    "query": {
                        "bool": {
                            "filter": [
                                {"term": {"kibana.alert.rule.rule_id": detection_id}},
                                {"range": {"@timestamp": {"gte": f"now-{days}d"}}},
                            ]
                        }
                    },
                    "aggs": {
                        f.replace(".", "_"): {"terms": {"field": f, "size": 8}} for f in group_by
                    },
                },
            )
        aggregations = result.get("aggregations") or {}
        groups = {}
        for name in group_by:
            buckets = aggregations.get(name.replace(".", "_"), {}).get("buckets", [])
            if buckets:
                pseudonymise = name in ("user.name", "host.name")
                groups[name] = [
                    {
                        "value": pseudonym(b["key"]) if pseudonymise else b["key"],
                        "alerts": b["doc_count"],
                    }
                    for b in buckets
                ]
        return {
            "rule": detection_id,
            "days": days,
            "alerts": result["hits"]["total"]["value"],
            "top_values": groups,
            "alert_ids": [f"alert:{h['_id'][:12]}" for h in result["hits"]["hits"]],
            "samples": [
                {"alert_id": f"alert:{h['_id'][:12]}", **redact(h["_source"])}
                for h in result["hits"]["hits"]
            ],
        }

    def collect_rules(self, client: Client) -> list[RuleHealth]:
        space = client.platforms.elastic.space
        with self._read_conn(client) as conn:
            alerts = call(
                conn.es,
                "POST",
                f"/.alerts-security.alerts-{space}/_search",
                params={"ignore_unavailable": "true", "allow_no_indices": "true"},
                json={
                    "size": 0,
                    "query": {"range": {"@timestamp": {"gte": "now-30d"}}},
                    "aggs": {
                        "rules": {"terms": {"field": "kibana.alert.rule.rule_id", "size": 10000}}
                    },
                },
            )
            counts = {
                b["key"]: b["doc_count"]
                for b in (alerts.get("aggregations") or {}).get("rules", {}).get("buckets", [])
            }
            health = []
            for rule_id, rule in sorted(self._managed_rules(conn, client).items()):
                last = (rule.get("execution_summary") or {}).get("last_execution") or {}
                health.append(
                    RuleHealth(
                        detection_id=rule_id,
                        platform=self.name,
                        enabled=bool(rule.get("enabled")),
                        last_status=last.get("status"),
                        last_run=last.get("date"),
                        alerts_30d=counts.get(rule_id, 0),
                        deployed_hash=deployed_hash(rule),
                        tables=list(rule.get("index", [])),
                        shadow=SHADOW_TAG in rule.get("tags", []),
                    )
                )
        return health

    # -- onboarding and Connect mode ----------------------------------------
    def provision(self, client: Client, rotate: bool = False) -> list[str]:
        return provision(client, rotate)

    def check_connection(self, client: Client) -> list[ConnectionCheck]:
        target = client.platforms.elastic
        checks = []
        for role in ("read", "deploy"):
            try:
                with ElasticConnection.from_env(target.connection, role, client.id) as conn:
                    hits = call(
                        conn.es,
                        "POST",
                        f"/{telemetry_pattern(target.namespace)}/_search",
                        params={"ignore_unavailable": "true", "allow_no_indices": "true"},
                        json={"size": 0, "track_total_hits": True},
                    )["hits"]["total"]["value"]
                    rules = call(
                        conn.kibana,
                        "GET",
                        f"{self._rules_url(client)}/_find",
                        params={"per_page": 1},
                    )["total"]
                    detail = f"{hits} events in namespace {target.namespace}; {rules} rules"
                    if role == "read":
                        detail += self._must_not_write(conn, client)
                    checks.append(ConnectionCheck(role, True, detail))
            except Exception as err:  # report every failure, whatever its type
                checks.append(ConnectionCheck(role, False, str(err)[:300]))
        return checks

    def _must_not_write(self, conn: ElasticConnection, client: Client) -> str:
        """The read identity must be refused when it tries to create a rule."""
        probe = {"rule_id": "praxis-read-only-probe", "name": "probe", "description": "probe"}
        probe |= {"type": "query", "query": "*:*", "risk_score": 1, "severity": "low"}
        response = conn.kibana.post(self._rules_url(client), json={**probe, "enabled": False})
        if response.status_code == 403:
            return "; write correctly refused"
        if response.is_success:
            call(
                conn.kibana, "DELETE", self._rules_url(client), params={"rule_id": probe["rule_id"]}
            )
        raise RuntimeError(f"read identity was able to write (HTTP {response.status_code})")

    # -- deploy ------------------------------------------------------------
    @staticmethod
    def _space_url(client: Client) -> str:
        return f"/s/{client.platforms.elastic.space}/api"

    def _rules_url(self, client: Client) -> str:
        return f"{self._space_url(client)}/detection_engine/rules"

    def _deploy_conn(self, client: Client) -> ElasticConnection:
        return ElasticConnection.from_env(client.platforms.elastic.connection, "deploy", client.id)

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

    def _delete_exception_list(self, conn: ElasticConnection, client: Client, list_id: str) -> None:
        url = f"{self._space_url(client)}/exception_lists"
        call(conn.kibana, "DELETE", url, params={"list_id": list_id, **_SINGLE}, ok=(404,))

    def _sync_exception_list(
        self, conn: ElasticConnection, client: Client, rule: RenderedRule
    ) -> dict[str, Any]:
        """Replace the rule's exception list with the rendered one; returns the envelope."""
        list_id = exception_list_id(client.id, rule.detection_id)
        self._delete_exception_list(conn, client, list_id)
        if not rule.extras:
            return rule.envelope
        url = f"{self._space_url(client)}/exception_lists"
        created = call(conn.kibana, "POST", url, json=rule.extras["exception_list"])
        for item in rule.extras["exception_items"]:
            call(conn.kibana, "POST", f"{url}/items", json=item)
        reference = {**rule.envelope["exceptions_list"][0], "id": created["id"]}
        return {**rule.envelope, "exceptions_list": [reference]}

    def deploy(self, rules: list[RenderedRule], client: Client) -> list[DeployAction]:
        actions: list[DeployAction] = []
        with self._deploy_conn(client) as conn:
            existing = self._managed_rules(conn, client)
            url = self._rules_url(client)
            for rule in rules:
                current = existing.pop(rule.detection_id, None)
                unchanged = (
                    current is not None
                    and deployed_hash(current) == rule.content_hash[:16]
                    and current.get("enabled") == rule.envelope["enabled"]
                )
                if unchanged:
                    action = "unchanged"
                else:
                    envelope = self._sync_exception_list(conn, client, rule)
                    call(conn.kibana, "POST" if current is None else "PUT", url, json=envelope)
                    action = "created" if current is None else "updated"
                    if current is not None and current.get("enabled") and envelope["enabled"]:
                        # An update keeps the old schedule, so the next run could be a
                        # full interval away. Re-enabling runs the rule now, which lets
                        # the smoke check judge the new version straight away.
                        for enabled in (False, True):
                            patch = {"rule_id": rule.detection_id, "enabled": enabled}
                            call(conn.kibana, "PATCH", url, json=patch)
                actions.append(DeployAction(rule.detection_id, action, rule.content_hash))
            # Whatever PRAXIS manages in this space but no longer renders is removed.
            for rule_id in existing:
                call(conn.kibana, "DELETE", url, params={"rule_id": rule_id})
                self._delete_exception_list(conn, client, exception_list_id(client.id, rule_id))
                actions.append(DeployAction(rule_id, "deleted"))
        return actions

    def smoke(
        self, rules: list[RenderedRule], client: Client, timeout: int = 240
    ) -> list[SmokeResult]:
        results: dict[str, SmokeResult] = {}
        deadline = time.monotonic() + timeout
        with self._deploy_conn(client) as conn:
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
        if not rendered.envelope["enabled"]:
            ok = not rule.get("enabled")
            return SmokeResult(rule_id, ok, "disabled", "disabled by tuning, as rendered")
        if not rule.get("enabled"):
            return SmokeResult(rule_id, False, "disabled", "rule is not enabled")
        if rendered.extras:
            wanted = len(rendered.extras["exception_items"])
            found = call(
                conn.kibana,
                "GET",
                f"{self._space_url(client)}/exception_lists/items/_find",
                params={"list_id": exception_list_id(client.id, rule_id), **_SINGLE},
                ok=(404,),
            )
            if (found or {}).get("total") != wanted:
                return SmokeResult(rule_id, False, "drift", "exception list does not match")
        last = (rule.get("execution_summary") or {}).get("last_execution")
        if (
            not last
            or last["date"] < rule["updated_at"]
            or last["status"] in ("running", "going to run")
        ):
            return None
        return SmokeResult(
            rule_id, last["status"] == "succeeded", last["status"], last.get("message", "")
        )
