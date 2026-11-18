#!/usr/bin/env bash
# Independent audit of one client's coverage snapshot.
#
# Run on the deployment server: docs/audits/audit-client.sh <client> <expected-hosts>
#
# It asks Elasticsearch and Kibana the raw questions directly (curl + jq, as
# the admin user), applies the rules in docs/visibility-scoring.md by hand in
# jq, and prints the result next to the latest stored snapshot. It shares no
# code with the gap engine, so agreement means the engine did what the
# document says.
set -euo pipefail
CLIENT="${1:?client id}"; EXPECTED_HOSTS="${2:?expected hosts}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
# shellcheck disable=SC1091
. "$ROOT/deploy/server/env.sh" admin
ES=(curl -s --cacert /etc/praxis/ca.crt -u "elastic:$PRAXIS_ELASTIC_LAB_ADMIN_PASSWORD" -H 'Content-Type: application/json')
KB=(curl -s -u "elastic:$PRAXIS_ELASTIC_LAB_ADMIN_PASSWORD" -H 'kbn-xsrf: audit')
ATTACK="$ROOT/src/praxis/data/attack.json"
TOKEN="$(grep '^PRAXIS_API_TOKEN=' "$ROOT/deploy/.env" | cut -d= -f2)"
WINDOW='{"range":{"@timestamp":{"gte":"now-14d","lte":"now"}}}'

count() { "${ES[@]}" "https://localhost:9200/$1/_count" -d "{\"query\":$2}" | jq .count; }

echo "== 1. Raw telemetry facts for namespace $CLIENT =="
printf '%-40s %8s %7s %5s %5s\n' "data stream" "ev 14d" "ev 24h" "days" "hosts"
for stream in $("${ES[@]}" "https://localhost:9200/_data_stream/logs-*-$CLIENT" | jq -r '.data_streams[].name' | sort); do
  total=$(count "$stream" "$WINDOW")
  recent=$(count "$stream" '{"range":{"@timestamp":{"gte":"now-24h"}}}')
  aggs=$("${ES[@]}" "https://localhost:9200/$stream/_search" -d "{\"size\":0,\"query\":$WINDOW,\"aggs\":{\"d\":{\"date_histogram\":{\"field\":\"@timestamp\",\"fixed_interval\":\"1d\",\"min_doc_count\":1}},\"h\":{\"cardinality\":{\"field\":\"host.name\"}}}}")
  days=$(echo "$aggs" | jq '[.aggregations.d.buckets | length, 14] | min')
  hosts=$(echo "$aggs" | jq .aggregations.h.value)
  printf '%-40s %8s %7s %5s %5s\n' "$stream" "$total" "$recent" "$days" "$hosts"
  echo "$stream $total $recent $days $hosts" >> /tmp/audit-$CLIENT.streams.$$
done

population() { # stream field -> share of 14d events that have the field
  local total with
  total=$(count "$1" "$WINDOW")
  with=$(count "$1" "{\"bool\":{\"filter\":[$WINDOW,{\"exists\":{\"field\":\"$2\"}}]}}")
  jq -n --argjson w "$with" --argjson t "$total" '$w / $t'
}

echo
echo "== 2. Component scores by hand (presence, stability, host coverage, field population) =="
# component | data stream prefix | required fields: copied from the schema notes by hand.
COMPONENTS='Process Creation|logs-endpoint.events.process|process.name process.executable process.command_line process.parent.name user.name
Command Execution|logs-endpoint.events.process|process.command_line user.name
Network Connection Creation|logs-endpoint.events.network|destination.ip destination.port source.ip process.name
File Creation|logs-endpoint.events.file|file.path file.name process.name user.name
File Modification|logs-endpoint.events.file|file.path process.name
Windows Registry Key Modification|logs-endpoint.events.registry|registry.path registry.data.strings process.name
Logon Session Creation|logs-system.security|user.name source.ip event.outcome
User Account Authentication|logs-system.security|user.name event.outcome'
: > /tmp/audit-$CLIENT.scores.$$
while IFS='|' read -r component prefix fields; do
  line=$(grep "^$prefix-$CLIENT " /tmp/audit-$CLIENT.streams.$$ || true)
  [ -n "$line" ] || continue
  read -r stream total recent days hosts <<< "$line"
  sum=0; n=0
  for f in $fields; do sum=$(jq -n --argjson s "$sum" --argjson p "$(population "$stream" "$f")" '$s + $p'); n=$((n+1)); done
  score=$(jq -n --argjson recent "$recent" --argjson days "$days" --argjson hosts "$hosts" \
    --argjson expected "$EXPECTED_HOSTS" --argjson sum "$sum" --argjson n "$n" '
    if $recent == 0 then 0 else
      1 + (if $days >= 12 then 1 else 0 end)
        + (if ($hosts / $expected) >= 0.8 then 1 else 0 end)
        + (if ($sum / $n) >= 0.9 then 1 else 0 end) end')
  printf '%-36s score %s  (24h=%s days=%s hosts=%s/%s fields=%.3f)\n' "$component" "$score" "$recent" "$days" "$hosts" "$EXPECTED_HOSTS" "$(jq -n --argjson s "$sum" --argjson n "$n" '$s/$n')"
  jq -n --arg c "$component" --argjson s "$score" '{($c): $s}' >> /tmp/audit-$CLIENT.scores.$$
done <<< "$COMPONENTS"
SCORES=$(jq -s 'add' /tmp/audit-$CLIENT.scores.$$)

echo
echo "== 3. Rules in Kibana space $CLIENT, and their status by hand =="
LIVE=$(awk '$3 > 0 {print $1}' /tmp/audit-$CLIENT.streams.$$ | jq -R . | jq -s .)
RULES=$("${KB[@]}" "http://localhost:5601/s/$CLIENT/api/detection_engine/rules/_find?per_page=500" | jq --argjson live "$LIVE" '
  [.data[] | select(.tags | index("PRAXIS")) | {
     id: .rule_id, enabled, last: .execution_summary.last_execution.status,
     techniques: [.threat[].technique[] | (.subtechnique // [] | .[].id), (select((.subtechnique // []) | length == 0) | .id)],
     index,
     status: (if (.enabled | not) then "disabled"
              elif .execution_summary.last_execution.status != "succeeded" then "blind"
              elif ([.index[] | select(. as $i | $live | index($i))] | length) == 0 then "blind"
              else "healthy" end)}] | sort_by(.id)')
echo "$RULES" | jq -r '.[] | "\(.id)  enabled=\(.enabled) last=\(.last) -> \(.status)  \(.techniques | join(","))"'

echo
echo "== 4. Technique classes by hand, from ATT&CK $(jq -r .version "$ATTACK") =="
AUDIT=$(jq --argjson scores "$SCORES" --argjson rules "$RULES" '
  def parents: map(., split(".")[0]) | unique;
  ([$rules[] | select(.status == "healthy") | .techniques[]] | parents) as $healthy
  | ([$rules[] | select(.status == "blind") | .techniques[]] | parents) as $blind
  | [.techniques | to_entries[] | {
      id: .key,
      class: (if (.key | IN($healthy[])) then "covered"
              elif (.key | IN($blind[])) then "blind_rule"
              elif ([.value.data_components[] | $scores[.] // 0] | max // 0) >= 2 then "detection_gap"
              else "visibility_gap" end)}]' "$ATTACK")
echo "$AUDIT" | jq -c 'group_by(.class) | map({(.[0].class): length}) | add'
echo "covered:    $(echo "$AUDIT" | jq -c '[.[] | select(.class == "covered") | .id]')"
echo "blind rule: $(echo "$AUDIT" | jq -c '[.[] | select(.class == "blind_rule") | .id]')"

echo
echo "== 5. Compare with the latest stored snapshot =="
SNAP=$(curl -s -H "Authorization: Bearer $TOKEN" "http://localhost:8000/api/clients/$CLIENT/coverage")
echo "snapshot $(echo "$SNAP" | jq -r '"\(.id) taken \(.taken_at)"')"
echo "snapshot classes: $(echo "$SNAP" | jq -c '.summary | {blind_rule, covered, detection_gap, visibility_gap}')"
echo "snapshot components: $(echo "$SNAP" | jq -c '[.components[] | {(.name): .score}] | add')"
echo "audit components:    $(echo "$SCORES" | jq -c .)"
echo "snapshot rules: $(echo "$SNAP" | jq -c '[.rules[] | {(.id): .status}] | add')"
echo "audit rules:    $(echo "$RULES" | jq -c '[.[] | {(.id): .status}] | add')"
DIFF=$(jq -n --argjson a "$AUDIT" --argjson s "$(echo "$SNAP" | jq '[.techniques[] | {id, class}]')" '
  ($a | map({(.id): .class}) | add) as $am | [$s[] | select($am[.id] != .class) | {id, snapshot: .class, audit: $am[.id]}]')
COMPONENT_DIFF=$(jq -n --argjson a "$SCORES" --argjson s "$(echo "$SNAP" | jq '[.components[] | {(.name): .score}] | add')" '$a == $s')
echo "techniques that differ: $(echo "$DIFF" | jq length) of $(echo "$AUDIT" | jq length)"
echo "component scores identical: $COMPONENT_DIFF"
rm -f /tmp/audit-$CLIENT.*.$$
[ "$(echo "$DIFF" | jq length)" = 0 ] && [ "$COMPONENT_DIFF" = true ] && echo "AUDIT MATCHES SNAPSHOT" || { echo "AUDIT DOES NOT MATCH"; echo "$DIFF" | jq -c '.[:20]'; exit 1; }
