# How PRAXIS scores visibility and classifies gaps

Everything here is computed by code (`src/praxis/visibility/engine.py`) from
facts a read-only collector takes from the client's SIEM. The same inputs
always give the same snapshot. No AI is involved.

## Inputs

For each client the collector records, over the last 14 days:

- **Log sources**: every telemetry table (Elastic: data stream) with its event
  count, events in the last 24 hours, number of days that have data, distinct
  hosts reporting, newest event, and how often each required field is filled.
- **Rules**: every PRAXIS-managed rule with whether it is enabled, the result
  of its latest run, and its alerts in the last 30 days.

The **data map** (`content/datamap-catalog/<siem>/<source>.md`) says which
ATT&CK data components each log source can show and which fields an analyst
needs for each. A table with no schema note counts for nothing until someone
writes one; the snapshot lists such tables.

## Visibility score per data component: 0 to 4

One point for each factor that holds, taken from the component's best source:

| Factor | Holds when |
| --- | --- |
| Presence | The source received events in the last 24 hours |
| Stability | It has data on at least 12 of the last 14 days |
| Host coverage | At least 80% of the client's expected hosts report to it |
| Field population | The component's required fields are filled in 90% of events, on average |

A source with no events in the last 24 hours is **silent** and scores 0,
whatever its history: nothing can be detected on it right now.

Expected hosts come from `assets.endpoints` in `client.yml`, or, when that is
not set, from the largest host count seen in any source.

## Rule status

| Status | Meaning |
| --- | --- |
| healthy | Enabled, latest run succeeded, and at least one of its log sources received events in the last 24 hours |
| blind | Enabled, but its latest run did not succeed, it never ran, or all its log sources are silent or missing |
| disabled | Turned off (for example by tuning). Gives no coverage |

## Technique classes

A technique's visibility is the highest score among its ATT&CK data
components. It is **visible** from a score of 2. A rule mapped to a
sub-technique also counts for the parent technique.

| Class | Rule |
| --- | --- |
| Covered | A healthy rule maps to it |
| Blind rule | No healthy rule, but a blind one maps to it |
| Detection gap | No rule, and it is visible |
| Visibility gap | No rule, and it is not visible |

Classes are checked in that order, so every technique has exactly one.

## Threat weight

`content/threat-profiles/<sector>.yml` lists the ATT&CK groups known to target
a sector. A technique's weight is the share of those groups reported to use it
(a sub-technique also counts for its parent), plus any explicit boost in the
profile, capped at 1. Gaps are ranked by weight, and **threat-weighted
coverage** is the weight of covered techniques over the weight of all
techniques.

## Limits worth knowing

- "Visible" means some relevant telemetry is flowing, not that every variant
  of the technique can be seen. Process creation alone makes many techniques
  visible; the score says how good that telemetry is, not how complete.
- Coverage is binary per technique. One healthy rule marks a technique
  covered, however narrow the rule is. Rule quality scoring comes with the
  AI curation phase.
- The thresholds (12 days, 80%, 90%, visible from 2) are defaults recorded in
  every snapshot under `thresholds`.
