# Agents

PRAXIS agents propose; they never deploy. Each one is a system prompt, a task,
a short list of allowed tools and a schema for its answer. Their work lands on
an `ai/` branch as a pull request that CI tests and a person reviews.

| Agent | Command | What it produces | Tools it may use |
| --- | --- | --- | --- |
| Curator | `praxis pack plan <client> --month YYYY-MM` | A gap brief and ranked picks from the catalog | coverage, library, catalog search, scoring |
| Platform Engineer (Elastic) | part of `pack plan` | A native detection with README and tests per pick | catalog, library, scoring, backtest, write detection, run tests |
| Reviewer | part of `pack plan` | An independent verdict with comments | read-only: coverage, library, scoring, backtest, run tests |
| Tuner | `praxis tune <rule> --client <client>` | A tested tuning file | rule, alert statistics, backtest, propose override |
| Hunt Planner | `praxis hunt "<threat>" --sector <sector>` | Hypotheses, queries and read-only findings | coverage, ATT&CK groups, catalog, hunt queries |

## What code decides, whatever a model says

- **Pack rules.** Budget, at most two rules per sub-technique, no duplicate of
  a library detection, no indicator-tier rule, the technique must be a current
  detection gap for the client, and a low score needs a written justification.
- **Measurements.** Quality scores, backtests, lab results and hunt hit counts
  in every record are computed by code after the agent answers.
- **Tests decide.** A pick whose tests do not pass is dropped and its files
  removed. A tuning whose lab fails is not proposed. A Reviewer `blocker`
  fails the pack.
- **Scope.** A session is bound to its clients; a tool call for another client
  is refused. An agent can only overwrite detections it created in the same session.
- **No deploy path.** No tool loads a deploy key. CD after a human merge is the
  only way into a SIEM.

## What a model gets to see

A coverage snapshot, aggregated alert counts, and at most five sample events
per query, reduced to an allow-list of fields with users and hosts replaced by
pseudonyms. Never raw bulk logs. Upstream rule text reaches the model wrapped
and labelled as untrusted data. Set `external_llm: false` in a client's
`client.yml` and no agent will run for that client.

## Running them

Agents use Claude through the Anthropic SDK. Set `ANTHROPIC_API_KEY`; the
model defaults to `claude-opus-5-5` and can be changed with `PRAXIS_LLM_MODEL`
(effort with `PRAXIS_LLM_EFFORT`). Run them from a workstation against the
server:

```bash
deploy/with-server.sh uv run praxis pack plan acme --month 2026-12 --budget 3
```

Every model call, tool call and guardrail decision is stored in the audit log
and shown on the dashboard's Audit page.

## Any MCP client

`praxis mcp` serves the same tools over the Model Context Protocol. For Claude Code:

```json
{"mcpServers": {"praxis": {"command": "deploy/with-server.sh", "args": ["uv", "run", "praxis", "mcp"]}}}
```
