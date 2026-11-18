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

## How agents write

Agent text follows the writing rules of ASD-STE100 Simplified Technical
English, and a template with hard limits. Code rejects an answer that breaks a
limit, and the agent must send it again.

- **Sentences:** at most 25 words to describe and 20 words for an instruction,
  one instruction per sentence. Active voice, simple tenses, the same word for
  the same thing, noun clusters of three words at most.
- **No repeats:** an agent does not restate what the page already shows next
  to its text (scores, weights, hit counts, test counts, names).
- **Templates:**

| Text | Limit |
| --- | --- |
| Pack brief | A headline of 25 words, up to 3 things added and 3 gaps left open, 12 words each |
| Pick | Why: 25 words. Caveat: 20 words, or empty |
| Engineer | What changed from the upstream draft: 25 words |
| Reviewer | Summary: 30 words. Up to 6 comments, each an issue (25 words) and an action (15 words) |
| Tuner | Findings: 40 words. Scope advice: 20 words |
| Hunt | Summary: 40 words. Per hypothesis: rationale 25 words, assessment 30 words |
| Detection README | Summary 50 words, how it works 110, blind spots 90, triage 110 |

The sentence and word limits are checked by code. Voice, tense and word choice
are instructions to the model and are not checked. PRAXIS does not apply the
STE dictionary of approved words, so this is not certified STE.

## What a model gets to see

A coverage snapshot, aggregated alert counts, and at most five sample events
per query, reduced to an allow-list of fields with users and hosts replaced by
pseudonyms. Never raw bulk logs. Upstream rule text reaches the model wrapped
and labelled as untrusted data. Set `external_llm: false` in a client's
`client.yml` and no agent will run for that client.

## Running them

**Sign in with ChatGPT.** Open the dashboard with `deploy/dashboard.sh`, go to
Settings and press "Sign in with ChatGPT". Your ChatGPT plan then pays for the
agents' model calls, and you can pick the model on the same page. Use the
`http://127.0.0.1:3000` address the script opens: the sign-in can only return
to 127.0.0.1. PRAXIS gets no access to your ChatGPT conversations, the tokens
stay on the server, and "Sign out of ChatGPT" revokes them. Usage shows up at
https://chatgpt.com/settings/usage.

Then run agents from a workstation against the server:

```bash
deploy/with-server.sh uv run praxis pack plan acme --month 2026-12 --budget 3
```

**Or Claude.** Without a ChatGPT sign-in, agents use Claude through the
Anthropic SDK: log in with `ant auth login` or set `ANTHROPIC_API_KEY`
(model `claude-opus-5-5`, change with `PRAXIS_LLM_MODEL`). Set
`PRAXIS_LLM_PROVIDER=openai` or `anthropic` to force one.

Every model call, tool call and guardrail decision is stored in the audit log
and shown on the dashboard's Audit page.

## Any MCP client, and your own AI assistant

`./px mcp` serves PRAXIS's tools over the Model Context Protocol. Claude Code
picks it up from `.mcp.json` at the repo root. Besides the tools PRAXIS's own
agents use, it offers operator tools: `status`, `client_add`,
`client_subscribe`, `sector_add` and `detection_lifecycle`. PRAXIS's agents are
not given those: only a person's own assistant can create a client or promote
a rule.

An assistant can also drive PRAXIS through the command line: `CLAUDE.md` tells
it how, and `docs/runbook.md` has a command for every step.
