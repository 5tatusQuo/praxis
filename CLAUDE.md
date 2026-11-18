# PRAXIS

PRAXIS is a detection engineering platform: one detection library in Git,
rendered per client, tested in a lab SIEM and deployed by CI/CD.

## Operating PRAXIS for someone

If you are asked to do something with a client, a rule, a pack, a hunt or the
SIEM, you are operating PRAXIS. Do this:

1. Run `./px status` first. It shows the clients, detections, working tree,
   coverage and whether a model sign-in exists.
2. Read `docs/runbook.md`. It has one command for every step of a client's
   life, in order, with a worked example.
3. Use `./px <command>` for everything. `./px --help` lists the commands,
   `./px <group> --help` lists a group, `./px <group> <command> --help` shows
   one command's options, and `--json` returns data.

Rules while operating:

- Client names are invented. Never write a real client or company name as a
  client, or a hostname or credential, anywhere in this repo. It is public.
  Detection logic may name the software it looks at (a product's path).
- Ship every change with `./px change submit "<what it does>"`, then
  `./px change merge <number>`. Merging deploys to the SIEM. `./px change show`
  reads a pull request, `./px change close` closes one, and `./px change home`
  returns to `main`.
- Ask the person before you merge a pull request an agent opened (its branch
  starts with `ai/`), before `./px client offboard`, and before anything else
  that deletes data or cannot be undone.
- When a command fails, read its message: it says what is wrong and what to
  do. Do not work around PRAXIS by editing files under `content/` by hand,
  calling the SIEM directly, or running `git` and `gh` yourself for things
  `./px change` does. If PRAXIS cannot do something, say so; that is a gap
  the person wants to know about.
- Show evidence. After a step, show the command's own output for it.

Reading and authoring actions are also tools from the `praxis` MCP server
(`.mcp.json`), for example `status`, `client_add`, `get_coverage`,
`search_catalog`, `write_detection` and `run_tests`. The MCP tools cannot
ship or deploy: pull requests, the agents (`pack plan`, `tune`, `hunt`),
provisioning and offboarding are `./px` commands only.

## Developing PRAXIS

Read PLAN.md (the architecture) and PROGRESS.md (what is built, the evidence,
what is open) first.

- `src/praxis/`: the platform code. `content/`: the detections it deploys;
  clients in here are fictional. `deploy/`: Docker and server setup.
  `web/`: the dashboard. `tests/`: tests for the platform code.
- Code never hard-codes the `content/` path; read it from a setting so content
  can move to its own repo later.
- Never add real client names, hostnames or credentials anywhere in this repo.
- Before a pull request: `uv run ruff check . && uv run ruff format . && uv run pytest -q`.
- `main` is protected. Every change is a pull request with CI green.
