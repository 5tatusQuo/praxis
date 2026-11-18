# PRAXIS

Read PLAN.md first. It is the architecture plan.

## Folders
- `src/praxis/`: the platform code.
- `content/`: the detections the platform deploys. Clients in here are fictional.
- `deploy/`: Docker and server setup.
- `tests/`: tests for the platform code.

## Rules
- Code never hard-codes the `content/` path; read it from a setting so content can move to its own repo later.
- Never add real client names, hostnames or credentials anywhere in this repo.
