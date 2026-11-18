# Deploying PRAXIS

PRAXIS has two modes. Both run the same core (API, dashboard, Postgres).
**Full** adds Elasticsearch and Kibana next to it; **Connect** uses a SIEM you
already run.

## One server with Docker Compose

This is the reference deployment and the only one proven end to end.

1. A Linux server with Docker and the Compose plugin, 8 GB of memory for Full mode.
2. Copy the repo to the server and run `deploy/server/bootstrap.sh full`
   (or `connect`). It generates `deploy/.env` with random passwords on first
   run and starts the stack. Every port listens on localhost only.
3. Onboard a client: `. deploy/server/env.sh admin`, then
   `praxis admin provision <client> --env-out /opt/praxis/keys.env`. This
   creates the client's Kibana space and three scoped API keys: lab, read and deploy.
4. `deploy/server/install-runner.sh <owner/repo>` installs a GitHub Actions
   runner as a service. `deploy/server/publish-keys.sh` gives it the keys:
   deploy keys for CD, read keys for collectors, and lab and read keys (never
   deploy keys) for the API.
5. Open the dashboard with `deploy/dashboard.sh` from your workstation. It prints the
   sign-in details. Sign-in is Keycloak, served under the dashboard's own address at `/kc`.

From a workstation, `deploy/remote.sh up full` does steps 1 and 2 over SSH for
the server named in `.env`, and `deploy/with-server.sh <command>` runs a
`praxis` command against the server's stack through tunnels.

## Kubernetes with Helm (Connect mode)

`deploy/helm/praxis` deploys the API, the dashboard and, for evaluation, an
in-cluster Postgres. The chart lints and renders in CI. **It has not been
installed on a real cluster yet.**

```bash
helm install praxis deploy/helm/praxis \
  --set secrets.create=true --set secrets.apiToken="$(openssl rand -hex 24)" \
  --set postgres.password="$(openssl rand -hex 16)"
```

For production, turn `postgres.enabled` off, point `secrets.databaseUrl` at a
managed database, supply the secret yourself, and mount your content repo
through `api.contentClaim`. Give the API read and lab keys through
`api.connectionSecret`; deploy keys belong to your CD runner only.

## AWS with Terraform (Connect mode)

`deploy/terraform/aws` creates RDS Postgres, a Secrets Manager secret, an S3
bucket for artifacts, and the API and dashboard on ECS Fargate behind an HTTPS
load balancer, inside a VPC you already have. It passes `terraform validate`
in CI. **It has not been applied to a real AWS account yet**, so treat it as
a starting point and review the plan before applying.

```bash
cd deploy/terraform/aws
terraform init
terraform plan -var vpc_id=vpc-... -var 'private_subnet_ids=[...]' \
  -var 'public_subnet_ids=[...]' -var 'allowed_cidrs=["203.0.113.0/24"]' \
  -var certificate_arn=arn:aws:acm:... -var image_tag=v1.0.0
```

Images come from GitHub Container Registry and are published by the
`praxis-release` workflow when a version tag is pushed.

## What runs where

| Piece | Where | Holds |
| --- | --- | --- |
| API, dashboard, Postgres | Compose, Kubernetes or ECS | Read and lab keys, snapshots, catalog, audit log |
| CI validation | GitHub-hosted runners | Nothing secret |
| Lab staging, CD, nightly | Your self-hosted runner | Deploy, read and lab keys, in files on that machine |
| Agents | An operator's workstation, through tunnels | The LLM key; read and lab keys in memory only |
