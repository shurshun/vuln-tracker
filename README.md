# vuln-tracker

Turns trivy-operator reports into one status per open vulnerability and tells
which Renovate MR, if any, fixes it.

trivy-operator (fork with S3 report storage) writes
`<cluster>/vulnerability_reports/<namespace>/<Kind>-<name>-<container>.json`
and a matching `sbom_reports/` object. vuln-tracker keeps its state in Postgres.

## Steps

| Command | Schedule | Does |
|---|---|---|
| `vuln-tracker run` | hourly | `ingest` new and rewritten reports from S3, then `evaluate` |
| `vuln-tracker rescan` | daily | stored SBOMs of live images against a fresh trivy DB |
| `vuln-tracker digest` | daily | Slack digest of open CRITICAL and HIGH findings |
| `vuln-tracker serve` | always | `/metrics` from Postgres for vmagent |

`evaluate` resolves running containers from kube-state-metrics
(`kube_pod_container_info`, `kube_pod_owner`, `kube_replicaset_owner`,
`kube_job_owner`) to the controller trivy-operator scanned, so a report of a
gone ReplicaSet never counts.

## Statuses

| Status | Meaning |
|---|---|
| `accepted` | matched by an entry in `security/exceptions.yaml` of `HELM_PROJECT`, not expired |
| `fix-ready` | an open Renovate MR's `security:diff` artifact lists the CVE as fixed |
| `upstream-pending` | open MR has a verdict, the CVE stays |
| `mr-unverified` | open MR without a verdict yet |
| `no-fix` | Renovate tracks the app, no MR is open: no newer version |
| `renovate-gap` | Renovate detects no dependency of the app |
| `unowned` | workload is not part of an ArgoCD application |
| `overdue` | CRITICAL open longer than `CRITICAL_SLA_DAYS` and not accepted |

Apps map to MRs by branch: Renovate names them `renovate/<app>/...`.

## Settings

| Variable | Example |
|---|---|
| `DATABASE_URL` | `postgresql://user:pass@host:5432/vuln_tracker` |
| `REPORTS_BUCKET` | `example-trivy-reports` |
| `CLUSTERS` | `mgmt=http://vmsingle-vm-stack.observability.svc:8428` |
| `GITLAB_URL`, `GITLAB_TOKEN`, `HELM_PROJECT` | `https://gitlab.example.com`, read_api token, `infra/helm` |
| `ARGOCD_URL`, `ARGOCD_TOKEN` | read-only account `vuln-tracker` |
| `ARGOCD_CLUSTER_PATTERN` | `example-(?P<env>[a-z0-9]+)-eks`: the `env` group names the cluster; unset uses the destination name |
| `ARGOCD_IN_CLUSTER` | `mgmt`: name of ArgoCD's own cluster, default `in-cluster` |
| `SLACK_TOKEN`, `SLACK_CHANNEL` | bot token, `#security` |
| `GRAFANA_URL` | dashboard link for the digest |
| `CRITICAL_SLA_DAYS` | `7` |

GitLab, ArgoCD and Slack are optional: without them statuses stop at `unowned`
or `renovate-gap` and the digest is not sent.

## Development

```bash
uv run pytest
uvx ruff check .
```

The database test runs when `TEST_DATABASE_URL` is set:

```bash
docker run -d --name vt-pg -p 55432:5432 -e POSTGRES_PASSWORD=test postgres:17-alpine
TEST_DATABASE_URL=postgresql://postgres:test@localhost:55432/postgres uv run pytest
```
