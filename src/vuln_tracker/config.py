"""Settings from the environment and the optional YAML config file."""

import os
import re
from dataclasses import dataclass
from datetime import timedelta

import yaml


@dataclass(frozen=True)
class Ownership:
    """Workload rules from CONFIG_FILE. Patterns are fnmatch over
    namespace/kind/name, and the first matching owner wins."""

    owners: tuple[tuple[str, str], ...] = ()
    managed: frozenset[str] = frozenset()
    ignore: tuple[str, ...] = ()

    @classmethod
    def load(cls, path: str) -> "Ownership":
        if not path:
            return cls()
        with open(path) as f:
            doc = yaml.safe_load(f) or {}
        return cls(
            owners=tuple((o["match"], o["app"]) for o in doc.get("owners") or []),
            managed=frozenset(doc.get("managed") or []),
            ignore=tuple(doc.get("ignore") or []),
        )


def _pairs(value: str) -> dict[str, str]:
    """"mgmt=http://a,qa=http://b" → {"mgmt": "http://a", "qa": "http://b"}."""
    return dict(item.split("=", 1) for item in value.split(",") if item)


@dataclass(frozen=True)
class Settings:
    database_url: str
    bucket: str

    # Cluster → VictoriaMetrics query URL holding its kube-state-metrics.
    clusters: dict[str, str]

    gitlab_url: str
    gitlab_token: str
    helm_project: str

    argocd_url: str
    argocd_token: str

    # Regex with an `env` group that names the cluster from an ArgoCD
    # destination, and the name of ArgoCD's own cluster.
    argocd_cluster_pattern: re.Pattern | None
    argocd_in_cluster: str

    ownership: Ownership

    slack_token: str
    slack_channel: str
    grafana_url: str

    critical_sla: timedelta
    trivy_db_repository: str
    trivy_cache_dir: str

    # A trailing newline from a secret store breaks the HTTP header and leaks
    # the token into the error message, so tokens are stripped.
    @classmethod
    def from_env(cls) -> "Settings":
        env = os.environ
        return cls(
            database_url=env["DATABASE_URL"],
            bucket=env.get("REPORTS_BUCKET", ""),
            clusters=_pairs(env.get("CLUSTERS", "")),
            gitlab_url=env.get("GITLAB_URL", "https://gitlab.com"),
            gitlab_token=env.get("GITLAB_TOKEN", "").strip(),
            helm_project=env.get("HELM_PROJECT", ""),
            argocd_url=env.get("ARGOCD_URL", ""),
            argocd_token=env.get("ARGOCD_TOKEN", "").strip(),
            argocd_cluster_pattern=re.compile(p) if (p := env.get("ARGOCD_CLUSTER_PATTERN")) else None,
            argocd_in_cluster=env.get("ARGOCD_IN_CLUSTER", "in-cluster"),
            ownership=Ownership.load(env.get("CONFIG_FILE", "")),
            slack_token=env.get("SLACK_TOKEN", "").strip(),
            slack_channel=env.get("SLACK_CHANNEL", ""),
            grafana_url=env.get("GRAFANA_URL", ""),
            critical_sla=timedelta(days=int(env.get("CRITICAL_SLA_DAYS", "7"))),
            trivy_db_repository=env.get("TRIVY_DB_REPOSITORY",
                                        "public.ecr.aws/aquasecurity/trivy-db"),
            trivy_cache_dir=env.get("TRIVY_CACHE_DIR", "/tmp/trivy"),
        )
