"""Which ArgoCD application owns a workload."""

import re

import httpx

Index = dict[tuple[str, str, str, str], str]


def cluster_of(destination: dict, pattern: re.Pattern | None, in_cluster: str) -> str | None:
    """Cluster name of an ArgoCD destination. The pattern's `env` group picks
    it out of the destination name; without a pattern the name is used as is."""

    name = destination.get("name") or destination.get("server", "")
    if name in ("in-cluster", "https://kubernetes.default.svc"):
        return in_cluster
    if pattern is None:
        return name or None
    m = pattern.search(name)
    return m.group("env") if m else None


def build_index(apps: list[dict], pattern: re.Pattern | None = None,
                in_cluster: str = "in-cluster") -> Index:
    """(cluster, namespace, kind, name) → app, with the -<cluster> suffix of the
    ApplicationSet name dropped: grafana-mgmt becomes grafana."""

    index: Index = {}
    for app in apps:
        cluster = cluster_of(app["spec"].get("destination", {}), pattern, in_cluster)
        if cluster is None:
            continue
        name = app["metadata"]["name"].removesuffix(f"-{cluster}")
        for res in app.get("status", {}).get("resources") or []:
            index[(cluster, res.get("namespace", ""), res["kind"], res["name"])] = name
    return index


def fetch_index(url: str, token: str, pattern: re.Pattern | None, in_cluster: str) -> Index:
    r = httpx.get(f"{url.rstrip('/')}/api/v1/applications",
                  headers={"Authorization": f"Bearer {token}"}, timeout=30)
    r.raise_for_status()
    return build_index(r.json().get("items") or [], pattern, in_cluster)
