"""VulnerabilityReport documents written by trivy-operator to S3."""

from dataclasses import dataclass
from datetime import datetime

SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}

LABEL_CONTAINER = "trivy-operator.container.name"
LABEL_SPEC_HASH = "resource-spec-hash"


@dataclass(frozen=True)
class Finding:
    vuln_id: str
    pkg: str
    installed: str
    fixed: str
    severity: str
    title: str
    link: str
    score: float | None


@dataclass(frozen=True)
class Report:
    key: str
    cluster: str
    namespace: str
    kind: str
    name: str
    container: str
    image: str
    digest: str
    spec_hash: str
    scanned_at: datetime
    findings: tuple[Finding, ...]


def report_key(cluster: str, namespace: str, kind: str, name: str, container: str,
               kind_dir: str = "vulnerability_reports") -> str:
    """Object key the fork writes: <prefix>/<dir>/<namespace>/<Kind>-<name>-<container>.json."""
    return f"{cluster}/{kind_dir}/{namespace}/{kind}-{name}-{container}.json"


def image_ref(registry: str, repository: str, tag: str, digest: str) -> str:
    ref = f"{registry}/{repository}" if registry else repository
    if tag:
        return f"{ref}:{tag}"
    if digest:
        return f"{ref}@{digest}"
    return ref


def dedupe(findings: list[Finding]) -> tuple[Finding, ...]:
    """One finding per (vuln, package, installed version); a package seen in
    several targets of the image keeps its highest severity."""

    best: dict[tuple[str, str, str], Finding] = {}
    for f in findings:
        key = (f.vuln_id, f.pkg, f.installed)
        kept = best.get(key)
        if kept is None or SEVERITY_RANK.get(f.severity, 0) > SEVERITY_RANK.get(kept.severity, 0):
            best[key] = f
    return tuple(best.values())


def split_key(key: str, container: str) -> tuple[str, str, str, str]:
    """Cluster, namespace, kind and name from an object key.

    The name comes from the key, because trivy-operator replaces the name
    label with a hash when the workload name is longer than a label allows.
    """

    cluster, _, namespace, filename = key.split("/", 3)
    stem = filename.removesuffix(".json").removesuffix(f"-{container}")
    kind, _, name = stem.partition("-")
    return cluster, namespace, kind, name


def parse_report(key: str, doc: dict) -> Report:
    labels = doc["metadata"].get("labels", {})
    data = doc["report"]
    container = labels[LABEL_CONTAINER]
    cluster, namespace, kind, name = split_key(key, container)
    artifact = data.get("artifact", {})
    registry = data.get("registry", {}).get("server", "")

    findings = [
        Finding(
            vuln_id=v["vulnerabilityID"],
            pkg=v.get("resource", ""),
            installed=v.get("installedVersion", ""),
            fixed=v.get("fixedVersion", ""),
            severity=v.get("severity", "UNKNOWN"),
            title=v.get("title", ""),
            link=v.get("primaryLink", ""),
            score=v.get("score"),
        )
        for v in data.get("vulnerabilities") or []
    ]

    return Report(
        key=key,
        cluster=cluster,
        namespace=namespace,
        kind=kind,
        name=name,
        container=container,
        image=image_ref(registry, artifact.get("repository", ""), artifact.get("tag", ""),
                        artifact.get("digest", "")),
        digest=artifact.get("digest", ""),
        spec_hash=labels.get(LABEL_SPEC_HASH, ""),
        scanned_at=datetime.fromisoformat(data["updateTimestamp"].replace("Z", "+00:00")),
        findings=dedupe(findings),
    )
