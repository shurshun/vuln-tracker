import re
from datetime import UTC, date, datetime, timedelta

from vuln_tracker import argocd, config, digest, evaluate, gitlab, inventory, reports, rescan
from vuln_tracker.config import Settings
from vuln_tracker.status import (
    ACCEPTED,
    FIX_READY,
    MANAGED,
    MR_UNVERIFIED,
    NO_FIX,
    OVERDUE,
    RENOVATE_GAP,
    UNOWNED,
    UPSTREAM_PENDING,
    MergeRequest,
    RiskException,
    decide,
)

NOW = datetime(2026, 9, 30, 12, tzinfo=UTC)
KEY = "mgmt/vulnerability_reports/observability/ReplicaSet-grafana-7d9f8-grafana.json"


def report_doc(name_label="grafana-7d9f8"):
    vuln = {"vulnerabilityID": "CVE-2026-1", "resource": "openssl", "installedVersion": "3.0.1",
            "fixedVersion": "3.0.2", "severity": "HIGH", "title": "t", "primaryLink": "l"}
    return {
        "metadata": {"labels": {
            "trivy-operator.resource.kind": "ReplicaSet",
            "trivy-operator.resource.name": name_label,
            "trivy-operator.container.name": "grafana",
            "resource-spec-hash": "abc",
        }},
        "report": {
            "updateTimestamp": "2026-09-30T10:00:00Z",
            "registry": {"server": "docker.io"},
            "artifact": {"repository": "grafana/grafana", "tag": "12.1.0", "digest": "sha256:1"},
            # The same package in two targets of the image must count once, at its highest severity.
            "vulnerabilities": [vuln, {**vuln, "severity": "CRITICAL"}],
        },
    }


def test_parse_report_takes_identity_from_key():
    r = reports.parse_report(KEY, report_doc(name_label="hash-instead-of-name"))
    assert (r.cluster, r.namespace, r.kind, r.name, r.container) == \
        ("mgmt", "observability", "ReplicaSet", "grafana-7d9f8", "grafana")
    assert r.image == "docker.io/grafana/grafana:12.1.0"
    assert [(f.vuln_id, f.severity) for f in r.findings] == [("CVE-2026-1", "CRITICAL")]


def test_resolve_maps_pods_to_scanned_controllers():
    containers = [
        {"namespace": "observability", "pod": "grafana-7d9f8-a", "container": "grafana", "image": "g"},
        {"namespace": "observability", "pod": "grafana-7d9f8-b", "container": "grafana", "image": "g"},
        {"namespace": "ops", "pod": "backup-29000-x", "container": "backup", "image": "b"},
        {"namespace": "ops", "pod": "debug", "container": "sh", "image": "d"},
    ]
    pod_owners = inventory.owner_map([
        {"namespace": "observability", "pod": "grafana-7d9f8-a", "owner_kind": "ReplicaSet",
         "owner_name": "grafana-7d9f8", "owner_is_controller": "true"},
        {"namespace": "observability", "pod": "grafana-7d9f8-b", "owner_kind": "ReplicaSet",
         "owner_name": "grafana-7d9f8", "owner_is_controller": "true"},
        {"namespace": "ops", "pod": "backup-29000-x", "owner_kind": "Job",
         "owner_name": "backup-29000", "owner_is_controller": "true"},
        {"namespace": "ops", "pod": "debug", "owner_kind": "<none>", "owner_name": "<none>"},
    ], "pod")
    rs = inventory.owner_map([{"namespace": "observability", "replicaset": "grafana-7d9f8",
                               "owner_kind": "Deployment", "owner_name": "grafana",
                               "owner_is_controller": "true"}], "replicaset")
    jobs = inventory.owner_map([{"namespace": "ops", "job_name": "backup-29000",
                                 "owner_kind": "CronJob", "owner_name": "backup",
                                 "owner_is_controller": "true"}], "job_name")

    live = {c.report_key: (c.workload_kind, c.workload_name)
            for c in inventory.resolve("mgmt", containers, pod_owners, rs, jobs)}

    assert live == {
        KEY: ("Deployment", "grafana"),
        "mgmt/vulnerability_reports/ops/CronJob-backup-backup.json": ("CronJob", "backup"),
        "mgmt/vulnerability_reports/ops/Pod-debug-sh.json": ("Pod", "debug"),
    }


MR = MergeRequest(1, "u", "renovate/grafana/grafana-13.x", "t")


def status(**kw):
    args = dict(cluster="mgmt", app="grafana", vuln_id="CVE-1", pkg="openssl", severity="HIGH",
                first_seen=NOW, now=NOW, exceptions=[], mrs=[], fixed_by={}, diffed=set(),
                tracked_apps=set(), sla=timedelta(days=7))
    return decide(**{**args, **kw}).status


def test_decide_statuses():
    assert status(app=None) == UNOWNED
    assert status() == RENOVATE_GAP
    assert status(tracked_apps={"grafana"}) == NO_FIX
    assert status(mrs=[MR]) == MR_UNVERIFIED
    assert status(mrs=[MR], diffed={MR.branch}) == UPSTREAM_PENDING
    assert status(mrs=[MR], diffed={MR.branch}, fixed_by={MR.branch: {"CVE-1"}}) == FIX_READY


def test_decide_overdue_and_accepted():
    old = NOW - timedelta(days=8)
    assert status(severity="CRITICAL", first_seen=old) == OVERDUE
    assert status(severity="HIGH", first_seen=old) == RENOVATE_GAP

    exc = RiskException(expires=date(2026, 12, 31), reason="r", app="grafana", vuln_id="CVE-1")
    assert status(severity="CRITICAL", first_seen=old, exceptions=[exc]) == ACCEPTED
    expired = RiskException(expires=date(2026, 9, 1), reason="r", package="openssl")
    assert status(exceptions=[expired]) == RENOVATE_GAP


def test_exceptions_file_and_dashboard():
    parsed = gitlab.parse_exceptions("""
- app: grafana
  id: CVE-1
  expires: 2026-12-31
  reason: not reachable
""")
    assert parsed == [RiskException(expires=date(2026, 12, 31), reason="not reachable",
                                    app="grafana", vuln_id="CVE-1")]
    body = "<summary>apps/alloy/helmfile.yaml.gotmpl</summary>\n - `apps/grafana/.helm/values.yaml.gotmpl`"
    assert gitlab.apps_in_dashboard(body) == {"alloy", "grafana"}
    assert gitlab.app_of_branch("renovate/grafana-mcp-setup/x-0.x") == "grafana-mcp-setup"
    assert gitlab.app_of_branch("renovate/configure") is None


def test_argocd_index_strips_env_suffix():
    index = argocd.build_index([{
        "metadata": {"name": "grafana-mgmt"},
        "spec": {"destination": {"name": "in-cluster"}},
        "status": {"resources": [{"kind": "Deployment", "namespace": "observability", "name": "grafana"}]},
    }, {
        "metadata": {"name": "loki-qa"},
        "spec": {"destination": {"name": "acme-qa-eks"}},
        "status": {"resources": [{"kind": "StatefulSet", "namespace": "observability", "name": "loki"}]},
    }], re.compile(r"acme-(?P<env>[a-z0-9]+)-eks"), "mgmt")
    assert index == {("mgmt", "observability", "Deployment", "grafana"): "grafana",
                     ("qa", "observability", "StatefulSet", "loki"): "loki"}


def test_parse_trivy_sbom_output():
    out = {"Results": [{"Vulnerabilities": [{
        "VulnerabilityID": "CVE-2", "PkgName": "zlib", "InstalledVersion": "1", "FixedVersion": "2",
        "Severity": "CRITICAL", "CVSS": {"nvd": {"V3Score": 9.8}}}]}]}
    [f] = rescan.parse_trivy(out)
    assert (f.vuln_id, f.pkg, f.score) == ("CVE-2", "zlib", 9.8)
    assert rescan.sbom_key(KEY).startswith("mgmt/sbom_reports/observability/")


def test_digest_render():
    rows = [
        ("mgmt", "grafana", "grafana", "CVE-1", "CRITICAL", FIX_READY, 7, "https://mr/7", NOW),
        ("mgmt", "loki", "loki", "CVE-2", "CRITICAL", OVERDUE, None, None, NOW - timedelta(days=9)),
    ]
    text = digest.render(rows, {"mgmt": 2}, NOW, "")
    assert "grafana — <https://mr/7|!7> fixes 1 CRITICAL · 0 HIGH" in text
    assert "loki/loki CVE-2 — 9 days" in text
    assert "Containers without a report: 2" in text


def test_settings_strip_tokens(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql://x")
    for name in ("ARGOCD_TOKEN", "GITLAB_TOKEN", "SLACK_TOKEN"):
        monkeypatch.setenv(name, "secret\n")
    s = Settings.from_env()
    assert (s.argocd_token, s.gitlab_token, s.slack_token) == ("secret", "secret", "secret")


def test_ownership_config(tmp_path, monkeypatch):
    cfg = tmp_path / "config.yaml"
    cfg.write_text("""
owners:
  - match: "team-a/*/*"
    app: billing
managed: [billing]
ignore:
  - "infra/DaemonSet/node-agent-*"
""")
    monkeypatch.setenv("DATABASE_URL", "postgresql://x")
    monkeypatch.setenv("CONFIG_FILE", str(cfg))
    o = Settings.from_env().ownership

    def live(ns, kind, name):
        return inventory.LiveContainer("dev", ns, "c", "img", kind, name, kind, name)

    assert evaluate.owner_of(live("team-a", "Deployment", "api"), o) == "billing"
    assert evaluate.owner_of(live("team-b", "Deployment", "api"), o) is None
    assert evaluate.is_ignored(live("infra", "DaemonSet", "node-agent-x"), o)
    assert not evaluate.is_ignored(live("infra", "Deployment", "node-agent-x"), o)
    assert status(app="billing", managed_apps=o.managed) == MANAGED
    assert status(app="billing", managed_apps=o.managed, severity="CRITICAL",
                  first_seen=NOW - timedelta(days=30)) == OVERDUE


def test_ownership_without_config(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql://x")
    monkeypatch.delenv("CONFIG_FILE", raising=False)
    assert Settings.from_env().ownership == config.Ownership()


def test_argocd_comparison_error_fails_the_run():
    def app(name, dest, conditions=()):
        return {"metadata": {"name": name}, "spec": {"destination": {"name": dest}},
                "status": {"conditions": list(conditions)}}

    err = [{"type": "ComparisonError", "message": "failed to load open api schema"}]
    pattern = re.compile(r"acme-(?P<env>[a-z0-9]+)-eks")
    apps = [app("web-dev", "acme-dev-eks"), app("web-prod", "acme-prod-eks", err)]

    argocd.check_comparable(apps, {"dev"}, pattern, "in-cluster")
    try:
        argocd.check_comparable(apps, {"dev", "prod"}, pattern, "in-cluster")
    except argocd.ArgoCDUnavailable as e:
        assert "web-prod" in str(e)
    else:
        raise AssertionError("a ComparisonError in an evaluated cluster must fail the run")
