"""Live containers × their reports → one status per open finding."""

import logging
from datetime import UTC, datetime
from fnmatch import fnmatchcase

import psycopg

from . import argocd, vm
from .config import Settings
from .db import set_checkpoint
from .gitlab import GitLab
from .inventory import LiveContainer, owner_map, resolve
from .status import decide

log = logging.getLogger(__name__)

# Only running pods: completed Job pods keep their series until deleted.
RUNNING_CONTAINERS = (
    'kube_pod_container_info * on (namespace, pod) group_left () '
    '(kube_pod_status_phase{phase="Running"} == 1)'
)


def live_containers(cluster: str, url: str) -> list[LiveContainer]:
    return resolve(
        cluster,
        vm.query(url, RUNNING_CONTAINERS),
        owner_map(vm.query(url, "kube_pod_owner"), "pod"),
        owner_map(vm.query(url, "kube_replicaset_owner"), "replicaset"),
        owner_map(vm.query(url, "kube_job_owner"), "job_name"),
    )


def owner_of(c: LiveContainer, owners: list[tuple[str, str]]) -> str | None:
    workload = f"{c.namespace}/{c.workload_kind}/{c.workload_name}"
    return next((app for pattern, app in owners if fnmatchcase(workload, pattern)), None)


def evaluate(settings: Settings, conn: psycopg.Connection) -> None:
    now = datetime.now(UTC)

    live = [c for cluster, url in settings.clusters.items() for c in live_containers(cluster, url)]
    apps = argocd.fetch_index(settings.argocd_url, settings.argocd_token, settings.argocd_cluster_pattern,
                              settings.argocd_in_cluster) if settings.argocd_url else {}

    gitlab = GitLab(settings.gitlab_url, settings.gitlab_token, settings.helm_project) \
        if settings.gitlab_token else None
    exceptions = gitlab.exceptions() if gitlab else []
    mrs = gitlab.renovate_mrs() if gitlab else {}
    tracked = gitlab.tracked_apps() if gitlab else set()

    fixed_by: dict[str, set[str]] = {}
    for mr in (mr for app_mrs in mrs.values() for mr in app_mrs):
        verdict = gitlab.security_diff(mr.branch)
        if verdict is not None:
            fixed_by[mr.branch] = {f["id"] for f in verdict.get("fixed", [])}

    keys = [c.report_key for c in live]
    reported = {row[0] for row in conn.execute(
        "select key from reports where key = any(%s)", (keys,))}
    findings: dict[str, list[tuple]] = {}
    for row in conn.execute(
            "select report_key, vuln_id, pkg, installed, fixed, severity, title, link "
            "from findings where report_key = any(%s)", (keys,)):
        findings.setdefault(row[0], []).append(row[1:])

    first_seen = {row[:7]: row[7] for row in conn.execute(
        "select cluster, namespace, workload_kind, workload_name, container, vuln_id, pkg, first_seen "
        "from statuses where resolved_at is null")}

    seen = set()
    with conn.transaction():
        conn.execute("delete from live_containers")
        for c in live:
            app = apps.get((c.cluster, c.namespace, c.workload_kind, c.workload_name)) \
                or owner_of(c, settings.owners)
            conn.execute(
                "insert into live_containers (cluster, namespace, container, image, report_key, "
                "workload_kind, workload_name, app, has_report) "
                "values (%s, %s, %s, %s, %s, %s, %s, %s, %s) on conflict (report_key) do nothing",
                (c.cluster, c.namespace, c.container, c.image, c.report_key, c.workload_kind,
                 c.workload_name, app, c.report_key in reported))

            for vuln_id, pkg, installed, fixed, severity, title, link in findings.get(c.report_key, []):
                pk = (c.cluster, c.namespace, c.workload_kind, c.workload_name, c.container, vuln_id, pkg)
                if pk in seen:
                    continue
                seen.add(pk)
                since = first_seen.get(pk, now)
                d = decide(cluster=c.cluster, app=app, vuln_id=vuln_id, pkg=pkg, severity=severity,
                           first_seen=since, now=now, exceptions=exceptions,
                           mrs=mrs.get(app, []) if app else [], fixed_by=fixed_by,
                           diffed=set(fixed_by), tracked_apps=tracked, sla=settings.critical_sla,
                           managed_apps=settings.managed_apps)
                conn.execute(
                    """
                    insert into statuses (cluster, namespace, workload_kind, workload_name, container,
                        app, image, vuln_id, pkg, installed, fixed, severity, title, link, status,
                        mr_iid, mr_url, first_seen, last_seen, resolved_at)
                    values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, null)
                    on conflict (cluster, namespace, workload_kind, workload_name, container, vuln_id, pkg)
                    do update set app = excluded.app, image = excluded.image,
                        installed = excluded.installed, fixed = excluded.fixed,
                        severity = excluded.severity, title = excluded.title, link = excluded.link,
                        status = excluded.status, mr_iid = excluded.mr_iid, mr_url = excluded.mr_url,
                        first_seen = excluded.first_seen, last_seen = excluded.last_seen,
                        resolved_at = null
                    """,
                    (*pk[:5], app, c.image, vuln_id, pkg, installed, fixed, severity, title, link,
                     d.status, d.mr.iid if d.mr else None, d.mr.url if d.mr else None, since, now))

        gone = [pk for pk in first_seen if pk not in seen]
        with conn.cursor() as cur:
            cur.executemany(
                "update statuses set resolved_at = %s where cluster = %s and namespace = %s "
                "and workload_kind = %s and workload_name = %s and container = %s "
                "and vuln_id = %s and pkg = %s", [(now, *pk) for pk in gone])
        set_checkpoint(conn, "success:evaluate", now)

    log.info("evaluate: %d live containers, %d without report, %d open findings, %d resolved",
             len(live), sum(1 for c in live if c.report_key not in reported), len(seen), len(gone))
