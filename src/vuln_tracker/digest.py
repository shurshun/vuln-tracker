"""Daily Slack digest of open CRITICAL and HIGH findings."""

import logging
from collections import Counter, defaultdict
from datetime import UTC, datetime

import httpx
import psycopg

from .config import Settings
from .db import set_checkpoint
from .status import (
    ACCEPTED,
    FIX_READY,
    MANAGED,
    MR_UNVERIFIED,
    NO_FIX,
    OVERDUE,
    RENOVATE_GAP,
    UNOWNED,
    UPSTREAM_PENDING,
)

log = logging.getLogger(__name__)

QUERY = """
select cluster, coalesce(app, namespace), workload_name, vuln_id, severity, status, mr_iid, mr_url,
       first_seen
from statuses
where resolved_at is null and severity in ('CRITICAL', 'HIGH')
order by cluster, 2, severity, vuln_id
"""


def counts(rows) -> str:
    c = Counter(r[4] for r in rows)
    return f"{c['CRITICAL']} CRITICAL · {c['HIGH']} HIGH"


def by_app(rows) -> dict[str, list]:
    grouped = defaultdict(list)
    for r in rows:
        grouped[r[1]].append(r)
    return grouped


def render(rows: list[tuple], without_report: dict[str, int], now: datetime, grafana_url: str) -> str:
    lines = []
    for cluster in sorted({r[0] for r in rows} | set(without_report)):
        mine = [r for r in rows if r[0] == cluster]
        by_status = defaultdict(list)
        for r in mine:
            by_status[r[5]].append(r)

        lines.append(f"*{cluster}*: {counts(mine)} open")

        if by_status[FIX_READY]:
            lines.append("Ready to merge:")
            mrs = defaultdict(list)
            for r in by_status[FIX_READY]:
                mrs[(r[1], r[6], r[7])].append(r)
            for (app, iid, url), items in sorted(mrs.items()):
                lines.append(f"• {app} — <{url}|!{iid}> fixes {counts(items)}")

        if by_status[OVERDUE]:
            lines.append("Overdue CRITICAL:")
            for r in by_status[OVERDUE][:10]:
                age = (now - r[8]).days
                mr = f", <{r[7]}|!{r[6]}>" if r[7] else ""
                lines.append(f"• {r[1]}/{r[2]} {r[3]} — {age} days{mr}")

        for status, title in ((MR_UNVERIFIED, "MR without security:diff verdict"),
                              (UPSTREAM_PENDING, "MR does not fix it yet"),
                              (NO_FIX, "No newer version upstream"),
                              (RENOVATE_GAP, "Not tracked by Renovate"),
                              (MANAGED, "Released outside the helm repo"),
                              (UNOWNED, "Not an ArgoCD app")):
            if by_status[status]:
                apps = ", ".join(f"{app} ({counts(items)})"
                                 for app, items in sorted(by_app(by_status[status]).items()))
                lines.append(f"{title}: {apps}")

        if by_status[ACCEPTED]:
            lines.append(f"Accepted risk: {len(by_status[ACCEPTED])}")
        if without_report.get(cluster):
            lines.append(f"Containers without a report: {without_report[cluster]}")
        lines.append("")

    if grafana_url:
        lines.append(f"<{grafana_url}|Dashboard>")
    return "\n".join(lines).strip() or "No open CRITICAL or HIGH findings."


def digest(settings: Settings, conn: psycopg.Connection) -> None:
    rows = conn.execute(QUERY).fetchall()
    without_report = dict(conn.execute(
        "select cluster, count(*) from live_containers where not has_report group by cluster").fetchall())
    text = render(rows, without_report, datetime.now(UTC), settings.grafana_url)

    r = httpx.post("https://slack.com/api/chat.postMessage",
                   headers={"Authorization": f"Bearer {settings.slack_token}"},
                   json={"channel": settings.slack_channel, "text": text, "unfurl_links": False},
                   timeout=30)
    r.raise_for_status()
    if not r.json().get("ok"):
        raise RuntimeError(f"slack: {r.json().get('error')}")

    log.info("digest sent to %s", settings.slack_channel)
    with conn.transaction():
        set_checkpoint(conn, "success:digest")
