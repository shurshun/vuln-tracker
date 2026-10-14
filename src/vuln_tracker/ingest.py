"""S3 → Postgres: new and rewritten vulnerability reports."""

import logging

import psycopg

from .config import Settings
from .db import set_checkpoint
from .reports import Finding, Report, parse_report
from .storage import Bucket

log = logging.getLogger(__name__)


def save_findings(conn: psycopg.Connection, key: str, findings: tuple[Finding, ...]) -> None:
    conn.execute("delete from findings where report_key = %s", (key,))
    with conn.cursor() as cur:
        cur.executemany(
            "insert into findings (report_key, vuln_id, pkg, installed, fixed, severity, title, link, score) "
            "values (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
            [(key, f.vuln_id, f.pkg, f.installed, f.fixed, f.severity, f.title, f.link, f.score)
             for f in findings])


def save_report(conn: psycopg.Connection, r: Report, modified) -> None:
    with conn.transaction():
        conn.execute(
            """
            insert into reports (key, cluster, namespace, kind, name, container, image, digest,
                                 spec_hash, scanned_at, s3_modified, rescanned_at)
            values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, null)
            on conflict (key) do update set
                image = excluded.image, digest = excluded.digest, spec_hash = excluded.spec_hash,
                scanned_at = excluded.scanned_at, s3_modified = excluded.s3_modified,
                rescanned_at = null
            """,
            (r.key, r.cluster, r.namespace, r.kind, r.name, r.container, r.image, r.digest,
             r.spec_hash, r.scanned_at, modified))
        save_findings(conn, r.key, r.findings)


def ingest(settings: Settings, conn: psycopg.Connection) -> None:
    bucket = Bucket(settings.bucket)
    for cluster in settings.clusters:
        known = dict(conn.execute("select key, s3_modified from reports where cluster = %s",
                                  (cluster,)).fetchall())
        changed = 0
        for key, modified in bucket.list(f"{cluster}/vulnerability_reports/"):
            if known.get(key) == modified:
                continue
            doc = bucket.get_json(key)
            if doc is None:
                continue
            try:
                report = parse_report(key, doc)
            except (KeyError, ValueError) as e:
                log.warning("skipping unreadable report %s: %r", key, e)
                continue
            save_report(conn, report, modified)
            changed += 1
        log.info("ingest %s: %d new or rewritten reports", cluster, changed)
    with conn.transaction():
        set_checkpoint(conn, "success:ingest")
