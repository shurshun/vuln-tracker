"""Ingest → evaluate → metrics against a real Postgres.

Runs when TEST_DATABASE_URL points at a scratch database, e.g.
docker run -d -p 55432:5432 -e POSTGRES_PASSWORD=test postgres:17
TEST_DATABASE_URL=postgresql://postgres:test@localhost:55432/postgres uv run pytest
"""

import os
from datetime import UTC, datetime

import pytest

from tests.test_units import KEY, report_doc
from vuln_tracker import db, evaluate, exporter, ingest, reports
from vuln_tracker.config import Settings

URL = os.environ.get("TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not URL, reason="TEST_DATABASE_URL not set")


@pytest.fixture
def conn():
    with db.connect(URL) as c:
        c.execute("drop table if exists findings, reports, live_containers, statuses, checkpoints cascade")
        c.commit()
    with db.connect(URL) as c:
        yield c


def settings():
    os.environ.update(DATABASE_URL=URL, CLUSTERS="mgmt=http://vm")
    return Settings.from_env()


def test_pipeline(conn, monkeypatch):
    modified = datetime(2026, 9, 30, 10, tzinfo=UTC)
    ingest.save_report(conn, reports.parse_report(KEY, report_doc()), modified)

    series = {
        evaluate.RUNNING_CONTAINERS: [{"namespace": "observability", "pod": "grafana-7d9f8-a",
                                       "container": "grafana", "image": "grafana/grafana:12.1.0"},
                                      {"namespace": "observability", "pod": "loki-0",
                                       "container": "loki", "image": "grafana/loki:3"}],
        "kube_pod_owner": [{"namespace": "observability", "pod": "grafana-7d9f8-a",
                            "owner_kind": "ReplicaSet", "owner_name": "grafana-7d9f8",
                            "owner_is_controller": "true"},
                           {"namespace": "observability", "pod": "loki-0",
                            "owner_kind": "StatefulSet", "owner_name": "loki",
                            "owner_is_controller": "true"}],
        "kube_replicaset_owner": [{"namespace": "observability", "replicaset": "grafana-7d9f8",
                                   "owner_kind": "Deployment", "owner_name": "grafana",
                                   "owner_is_controller": "true"}],
        "kube_job_owner": [],
    }
    monkeypatch.setattr(evaluate.vm, "query", lambda url, q: series[q])

    evaluate.evaluate(settings(), conn)
    evaluate.evaluate(settings(), conn)

    rows = conn.execute("select app, workload_name, vuln_id, status, resolved_at from statuses").fetchall()
    assert rows == [(None, "grafana", "CVE-2026-1", "unowned", None)]

    text = exporter.render(conn)
    assert ('vuln_tracker_findings{env="mgmt",namespace="observability",app="",'
            'severity="CRITICAL",status="unowned"} 1') in text
    assert 'vuln_tracker_live_containers{env="mgmt",reported="false"} 1' in text
    assert 'vuln_tracker_last_success_timestamp_seconds{step="evaluate"}' in text

    # The workload is gone: its finding resolves.
    series[evaluate.RUNNING_CONTAINERS] = series[evaluate.RUNNING_CONTAINERS][1:]
    evaluate.evaluate(settings(), conn)
    assert conn.execute("select count(*) from statuses where resolved_at is null").fetchone() == (0,)
