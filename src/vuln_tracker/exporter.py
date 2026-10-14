"""/metrics computed from Postgres on every scrape.

The cluster goes into an `env` label: vmagent sets its own `cluster` external
label on everything it writes.

Hourly CronJobs could push gauges instead, but an instant query only looks
back a few minutes, so pushed samples would vanish between runs.
"""

import logging
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import psycopg

log = logging.getLogger(__name__)

FINDINGS = """
select cluster, namespace, coalesce(app, ''), severity, status, count(*)
from statuses where resolved_at is null and status <> 'ignored'
group by 1, 2, 3, 4, 5
"""
LIVE = "select cluster, has_report, count(*) from live_containers group by 1, 2"
CHECKPOINTS = "select name, extract(epoch from value) from checkpoints where name like 'success:%'"


def escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def labels(**kv: str) -> str:
    return "{" + ",".join(f'{k}="{escape(str(v))}"' for k, v in kv.items()) + "}"


def render(conn: psycopg.Connection) -> str:
    out = [
        "# HELP vuln_tracker_findings Open findings by status.",
        "# TYPE vuln_tracker_findings gauge",
    ]
    for cluster, ns, app, severity, status, n in conn.execute(FINDINGS):
        series = labels(env=cluster, namespace=ns, app=app, severity=severity, status=status)
        out.append(f"vuln_tracker_findings{series} {n}")

    out += ["# HELP vuln_tracker_live_containers Running containers, with and without a report.",
            "# TYPE vuln_tracker_live_containers gauge"]
    for cluster, has_report, n in conn.execute(LIVE):
        out.append(f"vuln_tracker_live_containers{labels(env=cluster, reported=str(has_report).lower())} {n}")

    out += ["# HELP vuln_tracker_last_success_timestamp_seconds Last successful run of each step.",
            "# TYPE vuln_tracker_last_success_timestamp_seconds gauge"]
    for name, ts in conn.execute(CHECKPOINTS):
        series = labels(step=name.removeprefix("success:"))
        out.append(f"vuln_tracker_last_success_timestamp_seconds{series} {float(ts)}")
    return "\n".join(out) + "\n"


def serve(database_url: str, port: int) -> None:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/healthz":
                body, code = b"ok\n", 200
            elif self.path == "/metrics":
                try:
                    with psycopg.connect(database_url, autocommit=True) as conn:
                        body, code = render(conn).encode(), 200
                except psycopg.Error as e:
                    log.error("metrics: %s", e)
                    body, code = b"database unavailable\n", 503
            else:
                body, code = b"not found\n", 404
            self.send_response(code)
            self.send_header("Content-Type", "text/plain; version=0.0.4")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    log.info("serving /metrics on :%d", port)
    ThreadingHTTPServer(("", port), Handler).serve_forever()
