"""vuln-tracker <step>."""

import argparse
import logging

from .config import Settings
from .db import connect


def main() -> None:
    parser = argparse.ArgumentParser(prog="vuln-tracker", description=__doc__)
    sub = parser.add_subparsers(dest="step", required=True)
    sub.add_parser("ingest", help="load new and rewritten reports from S3")
    sub.add_parser("evaluate", help="match live containers to reports and assign statuses")
    sub.add_parser("run", help="ingest, then evaluate")
    sub.add_parser("rescan", help="rescan stored SBOMs of live images with a fresh trivy DB")
    sub.add_parser("digest", help="post the Slack digest")
    serve = sub.add_parser("serve", help="expose /metrics from the database")
    serve.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    settings = Settings.from_env()

    if args.step == "serve":
        from .exporter import serve as run_server
        connect(settings.database_url).close()
        run_server(settings.database_url, args.port)
        return

    with connect(settings.database_url) as conn:
        if args.step in ("ingest", "run"):
            from .ingest import ingest
            ingest(settings, conn)
        if args.step in ("evaluate", "run"):
            from .evaluate import evaluate
            evaluate(settings, conn)
        if args.step == "rescan":
            from .rescan import rescan
            rescan(settings, conn)
        if args.step == "digest":
            from .digest import digest
            digest(settings, conn)
