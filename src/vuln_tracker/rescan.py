"""Fresh findings for unchanged images: stored SBOMs against today's trivy DB.

The operator scans an image when it changes. A CVE published later against
the same image shows up here, without pulling the image again.
"""

import json
import logging
import subprocess
import tempfile
from datetime import UTC, datetime

import psycopg

from .config import Settings
from .db import set_checkpoint
from .ingest import save_findings
from .reports import Finding, dedupe
from .storage import Bucket

log = logging.getLogger(__name__)

JAVA_DB_REPOSITORY = "public.ecr.aws/aquasecurity/trivy-java-db"


def cvss_score(cvss: dict) -> float | None:
    for source in ("nvd", "ghsa", "redhat"):
        score = (cvss.get(source) or {}).get("V3Score")
        if score is not None:
            return score
    return None


def parse_trivy(result: dict) -> tuple[Finding, ...]:
    """Findings from `trivy sbom --format json` output."""
    return dedupe([
        Finding(
            vuln_id=v["VulnerabilityID"],
            pkg=v.get("PkgName", ""),
            installed=v.get("InstalledVersion", ""),
            fixed=v.get("FixedVersion", ""),
            severity=v.get("Severity", "UNKNOWN"),
            title=v.get("Title", ""),
            link=v.get("PrimaryURL", ""),
            score=cvss_score(v.get("CVSS") or {}),
        )
        for target in result.get("Results") or []
        for v in target.get("Vulnerabilities") or []
    ])


def sbom_key(vulnerability_key: str) -> str:
    return vulnerability_key.replace("/vulnerability_reports/", "/sbom_reports/", 1)


def trivy(settings: Settings, *args: str) -> str:
    cmd = ["trivy", "--quiet", "--cache-dir", settings.trivy_cache_dir, *args]
    return subprocess.run(cmd, check=True, capture_output=True, text=True).stdout


def rescan(settings: Settings, conn: psycopg.Connection) -> None:
    bucket = Bucket(settings.bucket)

    # One DB download per run; every scan below runs against it offline.
    trivy(settings, "image", "--download-db-only", "--db-repository", settings.trivy_db_repository)
    trivy(settings, "image", "--download-java-db-only", "--java-db-repository", JAVA_DB_REPOSITORY)

    keys = [row[0] for row in conn.execute("select report_key from live_containers where has_report")]
    done = 0
    for key in keys:
        doc = bucket.get_json(sbom_key(key))
        if doc is None:
            continue
        with tempfile.NamedTemporaryFile("w", suffix=".cdx.json") as bom:
            json.dump(doc["report"]["components"], bom)
            bom.flush()
            try:
                out = trivy(settings, "sbom", "--format", "json", "--scanners", "vuln",
                            "--ignore-unfixed", "--skip-db-update", "--skip-java-db-update",
                            bom.name)
            except subprocess.CalledProcessError as e:
                log.warning("rescan of %s failed: %s", key, e.stderr.strip())
                continue

        with conn.transaction():
            save_findings(conn, key, parse_trivy(json.loads(out)))
            conn.execute("update reports set rescanned_at = %s where key = %s",
                         (datetime.now(UTC), key))
        done += 1

    log.info("rescan: %d of %d live reports", done, len(keys))
    with conn.transaction():
        set_checkpoint(conn, "success:rescan")
