"""Read-only view of the helm repo: Renovate MRs, their security:diff verdicts,
the Dependency Dashboard and the exceptions file."""

import re
from datetime import date
from urllib.parse import quote

import httpx
import yaml

from .status import MergeRequest, RiskException

BRANCH_RE = re.compile(r"^renovate/(?P<app>[^/]+)/")
DASHBOARD_APP_RE = re.compile(r"apps/(?P<app>[^/\s`]+)/")

EXCEPTIONS_PATH = "security/exceptions.yaml"
DIFF_JOB = "security:diff"
DIFF_ARTIFACT = "security-diff.json"


def app_of_branch(branch: str) -> str | None:
    m = BRANCH_RE.match(branch)
    return m.group("app") if m else None


def apps_in_dashboard(body: str) -> set[str]:
    """Apps with at least one dependency Renovate detected."""
    return {m.group("app") for m in DASHBOARD_APP_RE.finditer(body)}


def parse_exceptions(text: str) -> list[RiskException]:
    entries = yaml.safe_load(text) or []
    result = []
    for e in entries:
        expires = e["expires"]
        result.append(RiskException(
            expires=expires if isinstance(expires, date) else date.fromisoformat(str(expires)),
            reason=e["reason"],
            app=e.get("app", "*"),
            cluster=e.get("cluster", "*"),
            vuln_id=e.get("id", ""),
            package=e.get("package", ""),
        ))
    return result


class GitLab:
    def __init__(self, url: str, token: str, project: str):
        self.project = quote(project, safe="")
        self.http = httpx.Client(base_url=f"{url.rstrip('/')}/api/v4",
                                 headers={"PRIVATE-TOKEN": token}, timeout=30)

    def _pages(self, path: str, **params):
        params = {"per_page": 100, **params}
        page = 1
        while page:
            r = self.http.get(path, params={**params, "page": page})
            r.raise_for_status()
            yield from r.json()
            page = int(r.headers.get("x-next-page") or 0)

    def renovate_mrs(self) -> dict[str, list[MergeRequest]]:
        by_app: dict[str, list[MergeRequest]] = {}
        for mr in self._pages(f"/projects/{self.project}/merge_requests", state="opened",
                              labels="renovate"):
            app = app_of_branch(mr["source_branch"])
            if app:
                by_app.setdefault(app, []).append(
                    MergeRequest(mr["iid"], mr["web_url"], mr["source_branch"], mr["title"]))
        return by_app

    def security_diff(self, branch: str) -> dict | None:
        """Verdict of the latest successful security:diff job on the branch."""
        r = self.http.get(
            f"/projects/{self.project}/jobs/artifacts/{quote(branch, safe='')}/raw/{DIFF_ARTIFACT}",
            params={"job": DIFF_JOB})
        if r.status_code == 404:
            return None
        r.raise_for_status()
        return r.json()

    def tracked_apps(self) -> set[str]:
        """Apps in the Dependency Dashboard Renovate updated last; an older one
        left by a previous bot account goes stale."""
        issues = list(self._pages(f"/projects/{self.project}/issues", state="opened",
                                  search="Dependency Dashboard", **{"in": "title"}))
        if not issues:
            return set()
        latest = max(issues, key=lambda i: i["updated_at"])
        return apps_in_dashboard(latest.get("description") or "")

    def exceptions(self) -> list[RiskException]:
        r = self.http.get(
            f"/projects/{self.project}/repository/files/{quote(EXCEPTIONS_PATH, safe='')}/raw",
            params={"ref": "master"})
        if r.status_code == 404:
            return []
        r.raise_for_status()
        return parse_exceptions(r.text)
