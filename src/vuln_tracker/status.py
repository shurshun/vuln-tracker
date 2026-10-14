"""Status of one open finding: what, if anything, fixes it."""

from dataclasses import dataclass
from datetime import date, datetime, timedelta

ACCEPTED = "accepted"
FIX_READY = "fix-ready"
UPSTREAM_PENDING = "upstream-pending"
MR_UNVERIFIED = "mr-unverified"
NO_FIX = "no-fix"
RENOVATE_GAP = "renovate-gap"
UNOWNED = "unowned"
OVERDUE = "overdue"


@dataclass(frozen=True)
class RiskException:
    """Entry of security/exceptions.yaml in the helm repo."""

    expires: date
    reason: str
    app: str = "*"
    cluster: str = "*"
    vuln_id: str = ""
    package: str = ""

    def matches(self, *, cluster: str, app: str | None, vuln_id: str, pkg: str, today: date) -> bool:
        if today > self.expires:
            return False
        if self.cluster not in ("*", cluster) or self.app not in ("*", app):
            return False
        if self.vuln_id and self.vuln_id != vuln_id:
            return False
        if self.package and self.package != pkg:
            return False
        return bool(self.vuln_id or self.package)


@dataclass(frozen=True)
class MergeRequest:
    iid: int
    url: str
    branch: str
    title: str


@dataclass(frozen=True)
class Decision:
    status: str
    mr: MergeRequest | None = None


def decide(*, cluster: str, app: str | None, vuln_id: str, pkg: str, severity: str,
           first_seen: datetime, now: datetime, exceptions: list[RiskException],
           mrs: list[MergeRequest], fixed_by: dict[str, set[str]], diffed: set[str],
           tracked_apps: set[str], sla: timedelta) -> Decision:
    """
    fixed_by maps an MR branch to the vulnerability ids its security:diff
    artifact reports as fixed; diffed holds branches that have an artifact.
    """

    if any(e.matches(cluster=cluster, app=app, vuln_id=vuln_id, pkg=pkg, today=now.date())
           for e in exceptions):
        return Decision(ACCEPTED)

    if app is None:
        decision = Decision(UNOWNED)
    elif mrs:
        fixing = next((mr for mr in mrs if vuln_id in fixed_by.get(mr.branch, set())), None)
        if fixing:
            decision = Decision(FIX_READY, fixing)
        elif any(mr.branch in diffed for mr in mrs):
            decision = Decision(UPSTREAM_PENDING, mrs[0])
        else:
            decision = Decision(MR_UNVERIFIED, mrs[0])
    elif app in tracked_apps:
        decision = Decision(NO_FIX)
    else:
        decision = Decision(RENOVATE_GAP)

    if severity == "CRITICAL" and now - first_seen > sla:
        return Decision(OVERDUE, decision.mr)
    return decision
