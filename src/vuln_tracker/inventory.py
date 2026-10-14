"""What runs now, from kube-state-metrics series.

trivy-operator scans the pod's controller: a ReplicaSet for a Deployment, the
CronJob for its Jobs, the Pod itself when nothing owns it. Resolving each
running container to that controller gives the exact report key.
"""

from dataclasses import dataclass

from .reports import report_key


@dataclass(frozen=True)
class LiveContainer:
    cluster: str
    namespace: str
    container: str
    image: str
    report_kind: str
    report_name: str
    workload_kind: str
    workload_name: str

    @property
    def report_key(self) -> str:
        return report_key(self.cluster, self.namespace, self.report_kind, self.report_name,
                          self.container)


Owners = dict[tuple[str, str], tuple[str, str]]


def owner_map(series: list[dict], name_label: str) -> Owners:
    """(namespace, object) → (owner kind, owner name), controllers only."""

    owners: Owners = {}
    for s in series:
        if s.get("owner_is_controller", "true") != "true" or s.get("owner_kind") in (None, "<none>"):
            continue
        owners[(s["namespace"], s[name_label])] = (s["owner_kind"], s["owner_name"])
    return owners


def resolve(cluster: str, containers: list[dict], pod_owners: Owners, rs_owners: Owners,
            job_owners: Owners) -> list[LiveContainer]:
    """One entry per (controller, container); replicas collapse into one."""

    live: dict[tuple, LiveContainer] = {}
    for c in containers:
        ns, pod = c["namespace"], c["pod"]
        owner = pod_owners.get((ns, pod))

        if owner is None:
            report = workload = ("Pod", pod)
        elif owner[0] == "ReplicaSet":
            report = owner
            workload = rs_owners.get((ns, owner[1]), owner)
        elif owner[0] == "Job":
            parent = job_owners.get((ns, owner[1]))
            report = workload = parent if parent and parent[0] == "CronJob" else owner
        else:
            report = workload = owner

        item = LiveContainer(cluster, ns, c["container"], c.get("image", ""), report[0], report[1],
                             workload[0], workload[1])
        live[(ns, report, c["container"])] = item
    return list(live.values())
