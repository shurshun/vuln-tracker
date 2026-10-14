"""Instant queries against VictoriaMetrics."""

import httpx


def query(url: str, promql: str) -> list[dict]:
    """Label sets of the series an instant query returns."""
    r = httpx.get(f"{url.rstrip('/')}/api/v1/query", params={"query": promql}, timeout=60)
    r.raise_for_status()
    body = r.json()
    if body.get("status") != "success":
        raise RuntimeError(f"query failed: {promql}: {body}")
    return [s["metric"] for s in body["data"]["result"]]
