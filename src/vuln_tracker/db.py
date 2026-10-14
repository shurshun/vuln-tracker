"""Postgres state. The schema is created idempotently on every run."""

from datetime import UTC, datetime

import psycopg

SCHEMA = """
create table if not exists reports (
    key          text primary key,
    cluster      text not null,
    namespace    text not null,
    kind         text not null,
    name         text not null,
    container    text not null,
    image        text not null,
    digest       text not null default '',
    spec_hash    text not null default '',
    scanned_at   timestamptz not null,
    s3_modified  timestamptz not null,
    rescanned_at timestamptz
);

create table if not exists findings (
    report_key text not null references reports(key) on delete cascade,
    vuln_id    text not null,
    pkg        text not null,
    installed  text not null,
    fixed      text not null,
    severity   text not null,
    title      text not null,
    link       text not null,
    score      real,
    primary key (report_key, vuln_id, pkg, installed)
);

create table if not exists live_containers (
    cluster       text not null,
    namespace     text not null,
    container     text not null,
    image         text not null,
    report_key    text not null,
    workload_kind text not null,
    workload_name text not null,
    app           text,
    has_report    boolean not null,
    primary key (report_key)
);

create table if not exists statuses (
    cluster       text not null,
    namespace     text not null,
    workload_kind text not null,
    workload_name text not null,
    container     text not null,
    app           text,
    image         text not null,
    vuln_id       text not null,
    pkg           text not null,
    installed     text not null,
    fixed         text not null,
    severity      text not null,
    title         text not null,
    link          text not null,
    status        text not null,
    mr_iid        integer,
    mr_url        text,
    first_seen    timestamptz not null,
    last_seen     timestamptz not null,
    resolved_at   timestamptz,
    primary key (cluster, namespace, workload_kind, workload_name, container, vuln_id, pkg)
);

create index if not exists statuses_open on statuses (status) where resolved_at is null;

create table if not exists checkpoints (
    name  text primary key,
    value timestamptz not null
);
"""


def connect(url: str) -> psycopg.Connection:
    conn = psycopg.connect(url)
    with conn.transaction():
        conn.execute(SCHEMA)
    return conn


def get_checkpoint(conn: psycopg.Connection, name: str) -> datetime | None:
    row = conn.execute("select value from checkpoints where name = %s", (name,)).fetchone()
    return row[0] if row else None


def set_checkpoint(conn: psycopg.Connection, name: str, value: datetime | None = None) -> None:
    conn.execute(
        "insert into checkpoints (name, value) values (%s, %s) "
        "on conflict (name) do update set value = excluded.value",
        (name, value or datetime.now(UTC)))
