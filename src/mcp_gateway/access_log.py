"""Per-request access logger backed by Postgres.

Writes are synchronous from the request hot path. The connection pool is
small (default 5) — at typical hobby-fleet volume the latency is invisible,
and a synchronous write keeps ordering guarantees obvious. The log function
swallows all exceptions so a transient PG hiccup never fails a real request.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

import psycopg2
from psycopg2.pool import ThreadedConnectionPool

log = logging.getLogger(__name__)

_pool: ThreadedConnectionPool | None = None


def init_pool(dsn: str, min_conn: int = 1, max_conn: int = 5) -> None:
    global _pool
    if _pool is not None:
        return
    try:
        _pool = ThreadedConnectionPool(min_conn, max_conn, dsn + " connect_timeout=5")
        log.warning("Access-log PG pool initialised (%d-%d connections)", min_conn, max_conn)
    except Exception:
        log.exception("Access-log PG pool init failed; logging will silently no-op")


def close_pool() -> None:
    global _pool
    if _pool is not None:
        _pool.closeall()
        _pool = None


def log_event(
    event: str,
    *,
    actor_kind: str | None = None,
    actor_name: str | None = None,
    client_ip: str | None = None,
    tool_name: str | None = None,
    profile: str | None = None,
    detail: dict[str, Any] | None = None,
) -> None:
    """Insert a single access-log row. Never raises."""
    if _pool is None:
        return
    conn = None
    try:
        conn = _pool.getconn()
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO gateway_access_log
                  (event, actor_kind, actor_name, client_ip, tool_name, profile, detail)
                VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb)
                """,
                (
                    event,
                    actor_kind,
                    actor_name,
                    client_ip,
                    tool_name,
                    profile,
                    json.dumps(detail) if detail is not None else None,
                ),
            )
        conn.commit()
    except psycopg2.Error:
        if conn is not None:
            try:
                conn.rollback()
            except Exception:
                pass
        log.warning("access_log write failed", exc_info=True)
    except Exception:
        log.warning("access_log unexpected error", exc_info=True)
    finally:
        if conn is not None:
            try:
                _pool.putconn(conn)
            except Exception:
                pass
