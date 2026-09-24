"""芯片批次和测量记录的 SQLite 结构、哈希链审计及事务辅助函数。"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Iterator


SCHEMA = """
CREATE TABLE IF NOT EXISTS chip_lots(
 lot_id TEXT PRIMARY KEY, product TEXT NOT NULL, process_rev TEXT NOT NULL,
 wafer_count INTEGER NOT NULL, status TEXT NOT NULL, owner TEXT NOT NULL,
 created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS measurements(
 measurement_id TEXT PRIMARY KEY, lot_id TEXT NOT NULL REFERENCES chip_lots(lot_id),
 wavelength_nm REAL NOT NULL, response REAL NOT NULL, noise REAL NOT NULL,
 instrument TEXT NOT NULL, operator TEXT NOT NULL, measured_at TEXT NOT NULL,
 UNIQUE(lot_id,measurement_id));
CREATE TABLE IF NOT EXISTS audit_events(
 event_id INTEGER PRIMARY KEY AUTOINCREMENT,
 entity_type TEXT NOT NULL, entity_id TEXT NOT NULL,
 event_type TEXT NOT NULL, actor TEXT NOT NULL, payload TEXT NOT NULL,
 previous_hash TEXT NOT NULL, event_hash TEXT NOT NULL UNIQUE,
 created_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_audit_entity
ON audit_events(entity_type, entity_id, event_id);
CREATE TABLE IF NOT EXISTS quality_reviews(
 review_id INTEGER PRIMARY KEY AUTOINCREMENT,
 lot_id TEXT NOT NULL REFERENCES chip_lots(lot_id),
 reviewer TEXT NOT NULL, result TEXT NOT NULL CHECK(result IN ('pass','fail')),
 note TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_reviews_lot ON quality_reviews(lot_id, review_id);
CREATE TABLE IF NOT EXISTS approval_decisions(
 decision_id INTEGER PRIMARY KEY AUTOINCREMENT,
 lot_id TEXT NOT NULL REFERENCES chip_lots(lot_id),
 reviewer TEXT NOT NULL, decision TEXT NOT NULL
 CHECK(decision IN ('release','hold','reject')),
 reason TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_decisions_lot ON approval_decisions(lot_id, decision_id);
"""

GENESIS_HASH = "0" * 64


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def canonical(payload: dict) -> str:
    return json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def connect(path: str = ":memory:") -> sqlite3.Connection:
    # HTTP 服务为多线程模型；写操作统一走 BEGIN IMMEDIATE 串行化，
    # 因此允许连接跨线程使用。
    db = sqlite3.connect(path, check_same_thread=False)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")
    db.executescript(SCHEMA)
    _migrate_legacy(db)
    db.commit()
    return db


def _migrate_legacy(db: sqlite3.Connection) -> None:
    """把基线版本的 lot_events/approvals 迁入哈希链与只增决定表。"""
    tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    if "lot_events" in tables:
        previous = GENESIS_HASH
        for row in db.execute(
            "SELECT lot_id,event_type,actor,payload,created_at FROM lot_events ORDER BY event_id"
        ):
            body = {
                "entity_type": "lot",
                "entity_id": row[0],
                "event_type": row[1],
                "actor": row[2],
                "payload": json.loads(row[3]),
                "created_at": row[4],
                "previous_hash": previous,
            }
            event_hash = hashlib.sha256(canonical(body).encode("utf-8")).hexdigest()
            db.execute(
                "INSERT INTO audit_events(entity_type,entity_id,event_type,actor,payload,"
                "previous_hash,event_hash,created_at) VALUES(?,?,?,?,?,?,?,?)",
                ("lot", row[0], row[1], row[2], row[3], previous, event_hash, row[4]),
            )
            previous = event_hash
        db.execute("DROP TABLE lot_events")
    if "approvals" in tables:
        db.execute(
            "INSERT INTO approval_decisions(lot_id,reviewer,decision,reason,created_at) "
            "SELECT lot_id,reviewer,decision,reason,created_at FROM approvals"
        )
        db.execute("DROP TABLE approvals")


@contextmanager
def transaction(db: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    try:
        db.execute("BEGIN IMMEDIATE")
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise


def record_event(
    db: sqlite3.Connection,
    entity_type: str,
    entity_id: str,
    event_type: str,
    actor: str,
    payload: dict,
    created_at: str | None = None,
) -> str:
    """在调用方事务内追加一个哈希链事件，返回该事件哈希。

    BEGIN IMMEDIATE 已持有写锁，串行读取链尾即可保证链不被分叉。
    """
    created_at = created_at or utcnow()
    tail = db.execute("SELECT event_hash FROM audit_events ORDER BY event_id DESC LIMIT 1").fetchone()
    previous_hash = GENESIS_HASH if tail is None else tail[0]
    body = {
        "entity_type": entity_type,
        "entity_id": entity_id,
        "event_type": event_type,
        "actor": actor,
        "payload": payload,
        "created_at": created_at,
        "previous_hash": previous_hash,
    }
    event_hash = hashlib.sha256(canonical(body).encode("utf-8")).hexdigest()
    db.execute(
        "INSERT INTO audit_events(entity_type,entity_id,event_type,actor,payload,"
        "previous_hash,event_hash,created_at) VALUES(?,?,?,?,?,?,?,?)",
        (
            entity_type,
            entity_id,
            event_type,
            actor,
            canonical(payload),
            previous_hash,
            event_hash,
            created_at,
        ),
    )
    return event_hash


def verify_chain(db: sqlite3.Connection) -> dict:
    """离线重放整条审计链，任一字段被改写都会使 valid 为 False。"""
    rows = db.execute("SELECT * FROM audit_events ORDER BY event_id").fetchall()
    previous_hash = GENESIS_HASH
    valid = True
    for row in rows:
        body = {
            "entity_type": row["entity_type"],
            "entity_id": row["entity_id"],
            "event_type": row["event_type"],
            "actor": row["actor"],
            "payload": json.loads(row["payload"]),
            "created_at": row["created_at"],
            "previous_hash": row["previous_hash"],
        }
        calculated = hashlib.sha256(canonical(body).encode("utf-8")).hexdigest()
        if row["previous_hash"] != previous_hash or not _const_eq(row["event_hash"], calculated):
            valid = False
            break
        previous_hash = row["event_hash"]
    return {"valid": valid, "events": len(rows), "head_hash": previous_hash}


def _const_eq(a: str, b: str) -> bool:
    import hmac

    return hmac.compare_digest(a, b)
