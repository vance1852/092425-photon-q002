"""芯片批次和测量记录的 SQLite 结构及事务辅助函数。"""

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
CREATE TABLE IF NOT EXISTS lot_events(
 event_id INTEGER PRIMARY KEY AUTOINCREMENT, lot_id TEXT NOT NULL,
 event_type TEXT NOT NULL, actor TEXT NOT NULL, payload TEXT NOT NULL,
 previous_hash TEXT NOT NULL, event_hash TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS approvals(
 lot_id TEXT NOT NULL, reviewer TEXT NOT NULL, decision TEXT NOT NULL,
 reason TEXT NOT NULL, created_at TEXT NOT NULL, PRIMARY KEY(lot_id,reviewer));
"""

GENESIS_HASH = "0" * 64


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def event_hash(lot_id: str, event_type: str, actor: str, payload: dict, created_at: str, previous_hash: str) -> str:
    body = {
        "lot_id": lot_id,
        "event_type": event_type,
        "actor": actor,
        "payload": payload,
        "created_at": created_at,
        "previous_hash": previous_hash,
    }
    return hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest()


def connect(path: str = ":memory:") -> sqlite3.Connection:
    db = sqlite3.connect(path, check_same_thread=False)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")
    db.executescript(SCHEMA)
    _migrate_lot_events(db)
    db.commit()
    return db


def _migrate_lot_events(db: sqlite3.Connection) -> None:
    """为旧库补齐审计哈希链列并按事件顺序回填。"""
    columns = {row["name"] for row in db.execute("PRAGMA table_info(lot_events)")}
    if "event_hash" in columns:
        return
    db.execute("ALTER TABLE lot_events ADD COLUMN previous_hash TEXT NOT NULL DEFAULT ''")
    db.execute("ALTER TABLE lot_events ADD COLUMN event_hash TEXT NOT NULL DEFAULT ''")
    previous_hash = GENESIS_HASH
    for row in db.execute("SELECT * FROM lot_events ORDER BY event_id").fetchall():
        digest = event_hash(row["lot_id"], row["event_type"], row["actor"], json.loads(row["payload"]), row["created_at"], previous_hash)
        db.execute("UPDATE lot_events SET previous_hash=?,event_hash=? WHERE event_id=?", (previous_hash, digest, row["event_id"]))
        previous_hash = digest


@contextmanager
def transaction(db: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    try:
        db.execute("BEGIN IMMEDIATE")
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise


def event(db: sqlite3.Connection, lot_id: str, event_type: str, actor: str, payload: dict) -> None:
    previous = db.execute("SELECT event_hash FROM lot_events ORDER BY event_id DESC LIMIT 1").fetchone()
    previous_hash = GENESIS_HASH if previous is None else previous["event_hash"]
    created_at = utcnow()
    digest = event_hash(lot_id, event_type, actor, payload, created_at, previous_hash)
    db.execute(
        "INSERT INTO lot_events(lot_id,event_type,actor,payload,previous_hash,event_hash,created_at) VALUES(?,?,?,?,?,?,?)",
        (lot_id, event_type, actor, canonical_json(payload), previous_hash, digest, created_at))


def verify_chain(db: sqlite3.Connection) -> dict:
    """重放全部审计事件并校验哈希链，任何篡改都会使 valid 为 False。"""
    rows = db.execute("SELECT * FROM lot_events ORDER BY event_id").fetchall()
    previous_hash = GENESIS_HASH
    for row in rows:
        digest = event_hash(row["lot_id"], row["event_type"], row["actor"], json.loads(row["payload"]), row["created_at"], row["previous_hash"])
        if row["previous_hash"] != previous_hash or row["event_hash"] != digest:
            return {"valid": False, "events": len(rows), "head_hash": previous_hash}
        previous_hash = row["event_hash"]
    return {"valid": True, "events": len(rows), "head_hash": previous_hash}
