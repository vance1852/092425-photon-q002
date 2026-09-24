"""协调认证、批次、测试和放行门禁的应用服务。"""

from __future__ import annotations

import threading
import uuid
from typing import Sequence

from .analytics import confidence_interval, summarize_spectrum, yield_rate
from .auth import Auth
from .storage import connect, event, transaction, utcnow, verify_chain


class PhotonService:
    def __init__(self, database: str = ":memory:"):
        self.db = connect(database)
        self.auth = Auth(self.db)
        self._lock = threading.RLock()

    def bootstrap_admin(self, user_id: str = "admin", password: str = "photon-admin") -> None:
        with self._lock:
            try:
                self.auth.create_user(user_id, password, "admin")
            except Exception:
                pass

    def login(self, user_id: str, password: str) -> str:
        with self._lock:
            return self.auth.login(user_id, password)

    def create_user(self, token: str, user_id: str, password: str, role: str = "operator") -> dict:
        with self._lock:
            self.auth.require(token, "admin")
            user = self.auth.create_user(user_id, password, role)
            return {"user_id": user.user_id, "role": user.role, "active": user.active}

    def deactivate_user(self, token: str, user_id: str) -> dict:
        with self._lock:
            self.auth.require(token, "admin")
            if not self.db.execute("SELECT 1 FROM users WHERE user_id=?", (user_id,)).fetchone():
                raise KeyError(user_id)
            self.auth.deactivate(user_id)
            return {"user_id": user_id, "active": False}

    def create_lot(self, token: str, lot_id: str, product: str, process_rev: str, wafer_count: int) -> dict:
        with self._lock:
            actor = self.auth.require(token, "submit")
            if wafer_count <= 0 or not lot_id.strip() or not process_rev.strip():
                raise ValueError("lot fields are invalid")
            now = utcnow()
            with transaction(self.db):
                self.db.execute("INSERT INTO chip_lots VALUES(?,?,?,?,?,?,?,?)", (lot_id, product, process_rev, wafer_count, "engineering", actor.user_id, now, now))
                event(self.db, lot_id, "created", actor.user_id, {"product": product, "process_rev": process_rev})
            return self.get_lot(token, lot_id)

    def get_lot(self, token: str, lot_id: str) -> dict:
        with self._lock:
            self.auth.require(token, "read")
            row = self.db.execute("SELECT * FROM chip_lots WHERE lot_id=?", (lot_id,)).fetchone()
            if not row:
                raise KeyError(lot_id)
            return dict(row)

    def add_measurement(self, token: str, lot_id: str, wavelength_nm: float, response: float, noise: float, instrument: str) -> dict:
        with self._lock:
            actor = self.auth.require(token, "measure")
            measurement_id = uuid.uuid4().hex
            with transaction(self.db):
                if not self.db.execute("SELECT 1 FROM chip_lots WHERE lot_id=?", (lot_id,)).fetchone():
                    raise KeyError(lot_id)
                self.db.execute("INSERT INTO measurements VALUES(?,?,?,?,?,?,?,?)", (measurement_id, lot_id, float(wavelength_nm), float(response), float(noise), instrument, actor.user_id, utcnow()))
                event(self.db, lot_id, "measurement", actor.user_id, {"measurement_id": measurement_id, "wavelength_nm": wavelength_nm})
            return {"measurement_id": measurement_id, "lot_id": lot_id}

    def analyze(self, token: str, lot_id: str) -> dict:
        with self._lock:
            self.auth.require(token, "analyze")
            rows = self.db.execute("SELECT wavelength_nm,response FROM measurements WHERE lot_id=? ORDER BY wavelength_nm", (lot_id,)).fetchall()
            if len(rows) < 3:
                raise ValueError("three measurements are required")
            summary = summarize_spectrum([r[0] for r in rows], [r[1] for r in rows])
            rates = yield_rate(self.get_lot(token, lot_id)["wafer_count"], sum(1 for r in rows if r[1] >= 0.8), 0)
            ci = confidence_interval([r[1] for r in rows])
            return {"lot_id": lot_id, "spectrum": summary.__dict__, "yield": rates, "response_ci": ci}

    def approve(self, token: str, lot_id: str, decision: str, reason: str) -> dict:
        with self._lock:
            actor = self.auth.require(token, "release" if decision == "release" else "approve")
            if decision not in {"release", "hold", "reject"} or not reason.strip():
                raise ValueError("decision and reason are required")
            with transaction(self.db):
                if not self.db.execute("SELECT 1 FROM chip_lots WHERE lot_id=?", (lot_id,)).fetchone():
                    raise KeyError(lot_id)
                self.db.execute("INSERT OR REPLACE INTO approvals VALUES(?,?,?,?,?)", (lot_id, actor.user_id, decision, reason, utcnow()))
                status = {"release": "released", "hold": "hold", "reject": "rejected"}[decision]
                self.db.execute("UPDATE chip_lots SET status=?,updated_at=? WHERE lot_id=?", (status, utcnow(), lot_id))
                event(self.db, lot_id, "approval", actor.user_id, {"decision": decision, "reason": reason})
            return self.get_lot(token, lot_id)

    def audit(self, token: str, lot_id: str) -> list[dict]:
        with self._lock:
            self.auth.require(token, "read")
            return [dict(r) for r in self.db.execute("SELECT * FROM lot_events WHERE lot_id=? ORDER BY event_id", (lot_id,)).fetchall()]

    def verify_audit(self, token: str) -> dict:
        with self._lock:
            self.auth.require(token, "read")
            return verify_chain(self.db)
