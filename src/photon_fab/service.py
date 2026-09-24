"""协调认证、批次、测试、质量复核和放行门禁的应用服务。"""

from __future__ import annotations

import uuid

from .analytics import confidence_interval, summarize_spectrum, yield_rate
from .auth import ROLES, Auth
from .errors import Conflict, ValidationFailed
from .storage import connect, record_event, transaction, utcnow, verify_chain


class PhotonService:
    def __init__(self, database: str = ":memory:"):
        self.db = connect(database)
        self.auth = Auth(self.db)

    def bootstrap_admin(self, user_id: str = "admin", password: str = "photon-admin") -> None:
        try:
            self.auth.create_user(user_id, password, "admin")
            self.db.commit()
        except Exception:
            self.db.rollback()

    # ---- 用户管理（仅管理员） ----

    def create_user(self, token: str, user_id: str, password: str, role: str) -> dict:
        actor = self.auth.require(token, "admin")
        if not user_id.strip() or role not in ROLES:
            raise ValidationFailed("user_id and valid role are required")
        with transaction(self.db):
            user = self.auth.create_user(user_id, password, role)
            record_event(self.db, "user", user_id, "user.created", actor.user_id, {"role": role})
        return {"user_id": user.user_id, "role": user.role, "active": user.active}

    def deactivate_user(self, token: str, user_id: str) -> dict:
        actor = self.auth.require(token, "admin")
        row = self.db.execute("SELECT role,active FROM users WHERE user_id=?", (user_id,)).fetchone()
        if not row:
            raise KeyError(user_id)
        with transaction(self.db):
            self.auth.deactivate(user_id)
            record_event(self.db, "user", user_id, "user.deactivated", actor.user_id, {"role": row[0]})
        return {"user_id": user_id, "active": False}

    # ---- 批次 ----

    def create_lot(self, token: str, lot_id: str, product: str, process_rev: str, wafer_count: int) -> dict:
        actor = self.auth.require(token, "submit")
        if wafer_count <= 0 or not lot_id.strip() or not process_rev.strip():
            raise ValidationFailed("lot fields are invalid")
        now = utcnow()
        with transaction(self.db):
            self.db.execute("INSERT INTO chip_lots VALUES(?,?,?,?,?,?,?,?)", (lot_id, product, process_rev, wafer_count, "engineering", actor.user_id, now, now))
            record_event(self.db, "lot", lot_id, "lot.created", actor.user_id, {"product": product, "process_rev": process_rev, "wafer_count": wafer_count})
        return self.get_lot(token, lot_id)

    def get_lot(self, token: str, lot_id: str) -> dict:
        self.auth.require(token, "read")
        return self._lot(lot_id)

    def _lot(self, lot_id: str) -> dict:
        row = self.db.execute("SELECT * FROM chip_lots WHERE lot_id=?", (lot_id,)).fetchone()
        if not row:
            raise KeyError(lot_id)
        return dict(row)

    # ---- 测量与分析（权限保持基线不变） ----

    def add_measurement(self, token: str, lot_id: str, wavelength_nm: float, response: float, noise: float, instrument: str) -> dict:
        actor = self.auth.require(token, "measure")
        measurement_id = uuid.uuid4().hex
        with transaction(self.db):
            if not self.db.execute("SELECT 1 FROM chip_lots WHERE lot_id=?", (lot_id,)).fetchone():
                raise KeyError(lot_id)
            self.db.execute("INSERT INTO measurements VALUES(?,?,?,?,?,?,?,?)", (measurement_id, lot_id, float(wavelength_nm), float(response), float(noise), instrument, actor.user_id, utcnow()))
            record_event(self.db, "lot", lot_id, "measurement.recorded", actor.user_id, {"measurement_id": measurement_id, "wavelength_nm": wavelength_nm, "response": float(response), "noise": float(noise), "instrument": instrument})
        return {"measurement_id": measurement_id, "lot_id": lot_id}

    def analyze(self, token: str, lot_id: str) -> dict:
        self.auth.require(token, "analyze")
        rows = self.db.execute("SELECT wavelength_nm,response FROM measurements WHERE lot_id=? ORDER BY wavelength_nm", (lot_id,)).fetchall()
        if len(rows) < 3:
            raise ValidationFailed("three measurements are required")
        summary = summarize_spectrum([r[0] for r in rows], [r[1] for r in rows])
        rates = yield_rate(self.get_lot(token, lot_id)["wafer_count"], sum(1 for r in rows if r[1] >= 0.8), 0)
        ci = confidence_interval([r[1] for r in rows])
        return {"lot_id": lot_id, "spectrum": summary.__dict__, "yield": rates, "response_ci": ci}

    # ---- 质量复核 ----

    def review(self, token: str, lot_id: str, result: str, note: str) -> dict:
        actor = self.auth.require(token, "review")
        if result not in {"pass", "fail"} or not note.strip():
            raise ValidationFailed("result (pass|fail) and note are required")
        with transaction(self.db):
            lot = self._lot(lot_id)
            if lot["status"] in {"released", "rejected"}:
                raise Conflict(f"lot is {lot['status']} and cannot be reviewed")
            now = utcnow()
            cur = self.db.execute(
                "INSERT INTO quality_reviews(lot_id,reviewer,result,note,created_at) VALUES(?,?,?,?,?)",
                (lot_id, actor.user_id, result, note, now),
            )
            review_id = cur.lastrowid
            record_event(self.db, "lot", lot_id, "quality.reviewed", actor.user_id, {"review_id": review_id, "result": result, "note": note})
        return {"review_id": review_id, "lot_id": lot_id, "reviewer": actor.user_id, "result": result}

    # ---- 放行决定 ----

    TERMINAL_STATUSES = {"released", "rejected"}
    DECISION_STATUS = {"release": "released", "hold": "hold", "reject": "rejected"}

    def approve(self, token: str, lot_id: str, decision: str, reason: str) -> dict:
        # 只有质量角色和管理员持有 approve 权限；操作员和工程师在此被稳定拒绝（403）。
        actor = self.auth.require(token, "approve")
        if decision not in self.DECISION_STATUS or not reason.strip():
            raise ValidationFailed("decision (release|hold|reject) and reason are required")
        with transaction(self.db):
            lot = self._lot(lot_id)
            if lot["status"] in self.TERMINAL_STATUSES:
                raise Conflict(f"lot is already {lot['status']}")
            if decision == "release":
                review = self.db.execute(
                    "SELECT result FROM quality_reviews WHERE lot_id=? ORDER BY review_id DESC LIMIT 1",
                    (lot_id,),
                ).fetchone()
                # 未完成质量复核（无复核记录或最新结论不是 pass）的批次禁止放行。
                if not review or review["result"] != "pass":
                    raise Conflict("lot has not passed quality review")
            now = utcnow()
            cur = self.db.execute(
                "INSERT INTO approval_decisions(lot_id,reviewer,decision,reason,created_at) VALUES(?,?,?,?,?)",
                (lot_id, actor.user_id, decision, reason, now),
            )
            decision_id = cur.lastrowid
            status = self.DECISION_STATUS[decision]
            self.db.execute("UPDATE chip_lots SET status=?,updated_at=? WHERE lot_id=?", (status, now, lot_id))
            record_event(self.db, "lot", lot_id, f"approval.{decision}", actor.user_id, {"decision_id": decision_id, "decision": decision, "reason": reason, "previous_status": lot["status"], "status": status})
        return self.get_lot(token, lot_id)

    # ---- 审计 ----

    def audit(self, token: str, lot_id: str) -> list[dict]:
        self.auth.require(token, "read")
        if not self.db.execute("SELECT 1 FROM chip_lots WHERE lot_id=?", (lot_id,)).fetchone():
            raise KeyError(lot_id)
        return [
            {"event_id": r["event_id"], "lot_id": r["entity_id"], "event_type": r["event_type"],
             "actor": r["actor"], "payload": r["payload"], "created_at": r["created_at"],
             "previous_hash": r["previous_hash"], "event_hash": r["event_hash"]}
            for r in self.db.execute(
                "SELECT * FROM audit_events WHERE entity_type='lot' AND entity_id=? ORDER BY event_id",
                (lot_id,),
            ).fetchall()
        ]

    def audit_chain(self, token: str) -> dict:
        self.auth.require(token, "read")
        return verify_chain(self.db)
