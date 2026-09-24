"""photon_fab 放行门禁的端到端 HTTP 测试。

全部断言通过真实 HTTP 请求（ThreadingHTTPServer + urllib）发出，
验证角色边界、批次状态机、会话失效和哈希链审计。
"""

from __future__ import annotations

import json
import re
import sqlite3
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from photon_fab.api import build_server
from photon_fab.service import PhotonService


class HttpSession:
    def __init__(self, base: str, token: str | None = None):
        self.base = base
        self.token = token

    def request(self, method: str, path: str, body: dict | None = None) -> tuple[int, dict]:
        data = json.dumps(body).encode() if body is not None else None
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        req = urllib.request.Request(self.base + path, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())

    def login(self, user_id: str, password: str) -> "HttpSession":
        status, body = self.request("POST", "/login", {"user_id": user_id, "password": password})
        assert status == 200, body
        return HttpSession(self.base, body["token"])


class ReleaseGateHttpTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.tmp.name) / "photon.sqlite3")
        service = PhotonService(self.db_path)
        service.bootstrap_admin()
        self.server = build_server(service, "127.0.0.1", 0)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.http = HttpSession(f"http://127.0.0.1:{self.port}")
        self.admin = self.http.login("admin", "photon-admin")
        for uid, role in (("op-1", "operator"), ("eng-1", "engineer"), ("qa-1", "quality")):
            status, _ = self.admin.request("POST", "/users", {"user_id": uid, "password": "password123", "role": role})
            self.assertEqual(status, 201)
        self.operator = self.http.login("op-1", "password123")
        self.engineer = self.http.login("eng-1", "password123")
        self.quality = self.http.login("qa-1", "password123")

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        self.tmp.cleanup()

    def _create_lot(self, lot_id: str, client: HttpSession | None = None) -> None:
        client = client or self.admin
        status, body = client.request("POST", "/lots", {
            "lot_id": lot_id, "product": "PD-array", "process_rev": "P3.2", "wafer_count": 12,
        })
        self.assertEqual(status, 201, body)

    def _measure(self, lot_id: str, client: HttpSession) -> None:
        for wavelength, response in ((450, .72), (520, .94), (650, .85)):
            status, body = client.request("POST", f"/lots/{lot_id}/measurements", {
                "wavelength_nm": wavelength, "response": response, "noise": .01, "instrument": "spec-1",
            })
            self.assertEqual(status, 201, body)

    # ---- 认证与角色边界 ----

    def test_health_and_login_failures(self) -> None:
        status, body = self.http.request("GET", "/health")
        self.assertEqual(status, 200)
        self.assertEqual(body["status"], "ok")
        status, _ = self.http.request("POST", "/login", {"user_id": "admin", "password": "wrong"})
        self.assertEqual(status, 401)
        status, _ = self.http.request("GET", "/lots/LOT-X")
        self.assertEqual(status, 401)
        status, _ = HttpSession(f"http://127.0.0.1:{self.port}", "bogus-token").request("GET", "/lots/LOT-X")
        self.assertEqual(status, 401)

    def test_operator_and_engineer_cannot_release_or_review(self) -> None:
        self._create_lot("LOT-A")
        self._measure("LOT-A", self.operator)
        for client in (self.operator, self.engineer):
            status, body = client.request("POST", "/lots/LOT-A/reviews", {"result": "pass", "note": "ok"})
            self.assertEqual(status, 403, body)
            status, body = client.request("POST", "/lots/LOT-A/decisions", {"decision": "release", "reason": "go"})
            self.assertEqual(status, 403, body)
            self.assertIn("error", body)
        # 被拒后批次必须仍处于 engineering，下游不会看到 released
        status, lot = self.admin.request("GET", "/lots/LOT-A")
        self.assertEqual(lot["status"], "engineering")

    def test_measure_and_analysis_interfaces_intact(self) -> None:
        self._create_lot("LOT-M")
        self._measure("LOT-M", self.operator)  # 操作员仍可测量
        status, body = self.operator.request("POST", "/lots/LOT-M/analysis", {})
        self.assertEqual(status, 403)  # 操作员本就无分析权限，保持基线
        status, analysis = self.engineer.request("POST", "/lots/LOT-M/analysis", {})
        self.assertEqual(status, 200, analysis)  # 工程师分析不受影响
        self.assertEqual(analysis["spectrum"]["peak_wavelength_nm"], 520.0)
        status, analysis = self.quality.request("POST", "/lots/LOT-M/analysis", {})
        self.assertEqual(status, 200)

    def test_only_admin_can_manage_users(self) -> None:
        for client in (self.operator, self.engineer, self.quality):
            status, _ = client.request("POST", "/users", {"user_id": "x", "password": "password123", "role": "operator"})
            self.assertEqual(status, 403)
        status, body = self.admin.request("POST", "/users", {"user_id": "op-2", "password": "short", "role": "operator"})
        self.assertEqual(status, 400)

    # ---- 批次状态门禁 ----

    def test_release_blocked_before_quality_review(self) -> None:
        self._create_lot("LOT-B")
        self._measure("LOT-B", self.operator)
        # 质量人员也不能在复核完成前放行
        status, body = self.quality.request("POST", "/lots/LOT-B/decisions", {"decision": "release", "reason": "trust me"})
        self.assertEqual(status, 409, body)
        status, lot = self.quality.request("GET", "/lots/LOT-B")
        self.assertEqual(lot["status"], "engineering")

    def test_failed_review_blocks_release_but_hold_works(self) -> None:
        self._create_lot("LOT-C")
        status, _ = self.quality.request("POST", "/lots/LOT-C/reviews", {"result": "fail", "note": "noise too high"})
        self.assertEqual(status, 201)
        status, body = self.quality.request("POST", "/lots/LOT-C/decisions", {"decision": "release", "reason": "anyway"})
        self.assertEqual(status, 409, body)
        status, lot = self.quality.request("POST", "/lots/LOT-C/decisions", {"decision": "hold", "reason": "rework"})
        self.assertEqual(status, 200, body)
        self.assertEqual(lot["status"], "hold")

    def test_full_pass_then_release_is_terminal(self) -> None:
        self._create_lot("LOT-D")
        self._measure("LOT-D", self.engineer)
        status, _ = self.quality.request("POST", "/lots/LOT-D/reviews", {"result": "pass", "note": "within spec"})
        self.assertEqual(status, 201)
        status, lot = self.quality.request("POST", "/lots/LOT-D/decisions", {"decision": "release", "reason": "review passed"})
        self.assertEqual(status, 200, lot)
        self.assertEqual(lot["status"], "released")
        # 终态批次拒绝新的复核与决定
        status, body = self.quality.request("POST", "/lots/LOT-D/reviews", {"result": "pass", "note": "again"})
        self.assertEqual(status, 409, body)
        status, body = self.admin.request("POST", "/lots/LOT-D/decisions", {"decision": "hold", "reason": "late"})
        self.assertEqual(status, 409, body)

    def test_admin_may_release_after_review(self) -> None:
        self._create_lot("LOT-E")
        status, _ = self.quality.request("POST", "/lots/LOT-E/reviews", {"result": "pass", "note": "ok"})
        self.assertEqual(status, 201)
        status, lot = self.admin.request("POST", "/lots/LOT-E/decisions", {"decision": "release", "reason": "admin override after review"})
        self.assertEqual(status, 200)
        self.assertEqual(lot["status"], "released")

    def test_unknown_lot_and_validation_shapes(self) -> None:
        status, _ = self.quality.request("POST", "/lots/NOPE/decisions", {"decision": "release", "reason": "x"})
        self.assertEqual(status, 404)
        self._create_lot("LOT-V")
        status, _ = self.quality.request("POST", "/lots/LOT-V/decisions", {"decision": "release", "reason": "   "})
        self.assertEqual(status, 422)
        status, _ = self.quality.request("POST", "/lots/LOT-V/decisions", {"decision": "ship-it", "reason": "x"})
        self.assertEqual(status, 422)
        # 缺少必填字段同样是 422，而不是被误判成 404
        status, _ = self.admin.request("POST", "/lots", {"lot_id": "LOT-Z"})
        self.assertEqual(status, 422)

    # ---- 停用即失效 ----

    def test_deactivated_user_sessions_fail_immediately(self) -> None:
        self._create_lot("LOT-S")
        # 停用前工程师的会话可用
        status, _ = self.engineer.request("POST", "/lots/LOT-S/measurements", {
            "wavelength_nm": 520, "response": .9, "noise": .01, "instrument": "spec-1"})
        self.assertEqual(status, 201)
        status, _ = self.admin.request("POST", "/users/eng-1/deactivate", {})
        self.assertEqual(status, 200)
        # 旧 token 立即失效：读、写一律 401，而不是 403
        status, body = self.engineer.request("GET", "/lots/LOT-S")
        self.assertEqual(status, 401, body)
        status, body = self.engineer.request("POST", "/lots/LOT-S/analysis", {})
        self.assertEqual(status, 401, body)
        # 停用后也不能再登录换新会话
        status, _ = self.http.request("POST", "/login", {"user_id": "eng-1", "password": "password123"})
        self.assertEqual(status, 401)
        # 其他用户不受影响
        status, _ = self.operator.request("GET", "/lots/LOT-S")
        self.assertEqual(status, 200)

    # ---- 哈希链审计 ----

    def test_decisions_are_append_only_and_chain_verifies(self) -> None:
        self._create_lot("LOT-F")
        self._measure("LOT-F", self.operator)
        self.quality.request("POST", "/lots/LOT-F/reviews", {"result": "pass", "note": "ok"})
        self.quality.request("POST", "/lots/LOT-F/decisions", {"decision": "release", "reason": "done"})
        status, chain = self.admin.request("GET", "/audit-chain")
        self.assertEqual(status, 200)
        self.assertTrue(chain["valid"], chain)
        self.assertGreater(chain["events"], 0)
        status, audit = self.admin.request("GET", "/lots/LOT-F/audit")
        self.assertEqual(status, 200)
        events = audit["events"]
        types = [e["event_type"] for e in events]
        self.assertIn("quality.reviewed", types)
        self.assertIn("approval.release", types)
        # 事件按 event_id 递增、哈希前后相接（全局链在该批次之前还有用户创建事件）
        self.assertEqual([e["event_id"] for e in events], sorted(e["event_id"] for e in events))
        self.assertRegex(events[0]["previous_hash"], r"^[0-9a-f]{64}$")
        for previous, current in zip(events, events[1:]):
            self.assertEqual(current["previous_hash"], previous["event_hash"])
        for event in events:  # 每个事件都带链指针与哈希
            self.assertEqual(len(event["previous_hash"]), 64)
            self.assertEqual(len(event["event_hash"]), 64)

    def test_tampering_with_history_breaks_chain(self) -> None:
        self._create_lot("LOT-G")
        self._measure("LOT-G", self.operator)
        self.quality.request("POST", "/lots/LOT-G/reviews", {"result": "fail", "note": "bad"})
        self.quality.request("POST", "/lots/LOT-G/decisions", {"decision": "hold", "reason": "quarantine"})
        # 入侵者试图把历史决定从 hold 改写成 release
        db = sqlite3.connect(self.db_path)
        db.execute("UPDATE approval_decisions SET decision='release' WHERE lot_id='LOT-G'")
        db.commit()
        db.close()
        # 决定表只增不改：批次状态不会因此变化
        status, lot = self.admin.request("GET", "/lots/LOT-G")
        self.assertEqual(lot["status"], "hold")
        # 直接篡改审计载荷则哈希链立刻失效
        db = sqlite3.connect(self.db_path)
        db.execute("UPDATE audit_events SET payload=? WHERE event_type='approval.hold'",
                   (json.dumps({"decision": "release"}, sort_keys=True),))
        db.commit()
        db.close()
        status, chain = self.admin.request("GET", "/audit-chain")
        self.assertEqual(status, 200)
        self.assertFalse(chain["valid"])


if __name__ == "__main__":
    unittest.main()
