"""光电芯片服务放行门禁、会话失效和审计链的 HTTP 级验证。"""

from __future__ import annotations

import json
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

from photon_fab.api import Handler
from photon_fab.service import PhotonService

PASSWORD = "pass-word-123"


class PhotonApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.service = PhotonService()
        cls.service.bootstrap_admin()
        handler = type("TestHandler", (Handler,), {
            "service": cls.service,
            "log_message": lambda self, *args: None,
        })
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"
        status, body = cls.call("POST", "/login", {"user_id": "admin", "password": "photon-admin"})
        assert status == 200, body
        cls.admin = body["token"]
        cls.tokens = {}
        for user_id, role in (("op-1", "operator"), ("eng-1", "engineer"), ("qa-1", "quality")):
            status, body = cls.call("POST", "/users", {"user_id": user_id, "password": PASSWORD, "role": role}, cls.admin)
            assert status == 201, body
            status, body = cls.call("POST", "/login", {"user_id": user_id, "password": PASSWORD})
            assert status == 200, body
            cls.tokens[user_id] = body["token"]

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)

    @classmethod
    def call(cls, method, path, body=None, token=None):
        data = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(cls.base + path, data=data, method=method)
        if token:
            request.add_header("Authorization", f"Bearer {token}")
        try:
            with urllib.request.urlopen(request) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())

    def make_lot(self, lot_id: str) -> None:
        status, body = self.call("POST", "/lots", {"lot_id": lot_id, "product": "edge coupler", "process_rev": "P4.0", "wafer_count": 8}, self.admin)
        self.assertEqual(status, 201, body)
        for wavelength, response in ((450, .71), (520, .93), (650, .84)):
            status, body = self.call("POST", f"/lots/{lot_id}/measurements",
                                     {"wavelength_nm": wavelength, "response": response, "noise": .01, "instrument": "spectrometer-1"},
                                     self.tokens["op-1"])
            self.assertEqual(status, 201, body)

    def lot_status(self, lot_id: str) -> str:
        status, body = self.call("GET", f"/lots/{lot_id}", token=self.admin)
        self.assertEqual(status, 200, body)
        return body["status"]

    def test_health(self):
        status, body = self.call("GET", "/health")
        self.assertEqual((status, body["status"]), (200, "ok"))

    def test_operator_cannot_release(self):
        self.make_lot("LOT-OP")
        for decision in ("release", "hold", "reject"):
            status, body = self.call("POST", "/lots/LOT-OP/release", {"decision": decision, "reason": "line request"}, self.tokens["op-1"])
            self.assertEqual(status, 403, body)
            self.assertEqual(body, {"error": "permission denied"})
        self.assertEqual(self.lot_status("LOT-OP"), "engineering")

    def test_engineer_cannot_release(self):
        self.make_lot("LOT-ENG")
        for decision in ("release", "hold", "reject"):
            status, body = self.call("POST", "/lots/LOT-ENG/release", {"decision": decision, "reason": "line request"}, self.tokens["eng-1"])
            self.assertEqual(status, 403, body)
            self.assertEqual(body, {"error": "permission denied"})
        self.assertEqual(self.lot_status("LOT-ENG"), "engineering")

    def test_rejection_is_stable_for_any_decision_value(self):
        self.make_lot("LOT-STABLE")
        for token in (self.tokens["op-1"], self.tokens["eng-1"]):
            first = self.call("POST", "/lots/LOT-STABLE/release", {"decision": "release", "reason": "x"}, token)
            second = self.call("POST", "/lots/LOT-STABLE/release", {"decision": "bogus", "reason": "x"}, token)
            self.assertEqual(first, second)
            self.assertEqual(first[0], 403)

    def test_quality_can_release(self):
        self.make_lot("LOT-QA")
        status, body = self.call("POST", "/lots/LOT-QA/release", {"decision": "release", "reason": "review passed"}, self.tokens["qa-1"])
        self.assertEqual(status, 200, body)
        self.assertEqual(body["status"], "released")
        self.assertEqual(self.lot_status("LOT-QA"), "released")

    def test_admin_can_release(self):
        self.make_lot("LOT-ADMIN")
        status, body = self.call("POST", "/lots/LOT-ADMIN/release", {"decision": "release", "reason": "expedited"}, self.admin)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["status"], "released")

    def test_release_requires_authentication(self):
        self.make_lot("LOT-ANON")
        status, body = self.call("POST", "/lots/LOT-ANON/release", {"decision": "release", "reason": "x"})
        self.assertEqual(status, 403)
        self.assertEqual(self.lot_status("LOT-ANON"), "engineering")

    def test_release_unknown_lot_is_client_error(self):
        status, _ = self.call("POST", "/lots/LOT-MISSING/release", {"decision": "release", "reason": "x"}, self.tokens["qa-1"])
        self.assertEqual(status, 400)

    def test_deactivated_user_session_expires_immediately(self):
        status, _ = self.call("POST", "/users", {"user_id": "temp-eng", "password": PASSWORD, "role": "engineer"}, self.admin)
        self.assertEqual(status, 201)
        status, body = self.call("POST", "/login", {"user_id": "temp-eng", "password": PASSWORD})
        self.assertEqual(status, 200)
        token = body["token"]
        self.make_lot("LOT-DEACT")
        status, _ = self.call("GET", "/lots/LOT-DEACT", token=token)
        self.assertEqual(status, 200)

        status, body = self.call("POST", "/users/temp-eng/deactivate", token=self.admin)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["active"], False)

        for method, path, payload in (
            ("GET", "/lots/LOT-DEACT", None),
            ("POST", "/lots/LOT-DEACT/measurements", {"wavelength_nm": 500, "response": .9, "instrument": "spectrometer-1"}),
            ("POST", "/lots/LOT-DEACT/release", {"decision": "release", "reason": "x"}),
        ):
            first = self.call(method, path, payload, token)
            second = self.call(method, path, payload, token)
            self.assertEqual(first, second)
            self.assertEqual(first[0], 403)
        status, _ = self.call("POST", "/login", {"user_id": "temp-eng", "password": PASSWORD})
        self.assertEqual(status, 403)

    def test_user_management_requires_admin(self):
        status, _ = self.call("POST", "/users", {"user_id": "ghost", "password": PASSWORD}, self.tokens["op-1"])
        self.assertEqual(status, 403)
        status, _ = self.call("POST", "/users/op-1/deactivate", token=self.tokens["eng-1"])
        self.assertEqual(status, 403)

    def test_decisions_are_written_to_audit_chain(self):
        self.make_lot("LOT-AUDIT")
        status, _ = self.call("POST", "/lots/LOT-AUDIT/release", {"decision": "release", "reason": "review passed"}, self.tokens["qa-1"])
        self.assertEqual(status, 200)

        status, body = self.call("GET", "/lots/LOT-AUDIT/audit", token=self.tokens["qa-1"])
        self.assertEqual(status, 200, body)
        events = body["events"]
        approvals = [e for e in events if e["event_type"] == "approval"]
        self.assertEqual(len(approvals), 1)
        self.assertEqual(approvals[0]["actor"], "qa-1")
        self.assertEqual(json.loads(approvals[0]["payload"]), {"decision": "release", "reason": "review passed"})
        for event in events:
            self.assertEqual(len(event["event_hash"]), 64)
            self.assertEqual(len(event["previous_hash"]), 64)

        status, body = self.call("GET", "/audit/verify", token=self.tokens["op-1"])
        self.assertEqual(status, 200, body)
        self.assertTrue(body["valid"], body)
        self.assertGreaterEqual(body["events"], len(events))

    def test_audit_chain_detects_tampering(self):
        self.make_lot("LOT-TAMPER")
        status, body = self.call("GET", "/audit/verify", token=self.admin)
        self.assertTrue(body["valid"], body)

        row = self.service.db.execute("SELECT event_id,actor FROM lot_events ORDER BY event_id DESC LIMIT 1").fetchone()
        self.service.db.execute("UPDATE lot_events SET actor='mallory' WHERE event_id=?", (row["event_id"],))
        self.service.db.commit()
        try:
            status, body = self.call("GET", "/audit/verify", token=self.admin)
            self.assertEqual(status, 200)
            self.assertFalse(body["valid"], body)
        finally:
            self.service.db.execute("UPDATE lot_events SET actor=? WHERE event_id=?", (row["actor"], row["event_id"]))
            self.service.db.commit()
        status, body = self.call("GET", "/audit/verify", token=self.admin)
        self.assertTrue(body["valid"], body)

    def test_measurements_and_analysis_still_work(self):
        self.make_lot("LOT-INTACT")
        status, body = self.call("POST", "/lots/LOT-INTACT/analysis", token=self.tokens["eng-1"])
        self.assertEqual(status, 200, body)
        self.assertEqual(body["lot_id"], "LOT-INTACT")
        self.assertEqual(body["spectrum"]["peak_wavelength_nm"], 520.0)
        self.assertIn("yield", body)
        self.assertIn("response_ci", body)
        status, _ = self.call("POST", "/lots/LOT-INTACT/analysis", token=self.tokens["op-1"])
        self.assertEqual(status, 403)
        status, body = self.call("GET", "/lots/LOT-INTACT", token=self.tokens["op-1"])
        self.assertEqual(status, 200, body)
        self.assertEqual(body["status"], "engineering")


if __name__ == "__main__":
    unittest.main()
