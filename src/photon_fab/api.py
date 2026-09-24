"""用于离线验收的无依赖 JSON HTTP API。"""

from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .service import PhotonService


class Handler(BaseHTTPRequestHandler):
    service = PhotonService()

    def _json(self, status: int, body: dict) -> None:
        data = json.dumps(body, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _token(self) -> str:
        return self.headers.get("Authorization", "").removeprefix("Bearer ")

    def do_GET(self):
        try:
            if self.path == "/health":
                return self._json(200, {"status": "ok", "service": "photon-fab"})
            token = self._token()
            if self.path == "/audit/verify":
                return self._json(200, self.service.verify_audit(token))
            if self.path.startswith("/lots/") and self.path.endswith("/audit"):
                lot_id = self.path.split("/")[2]
                return self._json(200, {"lot_id": lot_id, "events": self.service.audit(token, lot_id)})
            if self.path.startswith("/lots/"):
                return self._json(200, self.service.get_lot(token, self.path.split("/", 2)[2]))
            return self._json(404, {"error": "not found"})
        except PermissionError as exc:
            return self._json(403, {"error": str(exc)})
        except Exception as exc:
            return self._json(400, {"error": str(exc)})

    def do_POST(self):
        try:
            raw = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            body = json.loads(raw) if raw.strip() else {}
            if self.path == "/login":
                return self._json(200, {"token": self.service.login(body["user_id"], body["password"])})
            token = self._token()
            if self.path == "/users":
                return self._json(201, self.service.create_user(token, body["user_id"], body["password"], body.get("role", "operator")))
            if self.path.startswith("/users/") and self.path.endswith("/deactivate"):
                return self._json(200, self.service.deactivate_user(token, self.path.split("/")[2]))
            if self.path == "/lots":
                return self._json(201, self.service.create_lot(token, body["lot_id"], body["product"], body["process_rev"], body["wafer_count"]))
            if self.path.startswith("/lots/") and self.path.endswith("/measurements"):
                lot_id = self.path.split("/")[2]
                return self._json(201, self.service.add_measurement(token, lot_id, body["wavelength_nm"], body["response"], body.get("noise", 0.0), body["instrument"]))
            if self.path.startswith("/lots/") and self.path.endswith("/analysis"):
                return self._json(200, self.service.analyze(token, self.path.split("/")[2]))
            if self.path.startswith("/lots/") and self.path.endswith("/release"):
                return self._json(200, self.service.approve(token, self.path.split("/")[2], body["decision"], body["reason"]))
            return self._json(404, {"error": "not found"})
        except PermissionError as exc:
            return self._json(403, {"error": str(exc)})
        except Exception as exc:
            return self._json(400, {"error": str(exc)})


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", default=":memory:")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    Handler.service = PhotonService(args.database)
    Handler.service.bootstrap_admin()
    ThreadingHTTPServer((args.host, args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
