"""用于离线验收的无依赖 JSON HTTP API。

路由（除 /health 与 /login 外均需 ``Authorization: Bearer <token>``）：

- ``POST /login``                       登录换取会话令牌
- ``POST /users``                       管理员创建用户
- ``POST /users/{user_id}/deactivate``  管理员停用用户（旧会话立即失效）
- ``POST /lots``                        建立批次（工程师/管理员）
- ``GET  /lots/{lot_id}``               查询批次
- ``POST /lots/{lot_id}/measurements``  录入测量（操作员及以上）
- ``POST /lots/{lot_id}/analysis``      光谱分析（工程师及以上）
- ``POST /lots/{lot_id}/reviews``       质量复核（质量/管理员）
- ``POST /lots/{lot_id}/decisions``     放行决定 release/hold/reject（质量/管理员）
- ``GET  /lots/{lot_id}/audit``         批次审计事件（含哈希）
- ``GET  /audit-chain``                 全链完整性校验结果
"""

from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .errors import Conflict, Forbidden, Unauthorized, ValidationFailed
from .service import PhotonService


class Handler(BaseHTTPRequestHandler):
    service: PhotonService = PhotonService()

    def log_message(self, format: str, *args) -> None:  # noqa: A002 - 保持测试输出安静
        return

    def _json(self, status: int, body: dict | list) -> None:
        data = json.dumps(body, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _token(self) -> str:
        header = self.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            raise Unauthorized("bearer token required")
        return header.removeprefix("Bearer ").strip()

    def _body(self) -> dict:
        raw = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        if not raw:
            return {}
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValidationFailed(f"invalid JSON body: {exc}") from exc
        if not isinstance(parsed, dict):
            raise ValidationFailed("JSON body must be an object")
        return parsed

    @staticmethod
    def _field(body: dict, name: str, required: bool = True, default=None):
        if name not in body:
            if required:
                raise ValidationFailed(f"field {name!r} is required")
            return default
        return body[name]

    def _fail(self, exc: Exception) -> None:
        if isinstance(exc, Unauthorized):
            self._json(401, {"error": str(exc)})
        elif isinstance(exc, Forbidden):
            # 已认证但角色越界：对操作员/工程师的放行尝试给出稳定的 403 响应。
            self._json(403, {"error": str(exc)})
        elif isinstance(exc, KeyError):
            self._json(404, {"error": f"not found: {exc.args[0]}"})
        elif isinstance(exc, Conflict):
            self._json(409, {"error": str(exc)})
        elif isinstance(exc, ValidationFailed):
            self._json(422, {"error": str(exc)})
        else:
            self._json(400, {"error": str(exc)})

    # ---- GET ----

    def do_GET(self) -> None:  # noqa: N802 - http.server 接口
        try:
            if self.path == "/health":
                return self._json(200, {"status": "ok", "service": "photon-fab"})
            parts = self.path.strip("/").split("/")
            token = self._token()
            if len(parts) == 2 and parts[0] == "lots":
                return self._json(200, self.service.get_lot(token, parts[1]))
            if len(parts) == 3 and parts[0] == "lots" and parts[2] == "audit":
                return self._json(200, {"lot_id": parts[1], "events": self.service.audit(token, parts[1])})
            if self.path == "/audit-chain":
                return self._json(200, self.service.audit_chain(token))
            return self._json(404, {"error": "not found"})
        except Exception as exc:
            self._fail(exc)

    # ---- POST ----

    def do_POST(self) -> None:  # noqa: N802 - http.server 接口
        try:
            body = self._body()
            if self.path == "/login":
                token = self.service.auth.login(self._field(body, "user_id"), self._field(body, "password"))
                return self._json(200, {"token": token})

            token = self._token()
            parts = self.path.strip("/").split("/")

            if self.path == "/users":
                return self._json(201, self.service.create_user(
                    token, self._field(body, "user_id"), self._field(body, "password"),
                    body.get("role", "operator")))
            if len(parts) == 3 and parts[0] == "users" and parts[2] == "deactivate":
                return self._json(200, self.service.deactivate_user(token, parts[1]))

            if self.path == "/lots":
                return self._json(201, self.service.create_lot(
                    token, self._field(body, "lot_id"), self._field(body, "product"),
                    self._field(body, "process_rev"), self._field(body, "wafer_count")))
            if len(parts) == 3 and parts[0] == "lots" and parts[2] == "measurements":
                return self._json(201, self.service.add_measurement(
                    token, parts[1], self._field(body, "wavelength_nm"),
                    self._field(body, "response"), body.get("noise", 0.0),
                    self._field(body, "instrument")))
            if len(parts) == 3 and parts[0] == "lots" and parts[2] == "analysis":
                return self._json(200, self.service.analyze(token, parts[1]))
            if len(parts) == 3 and parts[0] == "lots" and parts[2] == "reviews":
                return self._json(201, self.service.review(
                    token, parts[1], self._field(body, "result"), body.get("note", "")))
            if len(parts) == 3 and parts[0] == "lots" and parts[2] == "decisions":
                return self._json(200, self.service.approve(
                    token, parts[1], self._field(body, "decision"), body.get("reason", "")))
            return self._json(404, {"error": "not found"})
        except Exception as exc:
            self._fail(exc)


def build_server(service: PhotonService, host: str = "127.0.0.1", port: int = 8080) -> ThreadingHTTPServer:
    handler = type("BoundHandler", (Handler,), {"service": service})
    return ThreadingHTTPServer((host, port), handler)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", default=":memory:")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    service = PhotonService(args.database)
    service.bootstrap_admin()
    build_server(service, args.host, args.port).serve_forever()


if __name__ == "__main__":
    main()
