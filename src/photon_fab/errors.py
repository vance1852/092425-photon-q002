"""HTTP 层可稳定映射状态码的领域错误类型。"""

from __future__ import annotations


class Unauthorized(PermissionError):
    """缺少凭证、凭证无效或会话已失效（HTTP 401）。"""


class Forbidden(PermissionError):
    """已认证但角色不允许该操作（HTTP 403）。"""


class Conflict(Exception):
    """批次当前状态不允许该操作（HTTP 409）。"""


class ValidationFailed(ValueError):
    """请求字段不合法（HTTP 422）。"""
