#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""UploadRanger 统一请求模板模型。

GUI、MCP、Repeater 和扫描器只交换这个结构，不在各自模块重复猜测请求格式。
"""
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class FilePart:
    field: str
    filename: str = "test.bin"
    content_type: str = "application/octet-stream"
    content: bytes = b""


@dataclass
class RequestTemplate:
    method: str
    url: str
    headers: Dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    file_parts: List[FilePart] = field(default_factory=list)
    form_fields: Dict[str, Any] = field(default_factory=dict)
    mode: str = "raw"
    metadata: Dict[str, Any] = field(default_factory=dict)

    def validate(self) -> None:
        if self.method.upper() not in {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"}:
            raise ValueError(f"不支持的 HTTP 方法: {self.method}")
        if not self.url.startswith(("http://", "https://")):
            raise ValueError("请求 URL 必须使用 http:// 或 https://")
        if len(self.body) > 20 * 1024 * 1024:
            raise ValueError("请求体超过 20 MiB 限制")

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RequestTemplate":
        raw_parts = data.get("file_parts") or []
        parts = [FilePart(
            field=str(p.get("field", "file")),
            filename=str(p.get("filename", "test.bin")),
            content_type=str(p.get("content_type", "application/octet-stream")),
            content=p.get("content", b"") if isinstance(p.get("content", b""), bytes) else str(p.get("content", "")).encode(),
        ) for p in raw_parts]
        body = data.get("body", b"")
        if isinstance(body, str):
            body = body.encode("utf-8")
        obj = cls(
            method=str(data.get("method", "POST")).upper(),
            url=str(data.get("url", "")),
            headers={str(k): str(v) for k, v in (data.get("headers") or {}).items()},
            body=body,
            file_parts=parts,
            form_fields=dict(data.get("form_fields") or {}),
            mode=str(data.get("mode", "raw")),
            metadata=dict(data.get("metadata") or {}),
        )
        obj.validate()
        return obj
