# -*- coding: utf-8 -*-
"""统一的文件签名（Magic Bytes）工具。

该模块只负责字节构造与识别，不负责判断上传是否成功；最终结论必须由
扫描器的响应分析和文件访问验证给出。
"""

from __future__ import annotations

from typing import Dict, Optional, Tuple


MAGIC_SIGNATURES: Dict[str, bytes] = {
    "gif": b"GIF89a",
    "png": b"\x89PNG\r\n\x1a\n",
    "jpg": b"\xff\xd8\xff\xe0\x00\x10JFIF",
    "jpeg": b"\xff\xd8\xff\xe0\x00\x10JFIF",
    "pdf": b"%PDF-",
    "zip": b"PK\x03\x04",
    "bmp": b"BM",
    "webp": b"RIFF",
}


def get_signature(name: str) -> bytes:
    """按名称取得签名，不认识的名称抛出 ValueError。"""
    key = str(name or "").strip().lower().lstrip(".")
    try:
        return MAGIC_SIGNATURES[key]
    except KeyError as exc:
        raise ValueError(f"未知文件签名: {name}") from exc


def build_magic_content(signature: bytes | str, payload: bytes = b"") -> bytes:
    """将签名与测试内容拼接，签名可传名称或原始 bytes。"""
    prefix = get_signature(signature) if isinstance(signature, str) else bytes(signature)
    return prefix + bytes(payload or b"")


def detect_signature(data: bytes) -> Optional[Tuple[str, bytes]]:
    """返回匹配到的 (名称, 签名)，未匹配返回 None。"""
    raw = bytes(data or b"")
    for name, signature in MAGIC_SIGNATURES.items():
        if name == "jpeg":
            continue
        if raw.startswith(signature):
            return name, signature
    return None


def signatures_for_ui() -> Dict[str, bytes]:
    """返回去重后的 UI 选项，避免 jpg/jpeg 重复显示。"""
    return {k: v for k, v in MAGIC_SIGNATURES.items() if k != "jpeg"}
