#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Payload Registry - 统一 Payload 注册中心

解决原来三套独立生成器（bypass_payloads / async_scanner / intruder_payloads）
各自维护、互不共享的问题。

所有 payload 来源通过此模块统一获取，支持：
- 按环境指纹过滤（传入 EnvironmentProfile）
- 按数量限制
- 优先级排序
- 去重

Author: UploadRanger
Version: 2.0.0
"""

from __future__ import annotations

import re
from typing import List, Optional, Dict, Any

# ---------------------------------------------------------------------------
# 规范化 payload 结构
# ---------------------------------------------------------------------------
# 所有来源的 payload 统一转换为以下字典格式：
#
#   {
#     'type'         : str,   # 分类标签，如 'php_ext', 'null_byte', 'polyglot' …
#     'ext'          : str,   # 目标扩展名，如 '.php'
#     'filename'     : str,   # 完整文件名，如 'shell.php.jpg'
#     'content'      : bytes, # 文件内容（可含 magic bytes）
#     'content_type' : str,   # multipart Content-Type
#     'desc'         : str,   # 人类可读描述
#     'technique'    : str,   # 绕过技术标签
#     'severity'     : str,   # '高' / '中' / '低'
#     'target_env'   : list,  # 适用服务器环境，空列表 = 通用
#     'target_os'    : list,  # 适用 OS，空列表 = 通用
#     'priority'     : int,   # 优先级 1-5（越大越优先）
#   }
# ---------------------------------------------------------------------------

_DEFAULT_PHP_CONTENT = b"<?php echo 'UR_TEST_' . (23*2); ?>"
_DEFAULT_JSP_CONTENT = b"<% out.println(\"UR_TEST_\" + (23*2)); %>"
_DEFAULT_ASP_CONTENT = b"<% Response.Write(\"UR_TEST_\" + 46) %>"


# ---------------------------------------------------------------------------
# 内部归一化辅助
# ---------------------------------------------------------------------------

def _norm(raw: Dict[str, Any]) -> Dict[str, Any]:
    """将任意来源的 payload dict 归一化为标准格式。"""
    filename = raw.get('filename') or ''
    ext_from_name = '.' + filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''

    return {
        'type':         raw.get('type') or raw.get('technique') or 'unknown',
        'ext':          raw.get('ext') or ext_from_name,
        'filename':     filename,
        'content':      raw.get('content') or _DEFAULT_PHP_CONTENT,
        'content_type': raw.get('content_type') or 'application/octet-stream',
        'desc':         raw.get('desc') or raw.get('description') or filename,
        'technique':    raw.get('technique') or raw.get('type') or 'unknown',
        'severity':     raw.get('severity') or '中',
        'target_env':   list(raw.get('target_env') or []),
        'target_os':    list(raw.get('target_os') or []),
        'priority':     int(raw.get('priority') or 3),
    }


# ---------------------------------------------------------------------------
# 来源 1：从 AsyncScanner._generate_payloads() 拉取
# ---------------------------------------------------------------------------

def _load_async_scanner_payloads() -> List[Dict[str, Any]]:
    try:
        from core.async_scanner import AsyncScanner
        scanner = AsyncScanner()
        raw_list = scanner._generate_payloads(None)
        result = []
        for p in raw_list:
            norm = _norm(p)
            # async_scanner 的 payload 质量最高，优先级适当上调
            norm['priority'] = max(norm['priority'], 3)
            result.append(norm)
        return result
    except Exception:
        return []


# ---------------------------------------------------------------------------
# 来源 2：从 BypassPayloadGenerator 拉取（多扩展名）
# ---------------------------------------------------------------------------

def _load_bypass_payloads(extensions: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    try:
        from payloads.bypass_payloads import BypassPayloadGenerator
        gen = BypassPayloadGenerator()
        exts = extensions or ['.php', '.asp', '.aspx', '.jsp']
        result = []
        seen = set()
        for ext in exts:
            for raw in gen.generate_all_payloads('shell', ext):
                fname = raw.get('filename', '')
                if fname in seen:
                    continue
                seen.add(fname)
                norm = _norm(raw)
                norm['ext'] = ext
                result.append(norm)
        return result
    except Exception:
        return []


# ---------------------------------------------------------------------------
# 主注册中心类
# ---------------------------------------------------------------------------

class PayloadRegistry:
    """
    统一 Payload 注册中心。

    使用示例：
        registry = PayloadRegistry()
        payloads = registry.get_payloads(max_count=800)

        # 配合环境指纹过滤：
        from core.fingerprinter import filter_payloads_by_profile
        filtered = filter_payloads_by_profile(payloads, profile, max_count)
    """

    def __init__(self):
        self._payloads: List[Dict[str, Any]] = []
        self._loaded = False

    # ------------------------------------------------------------------
    # 加载 / 刷新
    # ------------------------------------------------------------------

    def load(self, extensions: Optional[List[str]] = None) -> None:
        """从所有来源加载 payload，去重合并。"""
        seen_filenames: set = set()
        merged: List[Dict[str, Any]] = []

        # 优先加载 async_scanner（覆盖最广）
        for p in _load_async_scanner_payloads():
            fname = p.get('filename', '')
            if fname and fname not in seen_filenames:
                seen_filenames.add(fname)
                merged.append(p)

        # 补充 bypass_payloads（会有不少重复，跳过已存在的文件名）
        for p in _load_bypass_payloads(extensions):
            fname = p.get('filename', '')
            if fname and fname not in seen_filenames:
                seen_filenames.add(fname)
                merged.append(p)

        # 按优先级降序排列
        merged.sort(key=lambda x: x.get('priority', 3), reverse=True)

        self._payloads = merged
        self._loaded = True

    def _ensure_loaded(self) -> None:
        if not self._loaded:
            self.load()

    # ------------------------------------------------------------------
    # 查询接口
    # ------------------------------------------------------------------

    def get_payloads(
        self,
        profile=None,
        max_count: int = 1200,
        extensions: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        """
        获取 payload 列表。

        Args:
            profile:    EnvironmentProfile，用于指纹过滤；为 None 则不过滤。
            max_count:  最大数量。
            extensions: 指定目标扩展名（仅在 load() 时生效）。
        """
        self._ensure_loaded()

        payloads = list(self._payloads)

        # 指纹过滤
        if profile is not None:
            try:
                from core.fingerprinter import filter_payloads_by_profile
                payloads = filter_payloads_by_profile(
                    payloads, profile, max_count,
                    apply_disable=True, prioritize=True
                )
            except Exception:
                payloads = payloads[:max_count]
        else:
            payloads = payloads[:max_count]

        return payloads

    def count(self) -> int:
        self._ensure_loaded()
        return len(self._payloads)

    def types(self) -> List[str]:
        self._ensure_loaded()
        return sorted({p.get('type', 'unknown') for p in self._payloads})


# ---------------------------------------------------------------------------
# 模块级单例（方便直接 import 使用）
# ---------------------------------------------------------------------------

_registry: Optional[PayloadRegistry] = None


def get_registry() -> PayloadRegistry:
    """获取模块级单例注册中心（延迟初始化）。"""
    global _registry
    if _registry is None:
        _registry = PayloadRegistry()
    return _registry


def get_payloads(
    profile=None,
    max_count: int = 1200,
    extensions: Optional[List[str]] = None,
) -> List[Dict[str, Any]]:
    """便捷函数：直接从单例注册中心获取 payload 列表。"""
    return get_registry().get_payloads(profile=profile, max_count=max_count, extensions=extensions)
