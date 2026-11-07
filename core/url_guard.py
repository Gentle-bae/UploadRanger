#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""URL 安全校验：限制上传结果验证的跨域、私网和本地地址访问。"""
import ipaddress
import socket
import threading
import time
from urllib.parse import urlparse

# -----------------------------------------------------------------------------
# DNS 解析缓存：同一主机的解析结果在 TTL 内复用，校验与后续建连尽量共用同一次
# 解析结果，缩小 DNS rebinding 的 TOCTOU 窗口。
# 注意：这是缓解而非根治——TTL 过期后窗口重新打开；彻底修复需要把校验通过的
# IP 固定（pin）到后续连接（如自定义 httpx transport）。
# -----------------------------------------------------------------------------
_DNS_CACHE: dict = {}
_DNS_CACHE_LOCK = threading.Lock()
_DNS_CACHE_TTL_SECONDS = 60.0


def resolve_host_cached(host: str) -> list:
    """解析主机名并返回 IP 列表（模块级缓存，TTL 60 秒，threading.Lock 保证线程安全）。

    供 url_guard 内部统一使用，使同一扫描中对同一主机的重复校验复用同一份解析
    结果，缩小"校验时刻解析 A、建连时刻解析 B"的 DNS rebinding 窗口。
    这是缓解而非根治：TTL 过期后窗口重新打开，根治需将校验通过的 IP 固定到
    后续连接。
    """
    key = str(host or "").strip().lower().rstrip(".")
    if not key:
        return []
    now = time.monotonic()
    with _DNS_CACHE_LOCK:
        cached = _DNS_CACHE.get(key)
        if cached is not None and now - cached[1] < _DNS_CACHE_TTL_SECONDS:
            return list(cached[0])
    try:
        addresses = [item[4][0] for item in socket.getaddrinfo(key, None)]
    except OSError:
        # 解析失败（NXDOMAIN/网络错误等）：返回空列表，由调用方按策略处理
        addresses = []
    with _DNS_CACHE_LOCK:
        _DNS_CACHE[key] = (list(addresses), now)
    return list(addresses)


def _looks_like_numeric_ip_encoding(host: str) -> bool:
    """识别非点分十进制的数值 IP 编码写法。

    覆盖三类常见变体：
    - 十六进制整数：0x7f000001
    - 八进制段：0177.0.0.1（带前导 0 的段）
    - 纯十进制整数：2130706433

    getaddrinfo 对这些写法的接受度随平台而异（部分平台直接 OSError）。
    解析失败又无法确认是普通域名时，调用方按 fail-closed 处理视为 blocked，
    避免这类"看起来不像 IP"的写法绕过私网封锁。
    """
    text = str(host or "").strip().lower().rstrip(".")
    if not text:
        return False
    if text.startswith("0x"):
        try:
            int(text, 16)
            return True
        except ValueError:
            return False
    parts = text.split(".")
    if all(part.isdigit() for part in parts):
        # 单段纯数字（十六进制已排除）：十进制整数编码，如 2130706433
        if len(parts) == 1:
            return True
        # 多段全数字且含前导 0 段：八进制/非标准点分写法，如 0177.0.0.1
        return any(len(part) > 1 and part.startswith("0") for part in parts)
    return False


def _hostname(url: str) -> str:
    try:
        hostname = urlparse(url).hostname or ""
    except ValueError:
        # 非法 IPv6/端口等输入：按无主机处理，由调用方 fail-closed
        hostname = ""
    if not hostname and url and "://" not in str(url):
        # 兼容直接传入裸主机名的调用（如 is_blocked_host('127.0.0.1')）：
        # urlparse 会把纯主机解析为 path 导致 hostname 为空，这里回退提取。
        text = str(url).strip().rstrip(".")
        if text and "/" not in text and " " not in text:
            hostname = text.split("@")[-1].split(":")[0]
    return (hostname or "").lower().rstrip(".")


def is_blocked_host(url: str) -> bool:
    host = _hostname(url)
    if not host:
        return True
    if host in {"localhost", "localhost.localdomain"} or host.endswith(".local"):
        return True
    try:
        addresses = {host}
        resolved = resolve_host_cached(host)
        if not resolved and _looks_like_numeric_ip_encoding(host):
            # 解析失败且主机名形如数值 IP 编码（0x7f000001/0177.0.0.1/纯十进制
            # 整数）：无法确认其真实指向，按 fail-closed 视为 blocked
            return True
        addresses.update(resolved)
        for address in addresses:
            try:
                ip = ipaddress.ip_address(address)
            except ValueError:
                continue
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified:
                return True
    except Exception:
        return True
    return False


def is_same_origin(url: str, base: str) -> bool:
    try:
        a, b = urlparse(url), urlparse(base)
        aport = a.port or (443 if a.scheme.lower() == "https" else 80)
        bport = b.port or (443 if b.scheme.lower() == "https" else 80)
    except ValueError:
        # 非法端口（如 http://x:abc/）无法建立可信同源判定，fail-closed
        return False
    return (a.scheme.lower(), (a.hostname or "").lower(), aport) == (b.scheme.lower(), (b.hostname or "").lower(), bport)


def safe_verification_url(url: str, base: str, allow_cross_origin: bool = False) -> bool:
    try:
        parsed = urlparse(url)
        scheme = parsed.scheme.lower()
    except ValueError:
        # urlparse 对非法 IPv6/端口输入可能抛 ValueError，fail-closed
        return False
    if scheme not in {"http", "https"} or is_blocked_host(url):
        # 本地靶场/开发环境是合法扫描场景：仅当基准目标本身也是私网/回环地址，
        # 且验证 URL 保持严格同源时放行；公网目标仍保持默认阻断策略。
        if not is_same_origin(url, base) or not is_blocked_host(base):
            return False
    return allow_cross_origin or is_same_origin(url, base)
