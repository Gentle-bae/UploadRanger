#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""URL 安全校验：限制上传结果验证的跨域、私网和本地地址访问。"""
import ipaddress
import socket
from urllib.parse import urlparse


def _hostname(url: str) -> str:
    return (urlparse(url).hostname or "").lower().rstrip(".")


def is_blocked_host(url: str) -> bool:
    host = _hostname(url)
    if not host:
        return True
    if host in {"localhost", "localhost.localdomain"} or host.endswith(".local"):
        return True
    try:
        addresses = {host}
        try:
            addresses.update(item[4][0] for item in socket.getaddrinfo(host, None))
        except OSError:
            pass
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
    a, b = urlparse(url), urlparse(base)
    aport = a.port or (443 if a.scheme.lower() == "https" else 80)
    bport = b.port or (443 if b.scheme.lower() == "https" else 80)
    return (a.scheme.lower(), (a.hostname or "").lower(), aport) == (b.scheme.lower(), (b.hostname or "").lower(), bport)


def safe_verification_url(url: str, base: str, allow_cross_origin: bool = False) -> bool:
    parsed = urlparse(url)
    if parsed.scheme.lower() not in {"http", "https"} or is_blocked_host(url):
        # 本地靶场/开发环境是合法扫描场景：仅当基准目标本身也是私网/回环地址，
        # 且验证 URL 保持严格同源时放行；公网目标仍保持默认阻断策略。
        if not is_same_origin(url, base) or not is_blocked_host(base):
            return False
    return allow_cross_origin or is_same_origin(url, base)
