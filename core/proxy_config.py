#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
统一上游代理配置（Issue #8）—— 所有出网流量的代理配置唯一来源

覆盖的客户端：AsyncHTTPClient(httpx) / HTTPClient(requests) / RawHTTPClient(raw socket)
              / mitmproxy upstream（内置抓包代理的上游链）

支持协议: http / https / socks5 / socks5h / socks4
- 无 scheme 输入自动补 http://（如 127.0.0.1:8080 -> http://127.0.0.1:8080）
- 支持用户名密码认证（HTTP(S) 代理 -> Proxy-Authorization: Basic；SOCKS5 -> RFC1929）
- socks5h 语义 = 域名由代理端解析（内网渗透必需）：
    * requests + PySocks 原生支持 socks5h；
    * RawHTTPClient 的 SOCKS5 握手使用 ATYP=domain，同样由代理解析；
    * httpx 未提供 socks5h scheme，但其 socks5 实现把主机名放进 CONNECT 交给代理端
      解析，语义一致，因此 for_httpx() 会把 socks5h 归一为 socks5。
- no_proxy 例外列表：命中的主机不走代理（支持精确主机与 *.domain 通配）。

持久化走 ConfigManager 的 "upstream_proxy" 节，与既有 ~/.uploadranger/config.json 合并。
"""

import base64
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, quote

SUPPORTED_SCHEMES = {"http", "https", "socks5", "socks5h", "socks4"}
DEFAULT_PORTS = {"http": 80, "https": 443, "socks5": 1080, "socks5h": 1080, "socks4": 1080}


def normalize_proxy_url(raw: str) -> str:
    """把用户输入的代理地址归一化为 scheme://[user:pass@]host:port。

    非法输入抛 ValueError（调用方应把错误显式呈现给用户，而不是静默直连）。
    """
    if raw is None:
        raise ValueError("代理地址为空")
    raw = str(raw).strip()
    if not raw:
        raise ValueError("代理地址为空")
    if "://" not in raw:
        raw = "http://" + raw
    parsed = urlparse(raw)
    scheme = parsed.scheme.lower()
    if scheme not in SUPPORTED_SCHEMES:
        raise ValueError(f"不支持的代理协议: {parsed.scheme}（支持: {', '.join(sorted(SUPPORTED_SCHEMES))}）")
    if not parsed.hostname:
        raise ValueError("代理缺少主机名")
    port = parsed.port
    if port is None:
        port = DEFAULT_PORTS.get(scheme, 80)
    host = parsed.hostname
    host = f"[{host}]" if ":" in host else host  # IPv6 字面量
    netloc = host
    if parsed.username:
        # urlparse 不解码百分号编码，先解码再统一重编码，避免 %40 -> %2540 双重编码
        user = quote(parse_unquote(str(parsed.username)), safe="")
        pwd = quote(parse_unquote(str(parsed.password or "")), safe="")
        netloc = f"{user}:{pwd}@{host}"
    return f"{scheme}://{netloc}:{port}"


@dataclass
class ProxyConfig:
    """归一化后的上游代理配置"""

    scheme: str  # http / https / socks5 / socks5h / socks4
    host: str
    port: int
    username: str = ""
    password: str = ""
    no_proxy: List[str] = field(default_factory=list)
    verify_upstream_tls: bool = True  # 上游为 https 代理时是否校验其证书

    # ---------- 构造 ----------

    @classmethod
    def parse(cls, raw: str) -> "ProxyConfig":
        """从用户输入解析。非法输入抛 ValueError。"""
        url = normalize_proxy_url(raw)
        parsed = urlparse(url)
        host = parsed.hostname or ""
        return cls(
            scheme=parsed.scheme.lower(),
            host=host,
            port=parsed.port or DEFAULT_PORTS.get(parsed.scheme.lower(), 80),
            username=parse_unquote(parsed.username or ""),
            password=parse_unquote(parsed.password or ""),
        )

    @classmethod
    def from_url(cls, url: str) -> "ProxyConfig":
        return cls.parse(url)

    # ---------- 属性 ----------

    @property
    def url(self) -> str:
        """带认证的完整代理 URL"""
        netloc = f"[{self.host}]" if ":" in self.host else self.host
        if self.username:
            netloc = f"{quote(self.username, safe='')}:{quote(self.password, safe='')}@{netloc}"
        return f"{self.scheme}://{netloc}:{self.port}"

    @property
    def url_no_auth(self) -> str:
        netloc = f"[{self.host}]" if ":" in self.host else self.host
        return f"{self.scheme}://{netloc}:{self.port}"

    @property
    def auth_header(self) -> Optional[str]:
        """HTTP(S) 代理的 Proxy-Authorization 值；SOCKS 不适用返回 None"""
        if self.scheme not in ("http", "https") or not self.username:
            return None
        token = base64.b64encode(f"{self.username}:{self.password}".encode("utf-8")).decode("ascii")
        return f"Basic {token}"

    @property
    def is_socks(self) -> bool:
        return self.scheme.startswith("socks")

    # ---------- 各客户端适配 ----------

    def for_requests(self) -> Optional[Dict[str, str]]:
        """requests.Session.proxies 取值（PySocks 需安装以支持 socks 协议）"""
        return {"http": self.url, "https": self.url}

    def for_httpx(self) -> Optional[Dict[str, object]]:
        """httpx mounts 取值。socks5h 归一为 socks5（httpx 语义即远端解析）。

        no_proxy 命中的主机挂 None 表示直连。
        """
        scheme = "socks5" if self.scheme == "socks5h" else self.scheme
        mounts: Dict[str, object] = {}
        for pattern in self._no_proxy_patterns():
            mounts[f"all://{pattern}"] = None
        mounts["http://"] = self.url if scheme in ("http", "https") else f"{scheme}://{self._auth_netloc()}{self.host}:{self.port}"
        mounts["https://"] = self.url if scheme in ("http", "https") else f"{scheme}://{self._auth_netloc()}{self.host}:{self.port}"
        return mounts

    def for_raw(self) -> Tuple[str, str, int, str, str]:
        """RawHTTPClient 取值: (scheme, host, port, username, password)"""
        return self.scheme, self.host, self.port, self.username, self.password

    def _auth_netloc(self) -> str:
        if not self.username:
            return ""
        return f"{quote(self.username, safe='')}:{quote(self.password, safe='')}@"

    def _no_proxy_patterns(self) -> List[str]:
        """把 no_proxy 条目转成 httpx mount 模式（*.domain -> domain 后缀匹配由 httpx 处理）"""
        patterns = []
        for item in self.no_proxy:
            item = str(item).strip().lstrip(".").lower()
            if not item:
                continue
            if item.startswith("*."):
                item = item[2:]
            patterns.append(item)
        return patterns

    def matches_no_proxy(self, host: str) -> bool:
        """raw socket 客户端用：判断目标主机是否命中直连例外"""
        host = str(host or "").lower().rstrip(".")
        for item in self._no_proxy_patterns():
            if host == item or host.endswith("." + item):
                return True
        return False

    # ---------- 持久化 ----------

    def to_config_dict(self) -> Dict[str, object]:
        return {
            "url": self.url,
            "no_proxy": list(self.no_proxy),
            "verify_upstream_tls": self.verify_upstream_tls,
        }

    def save(self) -> bool:
        try:
            from .config_manager import get_config_manager
            cm = get_config_manager()
            cm.set("upstream_proxy", self.to_config_dict())
            return cm.save()
        except Exception:
            return False

    @classmethod
    def load_saved(cls) -> Optional["ProxyConfig"]:
        """读取持久化的上游代理；未配置或损坏返回 None"""
        try:
            from .config_manager import get_config_manager
            cm = get_config_manager()
            data = cm.get("upstream_proxy")
            if not data or not data.get("url"):
                return None
            pc = cls.parse(data["url"])
            pc.no_proxy = list(data.get("no_proxy") or [])
            pc.verify_upstream_tls = bool(data.get("verify_upstream_tls", True))
            return pc
        except Exception:
            return None

    # ---------- 连通性测试 ----------

    def test_connectivity(self, probe_url: str = "", timeout: float = 8.0) -> Dict[str, object]:
        """经代理探测连通性（同步阻塞，GUI 侧请放线程调用）。

        依次尝试：自定义 probe_url -> https://api.ipify.org（拿出口 IP）-> http://www.gstatic.com/generate_204。
        仅支持公网探测点；纯内网代理可传 probe_url 指向内网可达地址。
        """
        result: Dict[str, object] = {"ok": False, "latency_ms": None, "exit_ip": None, "error": None, "probe": None}
        candidates = [u for u in (probe_url, "https://api.ipify.org?format=json", "http://www.gstatic.com/generate_204") if u]
        last_err = "未知错误"
        import httpx
        for url in candidates:
            started = time.monotonic()
            try:
                with httpx.Client(proxy=self.url, timeout=timeout, verify=self.verify_upstream_tls, trust_env=False) as client:
                    resp = client.get(url)
                result.update({
                    "ok": resp.status_code < 500,
                    "latency_ms": int((time.monotonic() - started) * 1000),
                    "probe": url,
                    "error": None if resp.status_code < 500 else f"HTTP {resp.status_code}",
                    "exit_ip": _extract_ip(resp),
                })
                if resp.status_code < 500:
                    return result
                last_err = f"HTTP {resp.status_code}"
            except Exception as exc:  # noqa: BLE001 - 探测失败需要原样呈现给用户
                last_err = f"{type(exc).__name__}: {exc}"
                result["error"] = last_err
        result["ok"] = False
        result["error"] = last_err
        return result


def _extract_ip(resp) -> Optional[str]:
    """从探测响应里尽量提取出口 IP"""
    try:
        text = resp.text.strip()
        if text.startswith("{"):
            import json
            data = json.loads(text)
            for key in ("ip", "ip_addr", "query"):
                if key in data:
                    return str(data[key])
        if text and len(text) <= 64 and all(c in "0123456789abcdefABCDEF.:" for c in text):
            return text
    except Exception:
        pass
    return None


def parse_unquote(value: str) -> str:
    """urlparse 不会解码百分号编码的凭据，这里补一次解码"""
    from urllib.parse import unquote
    try:
        return unquote(value)
    except Exception:
        return value
