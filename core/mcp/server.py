"""UploadRanger MCP Server（本地 stdio）。

默认不自动启动；通过 ``python -m core.mcp.server`` 显式运行。
扫描使用任务 ID 异步执行，避免 MCP 请求长期阻塞。
"""

import asyncio
import uuid
import traceback
import sys
import os
import secrets
from pathlib import Path
from datetime import datetime
from typing import Any, Dict, Optional
from urllib.parse import urljoin, urlparse

import httpx
from mcp.server.fastmcp import FastMCP

from ..async_scanner import AsyncScanner
from ..auto_verifier import WebShellVerifier, VerificationResult, VerificationStatus
from ..proxy_config import ProxyConfig
from ..request_parser import parse_raw_request
from ..url_guard import is_blocked_host, is_same_origin

# C6：日志从项目根目录迁入用户目录 ~/.uploadranger/mcp.log，目录自动创建。
_UPLOADRANGER_HOME = Path.home() / ".uploadranger"
MCP_LOG_FILE = _UPLOADRANGER_HOME / "mcp.log"
try:
    _UPLOADRANGER_HOME.mkdir(parents=True, exist_ok=True)
except OSError:
    pass  # 目录创建失败时仅丢失文件日志，stderr 输出不受影响

# C5：ScanManager 资源上限。
_MAX_TRACKED_TASKS = 200    # results/progress/tasks 最多保留的任务数（FIFO 淘汰最旧）
_MAX_LOGS_PER_TASK = 500    # 单任务日志条数上限
_MAX_CONCURRENT_SCANS = 5   # 并发扫描上限

# C7：--proxy 传入的服务级默认上游代理（__main__ 中赋值；None 表示直连）。
_CLI_PROXY: Optional[str] = None

_log_mode_fixed = False


def _ensure_log_file_mode() -> None:
    """POSIX 下尽量把日志文件权限收紧为 0600（失败静默，不影响功能）。"""
    global _log_mode_fixed
    if _log_mode_fixed or os.name != "posix":
        return
    _log_mode_fixed = True
    try:
        os.chmod(MCP_LOG_FILE, 0o600)
    except OSError:
        pass


def _header_host(value: str) -> str:
    """从 Host 头取值（如 example.com:8080 / [::1]:443）归一化出小写主机名。"""
    if not value:
        return ""
    return (urlparse(f"http://{value.strip()}").hostname or "").lower().rstrip(".")


def _log_server(message: str) -> None:
    """服务级日志（无 scan_id）：stderr + MCP_LOG_FILE，stderr 行为与 emit_log 一致。"""
    timestamp = datetime.now().isoformat(timespec="seconds")
    print(f"[MCP] {message}", file=sys.stderr, flush=True)
    try:
        with MCP_LOG_FILE.open("a", encoding="utf-8") as fh:
            fh.write(f"[{timestamp}] {message}\n")
        _ensure_log_file_mode()
    except OSError:
        pass


class _StaticBearerTokenVerifier:
    """静态 Bearer Token 校验器（实现 mcp TokenVerifier 协议，C4 鉴权）。

    与 UPLOADRANGER_MCP_TOKEN 做常数时间精确比对：命中返回 AccessToken，
    未命中返回 None（FastMCP 的 RequireAuthMiddleware 将返回 401）。
    """

    def __init__(self, token: str) -> None:
        self._token = token

    async def verify_token(self, token: str):
        if token and secrets.compare_digest(str(token), self._token):
            from mcp.server.auth.provider import AccessToken
            return AccessToken(token=token, client_id="uploadranger-mcp", scopes=[], expires_at=None)
        return None


class _GuardedWebShellVerifier(WebShellVerifier):
    """逐跳门禁的 WebShellVerifier 包装（C3 / 审计：verify 路径重定向可跳内网）。

    auto_verifier.WebShellVerifier.verify() 内部硬编码 follow_redirects=True 且对
    重定向每一跳不复查安全门禁（302 → 127.0.0.1 / 云 metadata 可绕过并回显响应）。
    此处覆写 verify()：改为 follow_redirects=False 手动跟随（上限 5 跳），每一跳
    先过 is_blocked_host，命中即中止并报告。allow_local=True 时沿用调用方对
    本地/私网目标的显式授权，跳过逐跳门禁（与既有 pre-check 行为保持一致）。
    """

    MAX_REDIRECT_HOPS = 5

    def __init__(self, *args, allow_local: bool = False, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.allow_local = allow_local

    async def verify(self, upload_url: str, language: str = "php") -> VerificationResult:
        # 解析URL（复用父类逻辑）
        parsed = self._parse_upload_url(upload_url)
        if not parsed:
            return VerificationResult(
                status=VerificationStatus.FAILED,
                verified_url=None,
                response_code=0,
                response_preview="",
                execution_confirmed=False,
                error="无法解析上传URL",
            )
        verify_url, _filename = parsed
        try:
            # C3：关闭自动重定向，改为手动逐跳校验。
            client_kwargs = {
                "timeout": self.timeout,
                "verify": self.verify_ssl,
                "follow_redirects": False,
            }
            # httpx 0.28 使用 proxy=；多协议场景用 mounts（与父类保持一致）。
            if self.proxies:
                mounts = {
                    scheme: httpx.AsyncHTTPTransport(proxy=url)
                    for scheme, url in self.proxies.items()
                    if url
                }
                if mounts:
                    client_kwargs["mounts"] = mounts
            async with httpx.AsyncClient(**client_kwargs) as client:
                current_url = verify_url
                response = None
                loop = asyncio.get_running_loop()
                for hop in range(self.MAX_REDIRECT_HOPS + 1):
                    # 每一跳先过门禁，命中即中止。
                    # 【修复 P1】is_blocked_host 内部是同步 socket.getaddrinfo，
                    # 公网冷解析 ~200ms/跳、DNS 故障时可达秒级，会冻结整个事件循环
                    # （期间 status/logs/cancel/其他扫描全部无响应）。resolve_host_cached
                    # 自带 threading.Lock 线程安全，可安全放入线程池执行。
                    if not self.allow_local:
                        blocked = await loop.run_in_executor(
                            None, is_blocked_host, current_url
                        )
                        if blocked:
                            return VerificationResult(
                                status=VerificationStatus.FAILED,
                                verified_url=current_url,
                                response_code=0,
                                response_preview="",
                                execution_confirmed=False,
                                error=f"目标被安全门禁拦截：第 {hop + 1} 跳（{current_url}）命中回环/私网/保留段，已中止验证",
                            )
                    response = await client.get(current_url)
                    if not response.is_redirect:
                        break
                    if hop >= self.MAX_REDIRECT_HOPS:
                        return VerificationResult(
                            status=VerificationStatus.FAILED,
                            verified_url=current_url,
                            response_code=response.status_code,
                            response_preview="",
                            execution_confirmed=False,
                            error=f"重定向次数超过上限 {self.MAX_REDIRECT_HOPS} 跳，已中止验证",
                        )
                    location = response.headers.get("location", "")
                    if not location:
                        break
                    current_url = urljoin(current_url, location)
                # 最终响应按实际到达的 URL 检查。
                return self._check_response(response.status_code, response.text, language, current_url)
        except httpx.RequestError as e:
            return VerificationResult(
                status=VerificationStatus.FAILED,
                verified_url=verify_url,
                response_code=0,
                response_preview="",
                execution_confirmed=False,
                error=f"请求失败: {str(e)}",
            )


class ScanManager:
    def __init__(self) -> None:
        self.tasks: Dict[str, asyncio.Task] = {}
        self.results: Dict[str, Any] = {}
        self.progress: Dict[str, Dict[str, Any]] = {}
        self.log_callbacks = []
        # C5：并发扫描上限；信号量在任务启动时获取，排队中的任务仍可查询/取消。
        self._scan_semaphore = asyncio.Semaphore(_MAX_CONCURRENT_SCANS)

    def _bound_tracking(self) -> None:
        """C5：results/progress/tasks 有界——超过 _MAX_TRACKED_TASKS 时 FIFO 淘汰最旧；
        仍在运行的被淘汰任务先取消，避免孤儿任务与内存无限增长。"""
        while len(self.tasks) > _MAX_TRACKED_TASKS:
            oldest = next(iter(self.tasks))
            task = self.tasks.pop(oldest)
            if not task.done():
                task.cancel()
            self.progress.pop(oldest, None)
            self.results.pop(oldest, None)
        while len(self.progress) > _MAX_TRACKED_TASKS:
            self.progress.pop(next(iter(self.progress)))
        while len(self.results) > _MAX_TRACKED_TASKS:
            self.results.pop(next(iter(self.results)))

    def emit_log(self, scan_id: str, message: str) -> None:
        # 【修复 P2】任务被 FIFO 淘汰/取消后，扫描线程的迟到回调会让
        # progress.setdefault 复活"幽灵条目"（永不清理 → 内存泄漏 + status 僵尸）。
        # 条目已不在登记表中说明任务已被淘汰，直接丢弃本次回调。
        if scan_id not in self.progress:
            return
        entry = {"timestamp": datetime.now().isoformat(timespec="seconds"), "message": str(message)}
        logs = self.progress[scan_id]["logs"]
        logs.append(entry)
        if len(logs) > _MAX_LOGS_PER_TASK:  # C5：单任务日志有界
            del logs[: len(logs) - _MAX_LOGS_PER_TASK]
        for callback in list(self.log_callbacks):
            try:
                callback(scan_id, entry)
            except Exception:
                pass
        # stdio MCP 的 stdout 专用于协议，日志必须写 stderr，GUI 会实时读取。
        print(f"[MCP][{scan_id}] {entry['message']}", file=sys.stderr, flush=True)
        try:
            with MCP_LOG_FILE.open("a", encoding="utf-8") as fh:
                fh.write(f"[{entry['timestamp']}][{scan_id}] {entry['message']}\n")
            _ensure_log_file_mode()
        except OSError:
            pass

    async def start(self, params: Dict[str, Any]) -> str:
        scan_id = f"scan_{uuid.uuid4().hex[:12]}"
        task = asyncio.create_task(self._run(scan_id, params))
        self.tasks[scan_id] = task
        self.progress[scan_id] = {"percent": 0, "message": "queued", "logs": []}
        self.emit_log(scan_id, f"扫描任务已创建：{scan_id}")
        self._bound_tracking()  # C5：登记容量上限，FIFO 淘汰最旧
        return scan_id

    async def _run(self, scan_id: str, params: Dict[str, Any]) -> None:
        # C5：信号量在任务启动时获取；排队中的任务仍可通过 status/cancel 操作。
        async with self._scan_semaphore:
            scanner = AsyncScanner()
            def on_log(message: str):
                self.emit_log(scan_id, message)
            def on_progress(message: str, percent: int):
                if scan_id not in self.progress:
                    return  # 【修复 P2】任务已被淘汰，丢弃迟到的进度回调，防幽灵条目复活
                state = self.progress[scan_id]
                state["percent"] = max(0, min(100, int(percent)))
                state["message"] = str(message)
                self.emit_log(scan_id, f"进度 {state['percent']}%：{message}")
            try:
                proxies = params.get("proxies")
                if not proxies and _CLI_PROXY:
                    # C7：工具级 proxies 参数优先；未指定时套用 --proxy 服务级默认。
                    proxies = ProxyConfig.parse(_CLI_PROXY).for_httpx()
                    self.emit_log(scan_id, f"已应用 --proxy 服务级代理：{_CLI_PROXY}")
                result = await scanner.scan(
                    target_url=params["target_url"],
                    file_param=params.get("file_param", "file"),
                    headers=params.get("headers"),
                    cookies=params.get("cookies"),
                    proxies=proxies,
                    on_log_callback=on_log,
                    progress_callback=on_progress,
                    max_payloads=min(int(params.get("max_payloads", 100)), 1200),
                    timeout=min(int(params.get("timeout", 30)), 120),
                    scan_mode=params.get("scan_mode", "security"),
                    selected_extensions=params.get("selected_extensions"),
                    extra_fields=params.get("extra_fields") or None,
                    verify_ssl=bool(params.get("verify_ssl", True)),
                )
                self.progress[scan_id]["percent"] = 100
                self.progress[scan_id]["message"] = "completed"
                self.results[scan_id] = {"status": "completed", "result": result.to_dict() if hasattr(result, "to_dict") else result}
                self.emit_log(scan_id, "扫描完成")
            except asyncio.CancelledError:
                if scan_id in self.progress:  # 已被 FIFO 淘汰的任务不再写回登记表
                    self.results[scan_id] = {"status": "cancelled"}
                raise
            except Exception as exc:
                if scan_id in self.progress:
                    self.results[scan_id] = {"status": "failed", "error": str(exc), "traceback": traceback.format_exc(limit=8)}
                    self.emit_log(scan_id, f"扫描失败：{exc}")

    def status(self, scan_id: str) -> Dict[str, Any]:
        if scan_id in self.results:
            data = dict(self.results[scan_id])
            data["progress"] = self.progress.get(scan_id, {})
            return data
        task = self.tasks.get(scan_id)
        if task is None:
            return {"status": "not_found"}
        return {"status": "running", "done": task.done(), "progress": self.progress.get(scan_id, {})}

    def logs(self, scan_id: str) -> Dict[str, Any]:
        if scan_id not in self.tasks and scan_id not in self.results:
            return {"status": "not_found", "logs": []}
        return {"status": "ok", "logs": self.progress.get(scan_id, {}).get("logs", [])}

    async def cancel(self, scan_id: str) -> bool:
        task = self.tasks.get(scan_id)
        if not task or task.done():
            return False
        task.cancel()
        return True


def create_server(bearer_token: Optional[str] = None) -> FastMCP:
    """构建 FastMCP 服务；bearer_token 非空时启用 Bearer 鉴权（C4）。

    bearer_token 缺省回退读取环境变量 UPLOADRANGER_MCP_TOKEN——设置了该环境变量
    才启用鉴权，stdio 默认模式不受影响。
    """
    if bearer_token is None:
        bearer_token = os.environ.get("UPLOADRANGER_MCP_TOKEN", "").strip() or None
    mcp_kwargs: Dict[str, Any] = {}
    if bearer_token:
        # mcp>=1.10 的 FastMCP auth 机制：为 SSE/streamable-http 端点挂
        # BearerAuthBackend(token_verifier) + RequireAuthMiddleware（stdio 不经过 HTTP 端点）。
        try:
            from mcp.server.auth.settings import AuthSettings
        except ImportError as exc:
            raise RuntimeError(
                "UPLOADRANGER_MCP_TOKEN 已设置但当前 mcp 库不支持 auth 机制（需 mcp>=1.10），"
                f"拒绝以无鉴权模式启动：{exc}"
            ) from exc
        mcp_kwargs = {
            "auth": AuthSettings(issuer_url="https://uploadranger.local", resource_server_url=None),
            "token_verifier": _StaticBearerTokenVerifier(bearer_token),
        }
    mcp = FastMCP("UploadRanger", **mcp_kwargs)
    manager = ScanManager()

    @mcp.tool()
    async def uploadranger_scan(
        target_url: str,
        file_param: str = "file",
        max_payloads: int = 100,
        timeout: int = 30,
        scan_mode: str = "security",
        selected_extensions: Optional[list[str]] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[str] = None,
        extra_fields: Optional[Dict[str, str]] = None,
        raw_request: Optional[str] = None,
        proxies: Optional[Dict[str, str]] = None,
        verify_ssl: bool = True,
    ) -> Dict[str, Any]:
        """启动一次受限文件上传扫描，返回 scan_id。"""
        # C1：安全门禁放最前面——目标命中回环/私网/保留段直接拒绝。
        if target_url and is_blocked_host(target_url):
            raise ValueError("目标被安全门禁拦截：target_url 命中回环/私网/保留段地址")
        if raw_request:
            declared_target = target_url
            parsed = parse_raw_request(raw_request, base_url=declared_target or None)
            if declared_target:
                # C2：报文内 Host 可静默改写实际扫描目标——先比对解析出的实际 URL，
                # 再比对报文 Host 头（base_url 提供时 URL 取自 base_url，但伪造的
                # Host 头仍会随请求发出，改变远端 vhost 路由），任一不一致即拒绝。
                if not is_same_origin(parsed.url, declared_target):
                    raise ValueError("raw_request 的 Host 与 target_url 不一致，疑似改写扫描目标，已拒绝")
                raw_host = _header_host(parsed.headers.get("Host") or parsed.headers.get("host") or "")
                if raw_host and raw_host != _header_host(urlparse(declared_target).hostname or ""):
                    raise ValueError("raw_request 的 Host 头与 target_url 不一致，疑似改写扫描目标，已拒绝")
            else:
                # 未声明 target_url 时以报文解析结果为准。
                _log_server(f"raw_request 未提供 target_url，以报文解析结果为准：{parsed.url}")
            target_url = parsed.url
            file_param = parsed.file_parts[0].field if parsed.file_parts else file_param
            headers = parsed.headers
            extra_fields = parsed.form_fields
            # 解析出的有效目标同样要过门禁（Host 头可能指向内网）。
            if is_blocked_host(target_url):
                raise ValueError("目标被安全门禁拦截：raw_request 解析出的 URL 命中回环/私网/保留段地址")
        if not target_url.startswith(("http://", "https://")):
            raise ValueError("target_url 必须使用 http:// 或 https://")
        if not 1 <= max_payloads <= 1200:
            raise ValueError("max_payloads 必须在 1-1200 范围内")
        if not 1 <= timeout <= 120:
            raise ValueError("timeout 必须在 1-120 秒范围内")
        scan_id = await manager.start({
            "target_url": target_url, "file_param": file_param,
            "max_payloads": max_payloads, "timeout": timeout,
            "scan_mode": scan_mode, "selected_extensions": selected_extensions,
            "headers": headers, "cookies": cookies, "proxies": proxies,
            "verify_ssl": bool(verify_ssl),
            "extra_fields": extra_fields or {},
            "raw_request": raw_request,
        })
        return {"scan_id": scan_id, "status": "queued"}

    @mcp.tool()
    async def uploadranger_status(scan_id: str) -> Dict[str, Any]:
        """查询扫描状态。"""
        return manager.status(scan_id)

    @mcp.tool()
    async def uploadranger_result(scan_id: str) -> Dict[str, Any]:
        """获取扫描结果；不存在时返回 not_found。"""
        data = manager.status(scan_id)
        if data.get("status") == "completed" and isinstance(data.get("result"), dict):
            result = data["result"]
            raw_findings = list(result.get("findings", []))
            data["raw_finding_count"] = len(raw_findings)
            groups = {}
            for finding in raw_findings:
                # 名称中的括号通常是 payload 类型，不应导致同一漏洞拆成多个报告项。
                raw_name = str(finding.get("name", ""))
                vuln_name = raw_name.split(" (", 1)[0].strip()
                key = (finding.get("url", ""), vuln_name, finding.get("risk_level", ""))
                group = groups.setdefault(key, {
                    **finding,
                    "name": vuln_name,
                    "count": 0,
                    "payloads": [],
                    "proofs": [],
                    "evidence": [],
                })
                group["count"] += 1
                if finding.get("payload") and finding["payload"] not in group["payloads"]:
                    group["payloads"].append(finding["payload"])
                if finding.get("proof") and finding["proof"] not in group["proofs"]:
                    group["proofs"].append(finding["proof"])
                group["evidence"].append({
                    "payload": finding.get("payload"),
                    "proof": finding.get("proof"),
                    "request_data": finding.get("request_data"),
                    "response_data": finding.get("response_data"),
                })
            aggregated = list(groups.values())
            data["finding_count"] = len(aggregated)
            data["finding_groups"] = aggregated
            data["findings_raw"] = raw_findings
            data["result"] = dict(result)
            data["result"]["findings"] = aggregated
            data["result"]["findings_raw"] = raw_findings
        return data

    @mcp.tool()
    async def uploadranger_logs(scan_id: str) -> Dict[str, Any]:
        """获取 GUI/MCP 任务日志。"""
        return manager.logs(scan_id)

    @mcp.tool()
    async def uploadranger_verify(
        upload_url: str,
        language: str = "php",
        timeout: int = 10,
        allow_local: bool = False,
    ) -> Dict[str, Any]:
        """验证已知上传 URL；只返回验证证据，不直接改变漏洞等级。"""
        from ..url_guard import safe_verification_url, is_blocked_host
        if not upload_url.startswith(("http://", "https://")):
            raise ValueError("upload_url 必须使用 http:// 或 https://")
        if not allow_local and is_blocked_host(upload_url):
            raise ValueError("默认禁止验证本地/私网 URL；仅在授权靶场中设置 allow_local=true")
        if not allow_local and not safe_verification_url(upload_url, upload_url, allow_cross_origin=False):
            raise ValueError("验证 URL 被安全策略拒绝（禁止私网/回环/非同源地址）")
        # C3：使用逐跳门禁的验证器（follow_redirects=False 手动跟随，每跳复查）。
        verifier = _GuardedWebShellVerifier(timeout=min(max(int(timeout), 1), 60), allow_local=allow_local)
        result = await verifier.verify(upload_url, language)
        return {
            "status": result.status.value,
            "verified_url": result.verified_url,
            "response_code": result.response_code,
            "execution_confirmed": result.execution_confirmed,
            "execution_output": result.execution_output,
            "error": result.error,
        }

    @mcp.tool()
    async def uploadranger_cancel(scan_id: str) -> Dict[str, Any]:
        """取消正在执行的扫描。"""
        return {"scan_id": scan_id, "cancelled": await manager.cancel(scan_id)}

    return mcp


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="UploadRanger MCP Server")
    parser.add_argument("--transport", choices=("stdio", "sse", "streamable-http"), default="stdio")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=4554)
    parser.add_argument("--danger-allow-remote", action="store_true",
                        help="允许 SSE/streamable-http 绑定非回环地址"
                             "（网络内任意主机可调用全部工具，需自担风险）")
    parser.add_argument("--proxy", default=None,
                        help="服务级默认上游代理（http/https/socks5/socks5h/socks4）；工具级 proxies 参数优先")
    args = parser.parse_args()

    # C4：网络传输默认只允许绑定回环地址；非回环必须显式 --danger-allow-remote。
    _LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}
    if args.transport != "stdio" and args.host.strip().strip("[]").lower() not in _LOOPBACK_HOSTS \
            and not args.danger_allow_remote:
        print(
            f"错误：--transport {args.transport} 绑定非回环地址（--host {args.host}）会把全部工具"
            "暴露给网络内任意主机（可发起上传扫描/验证，且无会话隔离）。"
            "请改用 --host 127.0.0.1/localhost/::1，或确认风险后显式加 --danger-allow-remote。",
            file=sys.stderr,
        )
        sys.exit(1)

    # C7：--proxy 启动时即归一化校验，非法直接退出，避免任务中途才报错。
    if args.proxy:
        try:
            ProxyConfig.parse(args.proxy)
        except ValueError as exc:
            print(f"错误：--proxy 配置非法：{exc}", file=sys.stderr)
            sys.exit(1)
        _CLI_PROXY = args.proxy

    server = create_server()
    if args.transport != "stdio":
        server.settings.host = args.host
        server.settings.port = args.port
        if os.environ.get("UPLOADRANGER_MCP_TOKEN", "").strip():
            _log_server("已启用 Bearer 鉴权（UPLOADRANGER_MCP_TOKEN），SSE/streamable-http 端点需携带有效 Token。")
        else:
            # C4：网络传输未配置鉴权时的醒目警告。
            print(
                "[MCP] 警告：SSE/streamable-http 模式无鉴权，网络内任意主机可调用全部工具；"
                "建议仅本机使用，或设置环境变量 UPLOADRANGER_MCP_TOKEN 启用 Bearer 鉴权。",
                file=sys.stderr, flush=True,
            )
    server.run(transport=args.transport)
