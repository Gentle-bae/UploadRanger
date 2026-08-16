"""UploadRanger MCP Server（本地 stdio）。

默认不自动启动；通过 ``python -m core.mcp.server`` 显式运行。
扫描使用任务 ID 异步执行，避免 MCP 请求长期阻塞。
"""

import asyncio
import uuid
import traceback
import sys
from pathlib import Path
from datetime import datetime
from typing import Any, Dict, Optional

from mcp.server.fastmcp import FastMCP

from ..async_scanner import AsyncScanner
from ..auto_verifier import WebShellVerifier
from ..request_parser import parse_raw_request

MCP_LOG_FILE = Path(__file__).resolve().parents[2] / ".uploadranger_mcp.log"


class ScanManager:
    def __init__(self) -> None:
        self.tasks: Dict[str, asyncio.Task] = {}
        self.results: Dict[str, Any] = {}
        self.progress: Dict[str, Dict[str, Any]] = {}
        self.log_callbacks = []

    def emit_log(self, scan_id: str, message: str) -> None:
        entry = {"timestamp": datetime.now().isoformat(timespec="seconds"), "message": str(message)}
        self.progress.setdefault(scan_id, {"percent": 0, "message": "queued", "logs": []})["logs"].append(entry)
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
        except OSError:
            pass

    async def start(self, params: Dict[str, Any]) -> str:
        scan_id = f"scan_{uuid.uuid4().hex[:12]}"
        task = asyncio.create_task(self._run(scan_id, params))
        self.tasks[scan_id] = task
        self.progress[scan_id] = {"percent": 0, "message": "queued", "logs": []}
        self.emit_log(scan_id, f"扫描任务已创建：{scan_id}")
        return scan_id

    async def _run(self, scan_id: str, params: Dict[str, Any]) -> None:
        scanner = AsyncScanner()
        def on_log(message: str):
            self.emit_log(scan_id, message)
        def on_progress(message: str, percent: int):
            state = self.progress.setdefault(scan_id, {"percent": 0, "message": "running", "logs": []})
            state["percent"] = max(0, min(100, int(percent)))
            state["message"] = str(message)
            self.emit_log(scan_id, f"进度 {state['percent']}%：{message}")
        try:
            result = await scanner.scan(
                target_url=params["target_url"],
                file_param=params.get("file_param", "file"),
                headers=params.get("headers"),
                cookies=params.get("cookies"),
                proxies=params.get("proxies"),
                on_log_callback=on_log,
                progress_callback=on_progress,
                max_payloads=min(int(params.get("max_payloads", 100)), 1200),
                timeout=min(int(params.get("timeout", 30)), 120),
                scan_mode=params.get("scan_mode", "security"),
                selected_extensions=params.get("selected_extensions"),
                extra_fields=params.get("extra_fields") or None,
            )
            self.progress[scan_id]["percent"] = 100
            self.progress[scan_id]["message"] = "completed"
            self.results[scan_id] = {"status": "completed", "result": result.to_dict() if hasattr(result, "to_dict") else result}
            self.emit_log(scan_id, "扫描完成")
        except asyncio.CancelledError:
            self.results[scan_id] = {"status": "cancelled"}
            raise
        except Exception as exc:
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


def create_server() -> FastMCP:
    mcp = FastMCP("UploadRanger")
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
    ) -> Dict[str, Any]:
        """启动一次受限文件上传扫描，返回 scan_id。"""
        if raw_request:
            parsed = parse_raw_request(raw_request, base_url=target_url or None)
            target_url = parsed.url
            file_param = parsed.file_parts[0].field if parsed.file_parts else file_param
            headers = parsed.headers
            extra_fields = parsed.form_fields
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
        verifier = WebShellVerifier(timeout=min(max(int(timeout), 1), 60))
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
    parser = argparse.ArgumentParser()
    parser.add_argument("--transport", choices=("stdio", "sse", "streamable-http"), default="stdio")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=4554)
    args = parser.parse_args()
    server = create_server()
    if args.transport != "stdio":
        server.settings.host = args.host
        server.settings.port = args.port
    server.run(transport=args.transport)
