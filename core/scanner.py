#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
上传扫描器 - 核心扫描引擎 v2.0

改造要点：
1. 集成 RawHTTPClient - 字节级HTTP控制
2. 集成 SmartAnalyzer - 三级响应判定
3. 支持 filename 编码绕过
4. 支持自定义 boundary

"""

import os
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin

try:
    from .http_client import HTTPClient  # 保留用于兼容性
    from .raw_http_client import RawHTTPClient, MultipartPart, FilenameEncoder
    from .form_parser import FormParser
    from .response_analyzer import ResponseAnalyzer  # 保留用于兼容性
    from .smart_analyzer import SmartResponseAnalyzer
    from ..payloads.webshells import WebShellGenerator
    from ..payloads.bypass_payloads import BypassPayloadGenerator
    from ..payloads.polyglots import PolyglotGenerator
    from ..payloads.intruder_payloads import PayloadFactory, FuzzConfig, generate_intruder_payloads
except ImportError:
    from core.http_client import HTTPClient
    from core.raw_http_client import RawHTTPClient, MultipartPart, FilenameEncoder
    from core.form_parser import FormParser
    from core.response_analyzer import ResponseAnalyzer
    from core.smart_analyzer import SmartResponseAnalyzer
    from payloads.webshells import WebShellGenerator
    from payloads.bypass_payloads import BypassPayloadGenerator
    from payloads.polyglots import PolyglotGenerator
    from payloads.intruder_payloads import PayloadFactory, FuzzConfig, generate_intruder_payloads


class UploadScanner:
    """文件上传漏洞扫描器 v2.0"""
    
    def __init__(self, target_url, proxy=None, timeout=30, threads=5, delay=0,
                 cookies=None, headers=None, use_raw_client=True):
        """
        初始化扫描器
        
        Args:
            target_url: 目标URL
            proxy: 代理设置
            timeout: 超时时间
            threads: 线程数
            delay: 请求延迟
            cookies: Cookie字典
            headers: 请求头字典
            use_raw_client: 是否使用RawHTTPClient（推荐开启）
        """
        self.target_url = target_url
        self.proxy = proxy
        self.timeout = timeout
        self.threads = threads
        self.delay = delay
        self.use_raw_client = use_raw_client  # v2.0: 控制使用哪个客户端
        
        # 初始化组件
        self.http_client = HTTPClient(timeout=timeout, proxy=proxy, delay=delay)
        
        # v2.0: 新增 RawHTTPClient
        if self.use_raw_client:
            self.raw_http_client = RawHTTPClient(
                timeout=timeout,
                proxy=proxy,
                delay=delay
            )
        
        self.form_parser = FormParser(self.http_client)
        
        # v2.0: 新增 SmartAnalyzer，同时保留旧的用于兼容性
        self.response_analyzer = ResponseAnalyzer()
        self.smart_analyzer = SmartResponseAnalyzer()
        
        self.shell_generator = WebShellGenerator()
        self.bypass_generator = BypassPayloadGenerator()
        self.polyglot_generator = PolyglotGenerator()
        
        # Intruder Payload Factory
        self.intruder_factory = PayloadFactory()
        
        # v2.0: Payload配置
        self.payload_config = FuzzConfig()
        self.payload_config.max_payloads = 1200  # 增加payload数量
        
        # 设置认证信息
        if cookies:
            self.http_client.set_cookie(cookies)
            if self.use_raw_client:
                self.raw_http_client.set_cookie(cookies)
        if headers:
            for key, value in headers.items():
                self.http_client.set_header(key, value)
                if self.use_raw_client:
                    self.raw_http_client.set_header(key, value)
        
        # 扫描结果
        self.results = []
        self.forms = []
        self.is_running = False
        self.progress_callback = None
        
        # 统计信息
        self.stats = {
            "total_tests": 0,
            "successful_uploads": 0,
            "failed_uploads": 0,
            "errors": 0,
            "start_time": None,
            "end_time": None
        }
    
    def set_progress_callback(self, callback):
        """设置进度回调函数"""
        self.progress_callback = callback
    
    def _update_progress(self, message, percent=None):
        """更新进度"""
        if self.progress_callback:
            self.progress_callback(message, percent)
    
    def discover_forms(self):
        """发现上传表单"""
        self._update_progress("正在发现上传表单...", 10)
        
        self.forms = self.form_parser.find_upload_forms(self.target_url)
        
        self._update_progress(f"发现 {len(self.forms)} 个上传表单", 20)
        
        return self.forms
    
    def scan_form(self, form_info, test_config=None):
        """扫描单个表单"""
        if test_config is None:
            test_config = {
                "test_extensions": [".php", ".asp", ".aspx", ".jsp"],
                "test_bypass": True,
                "test_polyglots": True,
                "test_webshells": True
            }
        
        results = []
        
        # 获取表单信息
        action = form_info.get("action", self.target_url)
        method = form_info.get("method", "POST")
        file_fields = form_info.get("file_fields", [])
        other_fields = form_info.get("other_fields", {})
        
        if not file_fields:
            return results
        
        file_field = file_fields[0]["name"]  # 使用第一个文件字段
        
        # 测试基础上传
        self._update_progress(f"测试表单: {action}", None)
        
        # 生成测试payloads (传入form_info用于生成intruder payloads)
        payloads = self._generate_test_payloads(test_config, form_info=form_info)
        
        total = len(payloads)
        lock = threading.Lock()
        completed = [0]

        def _run_one(idx_payload):
            idx, payload = idx_payload
            if not self.is_running:
                return None
            try:
                self._update_progress(
                    f"测试 {payload.get('filename', 'unknown')} ({idx+1}/{total})",
                    20 + (idx / total * 70)
                )
                result = self._test_upload(action, file_field, payload, other_fields)
                with lock:
                    self.stats["total_tests"] += 1
                    completed[0] += 1
                    if result:
                        analysis = result.get("analysis", {})
                        if analysis.get("is_success") and analysis.get("uploaded_path"):
                            self.stats["successful_uploads"] += 1
                            if test_config.get("test_webshells"):
                                result["execution_test"] = self._test_webshell_execution(result)
                return result
            except Exception as e:
                with lock:
                    self.stats["errors"] += 1
                return {"error": str(e), "payload": payload}

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = executor.map(_run_one, enumerate(payloads))
            for r in futures:
                if r:
                    results.append(r)

        return results
    
    def _generate_test_payloads(self, test_config, form_info=None):
        """生成测试payloads
        
        Args:
            test_config: 测试配置字典
            form_info: 表单信息 (用于生成multipart模板)
        
        Returns:
            List[Dict]: payload列表
        """
        payloads = []
        
        extensions = test_config.get("test_extensions", [".php"])
        
        # 基础payloads
        for ext in extensions:
            payloads.append({
                "filename": f"test{ext}",
                "content": b"<?php echo 'test'; ?>",
                "content_type": "application/octet-stream",
                "description": f"基础{ext}测试"
            })
        
        # 绕过技术payloads (使用原有的bypass_generator)
        if test_config.get("test_bypass", True):
            for ext in extensions:
                bypass_payloads = self.bypass_generator.generate_all_payloads(
                    "shell", ext
                )
                for bp in bypass_payloads:
                    payloads.append({
                        "filename": bp["filename"],
                        "content": b"<?php echo 'test'; ?>",
                        "content_type": bp.get("content_type", "application/octet-stream"),
                        "description": bp.get("description", "绕过测试"),
                        "technique": bp.get("technique", "unknown"),
                        "severity": bp.get("severity", "中")
                    })
        
        # 新增: 使用Intruder Payload Factory生成高级payloads
        if test_config.get("use_intruder_payloads", True) and form_info:
            try:
                # 构建multipart模板
                template = self._build_multipart_template(form_info)
                if template:
                    # 生成intruder payloads
                    intruder_payloads = self.intruder_factory.generate_payloads(template)

                    # 使用配置的 max_payloads 上限，不再硬编码
                    intruder_limit = self.payload_config.max_payloads
                    for payload_template in intruder_payloads[:intruder_limit]:
                        parsed = self._parse_intruder_payload(payload_template)
                        if parsed:
                            payloads.append(parsed)
            except Exception as e:
                print(f"生成Intruder payloads失败: {e}")
        
        # Polyglot payloads
        if test_config.get("test_polyglots", True):
            polyglots = self.polyglot_generator.get_all_polyglots()
            for name, info in polyglots.items():
                try:
                    content = info["generator"]()
                    payloads.append({
                        "filename": f"test{name}{info['extension']}",
                        "content": content if isinstance(content, bytes) else content.encode(),
                        "content_type": "application/octet-stream",
                        "description": info["description"],
                        "technique": "polyglot",
                        "severity": "高"
                    })
                except Exception as e:
                    print(f"生成polyglot失败 {name}: {e}")
        
        # Webshell payloads
        if test_config.get("test_webshells", True):
            shells = self.shell_generator.get_php_shells()
            for name, info in shells.items():
                if name in ["simple_eval", "post_eval", "get_shell"]:
                    payloads.append({
                        "filename": f"shell_{name}.php",
                        "content": info["code"].encode(),
                        "content_type": "application/octet-stream",
                        "description": info["name"],
                        "technique": "webshell",
                        "severity": "高",
                        "usage": info.get("usage", "")
                    })
        
        return payloads
    
    def _build_multipart_template(self, form_info):
        """【修复】构建完整的multipart/form-data HTTP请求模板
        
        Args:
            form_info: 表单信息字典
        
        Returns:
            str: 完整HTTP请求模板字符串（包含请求行和Host头部）
        """
        if not form_info:
            return None
        
        action = form_info.get("action", self.target_url)
        file_fields = form_info.get("file_fields", [])
        other_fields = form_info.get("other_fields", {})
        
        if not file_fields:
            return None
        
        # 解析URL获取路径和Host
        from urllib.parse import urlparse
        parsed = urlparse(action)
        host = parsed.netloc or parsed.hostname or 'localhost'
        path = parsed.path or '/'
        if parsed.query:
            path += '?' + parsed.query
        
        # 构建简单的multipart模板
        boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW"
        file_field = file_fields[0]["name"]
        
        # 【修复】构建完整的HTTP请求，包含请求行和必要头部
        template = f"""POST {path} HTTP/1.1
Host: {host}
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary={boundary}
Connection: keep-alive

--{boundary}
Content-Disposition: form-data; name="{file_field}"; filename="test.jpg"
Content-Type: image/jpeg

[binary content]
"""
        # 添加其他表单字段
        for field_name, field_value in other_fields.items():
            template += f"""--{boundary}
Content-Disposition: form-data; name="{field_name}"

{field_value}
"""
        
        template += f"--{boundary}--\n"
        
        return template
    
    def _parse_intruder_payload(self, payload_template):
        """解析intruder payload模板
        
        Args:
            payload_template: HTTP请求模板字符串
        
        Returns:
            Dict: 解析后的payload字典
        """
        import re
        
        # 提取filename
        filename_match = re.search(r'filename="([^"]+)"', payload_template)
        if not filename_match:
            return None
        
        filename = filename_match.group(1)
        
        # 提取Content-Type
        ct_match = re.search(r'Content-Type:\s*([^\r\n]+)', payload_template)
        content_type = ct_match.group(1).strip() if ct_match else "application/octet-stream"
        
        # 提取content (简化处理)
        content_match = re.search(r'Content-Type:[^\r\n]*\r\n\r\n(.*?)(?:\r\n--|\Z)', payload_template, re.DOTALL)
        content = content_match.group(1).encode() if content_match else b"<?php echo 'test'; ?>"
        
        return {
            "filename": filename,
            "content": content,
            "content_type": content_type,
            "description": "Intruder高级绕过",
            "technique": "intruder",
            "severity": "高"
        }
    
    def _test_upload(self, url, field_name, payload, other_fields):
        """
        测试单个上传 v2.0
        
        优先使用 RawHTTPClient 进行字节级控制
        """
        filename = payload.get("filename", "test.txt")
        content = payload.get("content", b"")
        content_type = payload.get("content_type", "application/octet-stream")
        
        # 处理magic bytes
        if "magic_bytes" in payload:
            content = payload["magic_bytes"] + content
        
        # v2.0: 获取额外配置
        boundary = payload.get("boundary")
        filename_encoding = payload.get("filename_encoding")
        
        # v2.0: 优先使用RawHTTPClient
        if self.use_raw_client and self.raw_http_client:
            response = self.raw_http_client.upload_file(
                url=url,
                field_name=field_name,
                filename=filename,
                content=content,
                content_type=content_type,
                boundary=boundary,
                filename_encoding=filename_encoding,
                extra_fields=other_fields
            )
            # SmartAnalyzer 返回 AnalysisResult dataclass，统一转为 dict
            ar = self.smart_analyzer.analyze(response, filename)
            analysis = {
                "is_success": ar.is_success,
                "is_failure": ar.is_failure,
                "uploaded_path": ar.uploaded_path,
                "full_url": ar.full_url,
                "confidence": ar.confidence,
                "status_code": ar.status_code,
                "evidence": ar.evidence,
                "reasons": ar.reasons,
                "waf_detected": ar.waf_detected,
                "waf_names": ar.waf_names,
                "error_messages": ar.error_messages,
                "success_messages": ar.success_messages,
                "suggestions": ar.suggestions,
                "response_time": ar.response_time,
                "content_length": ar.content_length,
            }
        else:
            # 降级使用旧的HTTPClient，response_analyzer 直接返回 dict
            response = self.http_client.upload_bytes(
                url, field_name, content, filename,
                data=other_fields, headers={}, content_type=content_type
            )
            analysis = self.response_analyzer.analyze(response, filename)

        result = {
            "filename": filename,
            "description": payload.get("description", ""),
            "technique": payload.get("technique", "direct"),
            "severity": payload.get("severity", "低"),
            "analysis": analysis,
            "boundary": boundary,
            "filename_encoding": filename_encoding
        }

        return result

    def _test_webshell_execution(self, upload_result):
        """测试webshell是否可执行"""
        full_url = upload_result.get("analysis", {}).get("full_url")

        if not full_url:
            return None

        # 尝试访问上传的文件
        response = self.http_client.get(full_url)

        execution_test = self.response_analyzer.check_webshell_execution(response)
        
        return execution_test
    
    def scan(self, test_config=None):
        """执行完整扫描"""
        self.is_running = True
        self.stats["start_time"] = time.time()
        
        self._update_progress("开始扫描...", 0)
        
        # 发现表单
        if not self.forms:
            self.discover_forms()
        
        if not self.forms:
            self._update_progress("未发现上传表单", 100)
            return []
        
        # 扫描每个表单
        all_results = []
        for i, form in enumerate(self.forms):
            if not self.is_running:
                break
            
            self._update_progress(f"扫描表单 {i+1}/{len(self.forms)}", 30 + i * 10)
            
            results = self.scan_form(form, test_config)
            all_results.extend(results)
            
            form["scan_results"] = results
        
        self.stats["end_time"] = time.time()
        self.is_running = False
        
        self._update_progress("扫描完成", 100)
        
        self.results = all_results
        return all_results
    
    def stop(self):
        """停止扫描"""
        self.is_running = False
        self._update_progress("扫描已停止", 100)
    
    def get_statistics(self):
        """获取统计信息"""
        if self.stats["start_time"] and self.stats["end_time"]:
            duration = self.stats["end_time"] - self.stats["start_time"]
        else:
            duration = 0
        
        return {
            **self.stats,
            "duration": duration,
            "forms_found": len(self.forms),
            "results_count": len(self.results)
        }
    
    def get_vulnerable_uploads(self):
        """获取存在漏洞的上传结果"""
        vulnerable = []
        
        for result in self.results:
            analysis = result.get("analysis", {})
            
            # 检查是否成功上传webshell
            if analysis.get("is_success"):
                execution_test = result.get("execution_test", {})
                if execution_test and execution_test.get("is_executable"):
                    vulnerable.append(result)
                elif result.get("technique") == "webshell":
                    vulnerable.append(result)
        
        return vulnerable
    
    def verify_upload(self, uploaded_url):
        """验证上传文件是否可访问"""
        response = self.http_client.get(uploaded_url)
        
        if isinstance(response, dict):
            return False, response.get("error", "Unknown error")
        
        return response.status_code == 200, {
            "status_code": response.status_code,
            "content_length": len(response.content)
        }
    
    def close(self):
        """清理资源"""
        self.http_client.close()
        
        # v2.0: 关闭RawHTTPClient
        if self.use_raw_client and self.raw_http_client:
            self.raw_http_client.close()
