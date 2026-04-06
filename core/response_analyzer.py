#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
响应分析器 - 分析上传响应结果
"""

import re
import json
from urllib.parse import urljoin, urlparse


class ResponseAnalyzer:
    """响应分析器类"""
    
    def __init__(self):
        # 成功标识
        self.success_indicators = [
            "上传成功", "success", "uploaded", "file uploaded", "上传完成",
            "文件已上传", "upload complete", "successfully", "成功",
            "upload ok", "upload success", "文件上传成功", "上传OK",
            "上传成功！", "上传完成！", "文件已保存"
        ]
        
        # 失败标识
        self.failure_indicators = [
            "上传失败", "failed", "error", "invalid", "不允许",
            "文件类型错误", "file type not allowed", "upload failed",
            "forbidden", "blocked", "拒绝", "not allowed", "unsupported",
            "invalid file", "file too large", "extension not allowed",
            # 中文错误提示增强
            "文件未知", "上传失败！", "上传错误", "类型不允许",
            "后缀不允许", "格式不正确", "文件过大", "上传被阻止",
            "非法文件", "恶意文件", "危险文件", "禁止上传"
        ]
        
        # 文件路径模式
        self.path_patterns = [
            r'["\']([^"\']*uploads?/[^"\']+)["\']',
            r'["\']([^"\']*files?/[^"\']+)["\']',
            r'["\']([^"\']*images?/[^"\']+)["\']',
            r'["\']([^"\']*attachments?/[^"\']+)["\']',
            r'["\']([^"\']*media/[^"\']+)["\']',
            r'href=["\']?([^"\'>\s]+\.(?:php|asp|aspx|jsp))["\']?',
            r'src=["\']?([^"\'>\s]+\.(?:php|asp|aspx|jsp))["\']?',
            r'url[\("\']*[:\(]\s*["\']?([^"\'>\s]+)',
            r'path["\']?\s*[:=]\s*["\']?([^"\'>\s]+)',
            r'location["\']?\s*[:=]\s*["\']?([^"\'>\s]+)',
        ]
    
    def analyze(self, response, original_filename=None):
        """分析响应结果"""
        result = {
            "status_code": None,
            "is_success": False,
            "is_failure": False,
            "message": "",
            "uploaded_path": None,
            "full_url": None,
            "response_time": None,
            "content_length": 0,
            "indicators": [],
            "suggestions": [],
            # 新增: 详细提示信息
            "error_messages": [],
            "warning_messages": [],
            "success_messages": [],
            "hidden_indicators": []
        }
        
        # 处理错误响应
        if isinstance(response, dict) and "error" in response:
            result["message"] = f"请求错误: {response['error']}"
            result["is_failure"] = True
            return result
        
        try:
            result["status_code"] = response.status_code
            elapsed = getattr(response, 'elapsed', None) or getattr(response, 'elapsed_time', 0)
            result["response_time"] = elapsed.total_seconds() if hasattr(elapsed, 'total_seconds') else float(elapsed or 0)
            result["content_length"] = len(response.content)
            
            content = response.text.lower()
            original_content = response.text
            
            # 新增: 提取页面提示信息
            error_msgs = self._extract_page_messages(original_content, 'error')
            warning_msgs = self._extract_page_messages(original_content, 'warning')
            success_msgs = self._extract_page_messages(original_content, 'success')
            
            result["error_messages"] = error_msgs
            result["warning_messages"] = warning_msgs
            result["success_messages"] = success_msgs
            
            # 新增: 检测隐藏的成功指示
            hidden_indicators = self._detect_hidden_indicators(original_content)
            result["hidden_indicators"] = hidden_indicators

            # 提取上传路径（优先做，供后续综合判断使用）
            uploaded_path = self._extract_upload_path(original_content, response.url)
            if uploaded_path:
                result["uploaded_path"] = uploaded_path
                result["full_url"] = urljoin(response.url, uploaded_path)
            
            # 检查成功标识
            for indicator in self.success_indicators:
                if indicator.lower() in content:
                    result["is_success"] = True
                    result["indicators"].append(f"发现成功标识: {indicator}")
            
            # 检查失败标识
            for indicator in self.failure_indicators:
                if indicator.lower() in content:
                    result["is_failure"] = True
                    result["indicators"].append(f"发现失败标识: {indicator}")
            
            # 新增: 根据提取的消息判断
            if success_msgs and not error_msgs:
                result["is_success"] = True
            if error_msgs and not success_msgs:
                result["is_failure"] = True
            
            # 根据状态码和消息综合判断
            # 修复：即使状态码200，如果有错误消息也判定为失败
            if response.status_code == 200:
                # 如果有明确的错误消息，判定为失败
                if error_msgs:
                    result["is_success"] = False
                    result["is_failure"] = True
                # 如果有成功消息或上传路径，判定为成功
                elif success_msgs or result["uploaded_path"]:
                    result["is_success"] = True
                # 如果没有错误也没有成功标识，保持未知
                else:
                    # 检查是否有其他负面指示
                    if any(indicator in content for indicator in ["失败", "错误", "unknown", "invalid"]):
                        result["is_failure"] = True
                        result["is_success"] = False
                    else:
                        # 无明确成功/失败信号时不默认成功，避免误报
                        result["is_success"] = False
                        result["suggestions"].append("无法确定上传结果，建议手动验证")
            elif 300 <= response.status_code < 400:
                # 重定向本身不代表上传成功，避免 Location 指向页面/接口导致误报
                if result["uploaded_path"] and self._looks_like_file_resource(result["uploaded_path"]):
                    result["is_success"] = True
                else:
                    result["is_success"] = False
                    if not result["is_failure"]:
                        result["suggestions"].append("收到重定向响应，建议跟进重定向页或手动验证")
            elif response.status_code in [403, 415, 400]:
                result["is_failure"] = True
                result["suggestions"].append("可能需要使用绕过技术")
            
            # 生成分析消息
            if result["is_success"] and result["uploaded_path"]:
                result["message"] = f"上传成功！文件路径: {result['uploaded_path']}"
            elif result["is_success"]:
                result["message"] = "上传可能成功，但未找到文件路径"
            elif result["is_failure"]:
                # 新增: 包含错误消息
                if error_msgs:
                    result["message"] = f"上传被阻止: {error_msgs[0]}"
                else:
                    result["message"] = "上传被阻止"
            else:
                result["message"] = "无法确定上传结果"
            
        except Exception as e:
            result["message"] = f"分析错误: {str(e)}"
        
        return result
    
    def _extract_page_messages(self, html_content, msg_type):
        """提取页面中的提示信息
        
        Args:
            html_content: HTML内容
            msg_type: 消息类型 ('error', 'warning', 'success', 'info')
        
        Returns:
            List[str]: 提取的消息列表
        """
        messages = []
        
        # 通用CSS类名模式
        class_patterns = {
            'error': [
                r'<div[^>]*class="[^"]*error[^"]*"[^>]*>(.*?)</div>',
                r'<div[^>]*class="[^"]*alert-error[^"]*"[^>]*>(.*?)</div>',
                r'<div[^>]*class="[^"]*alert-danger[^"]*"[^>]*>(.*?)</div>',
                r'<span[^>]*class="[^"]*error[^"]*"[^>]*>(.*?)</span>',
                r'<p[^>]*class="[^"]*error[^"]*"[^>]*>(.*?)</p>',
                r'<div[^>]*id="[^"]*error[^"]*"[^>]*>(.*?)</div>',
                # 新增：针对upload-labs等靶场的提示样式
                r'<div[^>]*style="[^"]*color:\s*red[^"]*"[^>]*>(.*?)</div>',
                r'<span[^>]*style="[^"]*color:\s*red[^"]*"[^>]*>(.*?)</span>',
                r'<font[^>]*color="[^"]*red[^"]*"[^>]*>(.*?)</font>',
                r'<div[^>]*class="[^"]*msg[^"]*"[^>]*>(.*?)</div>',
                r'<div[^>]*class="[^"]*tip[^"]*"[^>]*>(.*?)</div>',
                r'<div[^>]*class="[^"]*notice[^"]*"[^>]*>(.*?)</div>',
            ],
            'warning': [
                r'<div[^>]*class="[^"]*warning[^"]*"[^>]*>(.*?)</div>',
                r'<div[^>]*class="[^"]*alert-warning[^"]*"[^>]*>(.*?)</div>',
                r'<span[^>]*class="[^"]*warning[^"]*"[^>]*>(.*?)</span>',
                r'<div[^>]*style="[^"]*color:\s*orange[^"]*"[^>]*>(.*?)</div>',
                r'<div[^>]*style="[^"]*color:\s*#ff[^"]*"[^>]*>(.*?)</div>',
            ],
            'success': [
                r'<div[^>]*class="[^"]*success[^"]*"[^>]*>(.*?)</div>',
                r'<div[^>]*class="[^"]*alert-success[^"]*"[^>]*>(.*?)</div>',
                r'<span[^>]*class="[^"]*success[^"]*"[^>]*>(.*?)</span>',
                r'<div[^>]*style="[^"]*color:\s*green[^"]*"[^>]*>(.*?)</div>',
                r'<font[^>]*color="[^"]*green[^"]*"[^>]*>(.*?)</font>',
            ],
            'info': [
                r'<div[^>]*class="[^"]*info[^"]*"[^>]*>(.*?)</div>',
                r'<div[^>]*class="[^"]*alert-info[^"]*"[^>]*>(.*?)</div>',
                r'<span[^>]*class="[^"]*info[^"]*"[^>]*>(.*?)</span>',
                r'<div[^>]*style="[^"]*color:\s*blue[^"]*"[^>]*>(.*?)</div>',
            ]
        }
        
        patterns = class_patterns.get(msg_type, [])
        
        for pattern in patterns:
            try:
                matches = re.findall(pattern, html_content, re.DOTALL | re.IGNORECASE)
                for match in matches:
                    # 清理HTML标签
                    clean_text = re.sub(r'<[^>]+>', '', match).strip()
                    if clean_text and len(clean_text) > 2:
                        messages.append(clean_text)
            except Exception:
                continue
        
        return messages
    
    def _detect_hidden_indicators(self, html_content):
        """检测隐藏的成功指示
        
        有些网站可能用JavaScript、注释等方式隐藏提示信息
        
        Args:
            html_content: HTML内容
        
        Returns:
            List[str]: 检测到的隐藏指示列表
        """
        indicators = []
        
        # 检测JavaScript中的提示
        js_patterns = [
            r'alert\s*\(\s*["\']([^"\']+)["\']',
            r'console\.log\s*\(\s*["\']([^"\']+)["\']',
            r'toast\s*\(\s*["\']([^"\']+)["\']',
            r'notify\s*\(\s*["\']([^"\']+)["\']',
        ]
        
        for pattern in js_patterns:
            matches = re.findall(pattern, html_content, re.IGNORECASE)
            for match in matches:
                if match and len(match) > 2:
                    indicators.append(f"JS提示: {match}")
        
        # 检测HTML注释中的提示
        comment_pattern = r'<!--\s*(.+?)\s*-->'
        comment_matches = re.findall(comment_pattern, html_content, re.DOTALL)
        for match in comment_matches:
            if any(keyword in match.lower() for keyword in ['upload', 'success', 'error', 'fail', 'uploaded']):
                indicators.append(f"注释提示: {match.strip()}")
        
        # 检测内联样式红色文本（upload-labs等常见）
        inline_red_pattern = r'<[^>]+style="[^"]*color:\s*#(?:ff0000|f00|red)[^"]*"[^>]*>(.*?)</[^>]+>'
        red_matches = re.findall(inline_red_pattern, html_content, re.IGNORECASE | re.DOTALL)
        for match in red_matches:
            clean = re.sub(r'<[^>]+>', '', match).strip()
            if clean and len(clean) > 2:
                indicators.append(f"红色提示: {clean}")
        
        # 检测data属性中的提示
        data_patterns = [
            r'data-message=["\']([^"\']+)["\']',
            r'data-error=["\']([^"\']+)["\']',
            r'data-success=["\']([^"\']+)["\']',
            r'data-result=["\']([^"\']+)["\']',
        ]
        
        for pattern in data_patterns:
            matches = re.findall(pattern, html_content, re.IGNORECASE)
            for match in matches:
                if match and len(match) > 2:
                    indicators.append(f"Data属性: {match}")
        
        return indicators
    
    def _extract_upload_path(self, content, base_url):
        """提取上传文件路径"""
        for pattern in self.path_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                # 返回第一个匹配的路径
                path = matches[0]
                # 清理路径
                path = path.strip('"\'<>')
                if self._looks_like_file_resource(path) and not self._same_endpoint(path, base_url):
                    return path
        
        # 尝试从JSON响应中提取
        try:
            data = json.loads(content)
            # 常见的路径字段名
            path_keys = ['path', 'url', 'file', 'filename', 'location', 
                        'link', 'src', 'href', 'file_path', 'file_url']
            for key in path_keys:
                if key in data:
                    val = str(data[key])
                    if self._looks_like_file_resource(val) and not self._same_endpoint(val, base_url):
                        return val
        except:
            pass
        
        return None

    def _looks_like_file_resource(self, value: str) -> bool:
        v = (value or "").strip()
        if not v:
            return False
        if " " in v:
            return False
        if v.startswith("http://") or v.startswith("https://"):
            try:
                p = urlparse(v).path or ""
            except Exception:
                p = ""
        else:
            p = v
        p = p.split("?", 1)[0].split("#", 1)[0].rstrip("/")
        if not p:
            return False
        last = p.rsplit("/", 1)[-1]
        if last in (".htaccess", ".user.ini", "web.config"):
            return True
        if "." not in last:
            return False
        if last.endswith("."):
            return False
        ext = last.rsplit(".", 1)[-1]
        if not ext or len(ext) > 10:
            return False
        if re.fullmatch(r"[a-zA-Z0-9]{1,10}", ext) is None:
            return False
        return True

    def _same_endpoint(self, a: str, b: str) -> bool:
        try:
            pa = urlparse(a)
            pb = urlparse(str(b))
            if pa.scheme and pb.scheme:
                return (pa.scheme, pa.netloc, pa.path) == (pb.scheme, pb.netloc, pb.path)
            return (pa.path or a) == (pb.path or str(b))
        except Exception:
            return False
    
    def check_webshell_execution(self, response, expected_content=None):
        """检查webshell是否可执行"""
        result = {
            "is_executable": False,
            "evidence": [],
            "output": None
        }
        
        if isinstance(response, dict) and "error" in response:
            return result
        
        content = response.text
        
        # 检查PHP信息特征
        php_indicators = [
            "phpinfo", "PHP Version", "System", "Build Date",
            "Server API", "Loaded Extensions"
        ]
        
        for indicator in php_indicators:
            if indicator in content:
                result["is_executable"] = True
                result["evidence"].append(f"发现PHP特征: {indicator}")
        
        # 检查命令执行输出特征
        command_indicators = [
            r"root:.*:0:0:",  # /etc/passwd
            r"uid=\d+.*gid=\d+",  # id命令输出
            r"Windows NT",  # Windows系统
            r"Microsoft Windows",  # Windows
            r"Directory of",  # Windows dir命令
        ]
        
        for pattern in command_indicators:
            if re.search(pattern, content):
                result["is_executable"] = True
                result["evidence"].append(f"发现命令执行特征: {pattern}")
        
        # 检查预期内容
        if expected_content and expected_content in content:
            result["is_executable"] = True
            result["evidence"].append("发现预期响应内容")
        
        result["output"] = content[:1000]  # 限制输出长度
        
        return result
    
    def compare_responses(self, baseline_response, test_response):
        """比较两个响应的差异"""
        differences = {
            "status_code_changed": False,
            "content_changed": False,
            "size_changed": False,
            "differences": []
        }
        
        if isinstance(baseline_response, dict) or isinstance(test_response, dict):
            return differences
        
        # 比较状态码
        if baseline_response.status_code != test_response.status_code:
            differences["status_code_changed"] = True
            differences["differences"].append(
                f"状态码变化: {baseline_response.status_code} -> {test_response.status_code}"
            )
        
        # 比较内容长度
        baseline_len = len(baseline_response.content)
        test_len = len(test_response.content)
        
        if abs(baseline_len - test_len) > 100:  # 允许100字节的差异
            differences["size_changed"] = True
            differences["differences"].append(
                f"内容长度变化: {baseline_len} -> {test_len}"
            )
        
        # 简单比较内容
        if baseline_response.text != test_response.text:
            differences["content_changed"] = True
            differences["differences"].append("响应内容发生变化")
        
        return differences
    
    def detect_waf(self, response):
        """检测是否存在WAF"""
        waf_signatures = {
            "Cloudflare": ["cloudflare", "cf-ray", "__cfduid"],
            "AWS WAF": ["awselb", "aws-waf"],
            "ModSecurity": ["mod_security", "modsecurity"],
            "Sucuri": ["sucuri", "x-sucuri"],
            "Incapsula": ["incap_ses", "visid_incap"],
            "Akamai": ["akamai", "akamai-ghost"],
            "F5 BIG-IP": ["bigip", "f5", "x-waf-status"],
            "Imperva": ["imperva", "incap_ses"],
            "Barracuda": ["barra"],
            "Fortinet": ["fortigate", "fortiwaf"],
        }
        
        detected_wafs = []
        
        if isinstance(response, dict):
            return detected_wafs
        
        headers_str = str(response.headers).lower()
        content = response.text.lower()
        
        for waf_name, signatures in waf_signatures.items():
            for sig in signatures:
                if sig.lower() in headers_str or sig.lower() in content:
                    detected_wafs.append(waf_name)
                    break
        
        # 检查特定的WAF阻止页面
        if response.status_code == 403:
            if "access denied" in content or "forbidden" in content:
                detected_wafs.append("Generic WAF (403 Forbidden)")
        
        return detected_wafs
    
    def get_security_headers(self, response):
        """获取安全相关响应头"""
        security_headers = {}
        
        if isinstance(response, dict):
            return security_headers
        
        important_headers = [
            "X-Frame-Options",
            "X-XSS-Protection",
            "X-Content-Type-Options",
            "Content-Security-Policy",
            "Strict-Transport-Security",
            "X-Permitted-Cross-Domain-Policies",
            "Referrer-Policy",
            "Feature-Policy",
            "Server",
            "X-Powered-By"
        ]
        
        for header in important_headers:
            value = response.headers.get(header)
            if value:
                security_headers[header] = value
        
        return security_headers
