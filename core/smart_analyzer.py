#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Smart Response Analyzer - 智能响应分析器

三级响应判定机制：
1. Level 1: 快速排除 - 明显的失败响应
2. Level 2: 证据打分 - 根据多个指标计算置信度
3. Level 3: 执行验证 - 需要验证的实际利用可行性

"""

import re
import json
from urllib.parse import urljoin
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field


# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class AnalysisResult:
    """分析结果"""
    # 基础判定
    status_code: int = 0
    is_success: bool = False
    is_failure: bool = False
    confidence: float = 0.0  # 0.0-1.0
    
    # 判定原因
    reasons: List[str] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)
    
    # 路径信息
    uploaded_path: Optional[str] = None
    full_url: Optional[str] = None
    relative_path: Optional[str] = None
    
    # 详细分析
    error_messages: List[str] = field(default_factory=list)
    warning_messages: List[str] = field(default_factory=list)
    success_messages: List[str] = field(default_factory=list)
    hidden_indicators: List[str] = field(default_factory=list)
    
    # 建议
    suggestions: List[str] = field(default_factory=list)
    
    # 技术细节
    technique_hints: List[str] = field(default_factory=list)  # 检测到的绕过技术提示
    waf_detected: bool = False
    waf_names: List[str] = field(default_factory=list)
    
    # 元数据
    response_time: float = 0.0
    content_length: int = 0
    raw_content: str = ""


@dataclass  
class ScoringRule:
    """打分规则"""
    pattern: str
    weight: float  # 正数=加分, 负数=减分
    category: str  # 'success', 'failure', 'neutral'
    description: str


# =============================================================================
# Smart Response Analyzer
# =============================================================================

class SmartResponseAnalyzer:
    """
    智能响应分析器
    
    使用三级判定机制来提高准确性：
    - Level 1: 快速排除明显的失败
    - Level 2: 综合打分
    - Level 3: 执行验证（需要额外请求）
    """
    
    # Level 1: 快速排除规则（应用于响应 body 文本，不包含 HTTP 状态行）
    # 注意：状态码检查在 analyze() 中单独通过 status_code 参数处理
    QUICK_FAIL_PATTERNS = [
        # 明确的失败关键词（仅匹配 body 文本）
        (r'上传失败', -0.9, "包含'上传失败'"),
        (r'upload\s*fail', -0.9, "包含'upload fail'"),
        (r'上传错误', -0.8, "包含'上传错误'"),
        (r'文件类型错误', -0.8, "包含'文件类型错误'"),
        (r'extension\s+not\s+allow', -0.9, "扩展名不允许"),
        (r'file\s+type\s+not\s+allow', -0.9, "文件类型不允许"),
        (r'安全风险', -0.8, "安全风险提示"),
        (r'恶意文件', -0.9, "恶意文件提示"),
    ]

    # HTTP 4xx/5xx 状态码集合（Level 1 快速排除）
    QUICK_FAIL_STATUS_CODES = {400, 401, 403, 404, 405, 415, 500, 502, 503}
    
    # Level 2: 打分规则（统一使用 ScoringRule，避免混合类型导致 tuple 解包崩溃）
    SUCCESS_INDICATORS = [
        # 成功关键词
        ScoringRule(r'上传成功', 0.8, 'success', '上传成功'),
        ScoringRule(r'upload\s*success', 0.8, 'success', 'Upload Success'),
        ScoringRule(r'success', 0.3, 'success', '包含success'),
        ScoringRule(r'successfully', 0.3, 'success', '包含successfully'),
        ScoringRule(r'uploaded', 0.5, 'success', '包含uploaded'),
        ScoringRule(r'文件已上传', 0.8, 'success', '上传成功'),
        ScoringRule(r'上传完成', 0.7, 'success', '上传完成'),
        ScoringRule(r'上传OK', 0.8, 'success', '上传OK'),
        ScoringRule(r'upload\s*complete', 0.7, 'success', 'Upload Complete'),
        ScoringRule(r'file\s+saved', 0.6, 'success', 'File Saved'),
        ScoringRule(r'成功', 0.2, 'success', '包含成功'),
        ScoringRule(r'完成', 0.1, 'success', '包含完成'),
        ScoringRule(r'ok', 0.1, 'success', '包含ok'),

        # 路径泄露
        ScoringRule(r'["\']([^"\']*uploads?/[^"\']+)["\']', 0.6, 'success', '发现上传路径'),
        ScoringRule(r'["\']([^"\']*files?/[^"\']+)["\']', 0.5, 'success', '发现文件路径'),
        ScoringRule(r'["\']([^"\']*images?/[^"\']+)["\']', 0.4, 'success', '发现图片路径'),
        ScoringRule(r'href=["\']?([^"\'>\s]*\.php)["\']?', 0.6, 'success', '发现PHP文件链接'),
        ScoringRule(r'src=["\']?([^"\'>\s]*\.php)["\']?', 0.6, 'success', '发现PHP文件引用'),

        # JSON响应
        ScoringRule(r'"status"\s*:\s*"success"', 0.8, 'success', 'JSON成功状态'),
        ScoringRule(r'"code"\s*:\s*200', 0.3, 'success', 'JSON代码200'),
        ScoringRule(r'"error"\s*:\s*null', 0.3, 'success', 'JSON无错误'),
    ]

    FAILURE_INDICATORS = [
        # 失败关键词（统一使用 ScoringRule）
        ScoringRule(r'上传失败', -0.8, 'failure', '上传失败'),
        ScoringRule(r'error', -0.2, 'failure', '包含error'),
        ScoringRule(r'failed', -0.3, 'failure', '包含failed'),
        ScoringRule(r'invalid', -0.3, 'failure', '包含invalid'),
        ScoringRule(r'不允许', -0.5, 'failure', '不允许'),
        ScoringRule(r'not\s*allow', -0.6, 'failure', '不允许'),
        ScoringRule(r'禁止', -0.5, 'failure', '禁止'),
        ScoringRule(r'拒绝', -0.5, 'failure', '拒绝'),
    ]
    
    # 状态码权重
    STATUS_CODE_WEIGHTS = {
        200: 0.3,    # OK
        201: 0.4,    # Created
        204: 0.2,    # No Content
        301: -0.3,   # Redirect
        302: -0.3,   # Redirect
        400: -0.7,   # Bad Request
        401: -0.6,   # Unauthorized
        403: -0.6,   # Forbidden
        404: -0.8,   # Not Found
        415: -0.7,   # Unsupported Media Type
        500: -0.9,   # Server Error
    }
    
    # WAF特征
    WAF_SIGNATURES = {
        "Cloudflare": ["cloudflare", "cf-ray", "__cfduid"],
        "AWS WAF": ["awselb", "aws-waf"],
        "ModSecurity": ["mod_security", "modsecurity"],
        "Sucuri": ["sucuri", "x-sucuri"],
        "Incapsula": ["incap_ses", "visid_incap"],
        "Akamai": ["akamai"],
        "F5 BIG-IP": ["bigip", "x-waf-status"],
        "Imperva": ["imperva", "incap_ses"],
        "Barracuda": ["barra"],
        "Fortinet": ["fortigate", "fortiwaf"],
    }
    
    def __init__(self):
        self.baseline_response: Optional[Dict] = None
        self.threshold = 0.5  # 置信度阈值
    
    def set_baseline(self, response: Dict):
        """设置基准响应（正常上传的响应）"""
        self.baseline_response = response
    
    def analyze(self, response: Any, original_filename: str = None, 
                baseline_response: Any = None) -> AnalysisResult:
        """
        分析响应结果
        
        Args:
            response: 响应对象（支持RawHTTPResponse或requests.Response）
            original_filename: 原始文件名
            baseline_response: 基准响应
        
        Returns:
            AnalysisResult
        """
        result = AnalysisResult()
        
        # 提取响应数据
        status_code = self._get_status_code(response)
        content = self._get_content(response)
        headers = self._get_headers(response)
        response_time = self._get_response_time(response)
        
        result.status_code = status_code
        result.response_time = response_time
        result.content_length = len(content) if content else 0
        result.raw_content = content[:5000] if content else ""  # 限制长度
        
        # Level 1: 快速排除（状态码 + body 关键词）
        if status_code in self.QUICK_FAIL_STATUS_CODES:
            result.is_failure = True
            result.confidence = 0.9
            result.reasons.append(f"Level 1: 快速排除 - HTTP {status_code}")
            return result
        if self._quick_fail_check(content):
            result.is_failure = True
            result.confidence = 0.9
            result.reasons.append("Level 1: 快速排除 - 明显失败关键词")
            return result
        
        # Level 2: 综合打分
        score = 0.0
        
        # 状态码打分
        score += self.STATUS_CODE_WEIGHTS.get(status_code, 0)
        
        # 成功指标打分（全部 ScoringRule，直接用属性访问）
        for indicator in self.SUCCESS_INDICATORS:
            pattern = indicator.pattern
            weight = indicator.weight
            desc = indicator.description
            if re.search(pattern, content, re.IGNORECASE):
                result.evidence.append(desc)
                score += weight
                # 提取路径
                if 'uploads' in pattern.lower() or 'files' in pattern.lower():
                    path_match = re.search(pattern, content, re.IGNORECASE)
                    if path_match and path_match.lastindex:
                        result.uploaded_path = path_match.group(1)

        # 失败指标打分
        for indicator in self.FAILURE_INDICATORS:
            pattern = indicator.pattern
            weight = indicator.weight
            desc = indicator.description
            if re.search(pattern, content, re.IGNORECASE):
                result.evidence.append(desc)
                score += weight
        
        # 检测WAF
        waf_result = self._detect_waf(headers, content)
        if waf_result:
            result.waf_detected = True
            result.waf_names = waf_result
            result.evidence.append(f"检测到WAF: {', '.join(waf_result)}")
            score -= 0.2  # 有WAF降低置信度
        
        # 与基准对比
        if baseline_response or self.baseline_response:
            baseline = baseline_response or self.baseline_response
            comparison = self._compare_with_baseline(response, baseline)
            result.technique_hints = comparison.get('hints', [])
            score += comparison.get('score_delta', 0)
        
        # 计算最终置信度
        result.confidence = max(0.0, min(1.0, (score + 1) / 2))  # 归一化到0-1
        
        # 判定结果
        if result.confidence >= self.threshold:
            result.is_success = True
            result.reasons.append(f"Level 2: 综合打分 - 置信度 {result.confidence:.2f}")
        else:
            result.is_failure = score < 0
            result.reasons.append(f"Level 2: 综合打分 - 置信度 {result.confidence:.2f}")
        
        # 提取页面消息
        result.error_messages = self._extract_page_messages(content, 'error')
        result.warning_messages = self._extract_page_messages(content, 'warning')
        result.success_messages = self._extract_page_messages(content, 'success')
        
        # 检测隐藏指示
        result.hidden_indicators = self._detect_hidden_indicators(content)
        
        # 提取上传路径
        if not result.uploaded_path:
            result.uploaded_path = self._extract_upload_path(content)
        
        # 构建完整URL
        if result.uploaded_path and hasattr(response, 'url'):
            base_url = getattr(response, 'url', '') or ''
            result.full_url = urljoin(base_url, result.uploaded_path)
        
        # 生成建议
        self._generate_suggestions(result, content)
        
        return result
    
    def _quick_fail_check(self, content: str) -> bool:
        """Level 1: 快速排除"""
        if not content:
            return True
        
        for pattern, weight, desc in self.QUICK_FAIL_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                return True
        
        return False
    
    def _get_status_code(self, response: Any) -> int:
        """获取状态码"""
        if hasattr(response, 'status_code'):
            return response.status_code
        if isinstance(response, dict):
            return response.get('status_code', 0)
        return 0
    
    def _get_content(self, response: Any) -> str:
        """获取响应内容"""
        if hasattr(response, 'text'):
            return response.text
        if hasattr(response, 'content'):
            if isinstance(response.content, bytes):
                try:
                    return response.content.decode('utf-8', errors='ignore')
                except:
                    return str(response.content)
            return str(response.content)
        if isinstance(response, dict):
            return response.get('content', '')
        return str(response) if response else ''
    
    def _get_headers(self, response: Any) -> Dict:
        """获取响应头"""
        if hasattr(response, 'headers'):
            return dict(response.headers)
        if isinstance(response, dict):
            return response.get('headers', {})
        return {}
    
    def _get_response_time(self, response: Any) -> float:
        """获取响应时间"""
        if hasattr(response, 'elapsed'):
            return getattr(response, 'elapsed', 0)
        if isinstance(response, dict):
            return response.get('elapsed_time', 0)
        return 0
    
    def _detect_waf(self, headers: Dict, content: str) -> List[str]:
        """检测WAF"""
        detected = []
        headers_str = str(headers).lower()
        content_lower = content.lower()
        
        for waf_name, signatures in self.WAF_SIGNATURES.items():
            for sig in signatures:
                if sig.lower() in headers_str or sig.lower() in content_lower:
                    detected.append(waf_name)
                    break
        
        return detected
    
    def _compare_with_baseline(self, response: Any, baseline: Any) -> Dict:
        """与基准响应对比"""
        result = {
            'score_delta': 0.0,
            'hints': []
        }
        
        current_content = self._get_content(response)
        baseline_content = self._get_content(baseline)
        
        current_code = self._get_status_code(response)
        baseline_code = self._get_status_code(baseline)
        
        # 状态码变化检测
        if current_code == 200 and baseline_code != 200:
            result['hints'].append("状态码异常: 期望非200但返回200")
            result['score_delta'] += 0.3
        
        # 内容差异检测
        if len(current_content) != len(baseline_content):
            size_diff = abs(len(current_content) - len(baseline_content))
            if size_diff > 1000:
                result['hints'].append(f"响应大小显著变化: {size_diff}字节")
                result['score_delta'] += 0.2
        
        # 内容变化检测
        if current_content != baseline_content:
            result['hints'].append("响应内容发生变化")

            # 检查是否有新增的成功指示（全部 ScoringRule，用属性访问）
            for indicator in self.SUCCESS_INDICATORS:
                pattern = indicator.pattern
                desc = indicator.description
                if re.search(pattern, current_content) and not re.search(pattern, baseline_content):
                    result['hints'].append(f"新增成功指示: {desc}")
                    result['score_delta'] += 0.2
        
        return result
    
    def _extract_page_messages(self, content: str, msg_type: str) -> List[str]:
        """提取页面提示消息"""
        messages = []
        
        class_patterns = {
            'error': [
                r'class="[^"]*error[^"]*"[^>]*>([^<]+)',
                r'class="[^"]*alert-error[^"]*"[^>]*>([^<]+)',
                r'class="[^"]*alert-danger[^"]*"[^>]*>([^<]+)',
                r'<p[^>]*class="[^"]*error[^"]*"[^>]*>([^<]+)',
                r'style="[^"]*color:\s*red[^"]*"[^>]*>([^<]+)',
                r'<font[^>]*color="[^"]*red[^"]*"[^>]*>([^<]+)',
            ],
            'warning': [
                r'class="[^"]*warning[^"]*"[^>]*>([^<]+)',
                r'class="[^"]*alert-warning[^"]*"[^>]*>([^<]+)',
            ],
            'success': [
                r'class="[^"]*success[^"]*"[^>]*>([^<]+)',
                r'class="[^"]*alert-success[^"]*"[^>]*>([^<]+)',
                r'style="[^"]*color:\s*green[^"]*"[^>]*>([^<]+)',
            ]
        }
        
        patterns = class_patterns.get(msg_type, [])
        for pattern in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            messages.extend(matches)
        
        return list(set(messages))[:5]  # 去重，最多5条
    
    def _detect_hidden_indicators(self, content: str) -> List[str]:
        """检测隐藏的成功指示"""
        indicators = []
        
        # JavaScript提示
        js_patterns = [
            r'alert\s*\(\s*["\']([^"\']+)["\']',
            r'console\.log\s*\(\s*["\']([^"\']+)["\']',
            r'toast\s*\(\s*["\']([^"\']+)["\']',
            r'notify\s*\(\s*["\']([^"\']+)["\']',
        ]
        for pattern in js_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if match:
                    indicators.append(f"JS提示: {match}")
        
        # HTML注释
        comment_pattern = r'<!--\s*(.+?)\s*-->'
        comments = re.findall(comment_pattern, content, re.DOTALL)
        for comment in comments:
            keywords = ['upload', 'success', 'path', 'saved', 'uploaded']
            if any(kw in comment.lower() for kw in keywords):
                indicators.append(f"注释提示: {comment.strip()[:100]}")
        
        # Data属性
        data_patterns = [
            r'data-message=["\']([^"\']+)["\']',
            r'data-result=["\']([^"\']+)["\']',
            r'data-status=["\']([^"\']+)["\']',
        ]
        for pattern in data_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if match:
                    indicators.append(f"Data属性: {match}")
        
        return indicators[:10]  # 最多10条
    
    def _extract_upload_path(self, content: str) -> Optional[str]:
        """提取上传文件路径"""
        path_patterns = [
            r'["\']([^"\']*uploads?/[^"\']+)["\']',
            r'["\']([^"\']*files?/[^"\']+)["\']',
            r'["\']([^"\']*images?/[^"\']+)["\']',
            r'["\']([^"\']*media/[^"\']+)["\']',
            r'["\']([^"\']*storage/[^"\']+)["\']',
            r'href=["\']?([^"\'>\s]+\.(?:php|asp|aspx|jsp))["\']?',
            r'src=["\']?([^"\'>\s]+\.(?:php|asp|aspx|jsp))["\']?',
            r'"url"\s*:\s*"([^"]+)"',
            r'"path"\s*:\s*"([^"]+)"',
            r'"file"\s*:\s*"([^"]+)"',
        ]
        
        for pattern in path_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                return matches[0]
        
        # 尝试JSON解析
        try:
            if content.strip().startswith('{') or content.strip().startswith('['):
                data = json.loads(content)
                for key in ['url', 'path', 'file', 'filename', 'location', 'link', 'src']:
                    if key in data:
                        return str(data[key])
        except:
            pass
        
        return None
    
    def _generate_suggestions(self, result: AnalysisResult, content: str):
        """生成建议"""
        if result.waf_detected:
            result.suggestions.append("检测到WAF，建议使用WAF绕过技术")
        
        if not result.uploaded_path and result.is_success:
            result.suggestions.append("上传可能成功但未检测到路径，建议手动验证")
        
        if result.confidence < 0.6:
            result.suggestions.append("置信度较低，建议尝试其他绕过技术")
        
        if 400 <= result.status_code < 500:
            result.suggestions.append("HTTP客户端错误，建议检查Content-Type或请求格式")
        
        if result.hidden_indicators:
            result.suggestions.append("检测到隐藏提示信息，建议查看详情")


# =============================================================================
# Testing
# =============================================================================

if __name__ == "__main__":
    print("Smart Response Analyzer Test")
    print("=" * 50)
    
    analyzer = SmartResponseAnalyzer()
    
    # 测试用例
    test_cases = [
        # (content, expected_result, description)
        ("上传成功，文件已保存到 /uploads/test.php", True, "明确成功"),
        ("upload success", True, "英文成功"),
        ("上传失败，文件类型不允许", False, "明确失败"),
        ("error occurred", False, "包含错误"),
        ("<div class='alert-success'>文件上传成功</div>", True, "CSS类成功"),
        ("HTTP/1.1 200 OK\n\nsuccess", True, "状态码200+success"),
        ("<div class='error'>Invalid file type</div>", False, "CSS类错误"),
        ("", False, "空响应"),
    ]
    
    print("\nTest Results:")
    for content, expected, desc in test_cases:
        result = analyzer.analyze(type('Response', (), {
            'status_code': 200,
            'text': content,
            'headers': {},
            'url': 'http://example.com/upload.php'
        })())
        
        status = "✓" if result.is_success == expected else "✗"
        print(f"\n{status} {desc}")
        print(f"  Content: {content[:50]}...")
        print(f"  Expected: {expected}, Got: {result.is_success}")
        print(f"  Confidence: {result.confidence:.2f}")
        print(f"  Evidence: {result.evidence[:2]}")
