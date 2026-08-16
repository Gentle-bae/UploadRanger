#!/usr/bin/env python3
"""
基线比对分析器 - v1.1.2核心组件

取代硬编码的upload-labs判定逻辑，采用动态基线比对法。
"""

import re
import hashlib
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from difflib import SequenceMatcher


@dataclass
class BaselineProfile:
    """成功基线配置"""
    status_code: int
    content_length: int
    content_hash: str
    structure_signature: str
    response_sample: str
    similarity_threshold: float = 0.85
    length_variance_threshold: float = 0.05


@dataclass
class AnalysisResult:
    """分析结果"""
    is_success: bool
    confidence: float
    similarity_score: float
    length_ratio: float
    decision_reason: str
    is_fake_200: bool


class BaselineAnalyzer:
    """
    基线比对分析器
    
    工作原理:
    1. 发送无害文件(test.jpg)建立成功基线
    2. 后续响应与基线比对
    3. 结构相似+无拦截关键词 = 成功
    """
    
    # 拦截关键词库
    FAILURE_KEYWORDS = [
        # 中文
        "不允许", "文件类型错误", "上传失败", "非法文件", 
        "恶意文件", "后缀不允许", "格式不正确", "类型不允许",
        "文件过大", "上传被阻止", "危险文件", "禁止上传",
        "无法上传", "不被允许", "仅限", "只能是",
        # 英文
        "not allowed", "invalid file", "file type error", 
        "upload failed", "forbidden", "blocked", "not permitted",
        "extension not allowed", "unsupported file type",
        "file too large", "upload denied",
    ]
    
    def __init__(self):
        self.baseline: Optional[BaselineProfile] = None
    
    def establish_baseline(self, response_text: str, status_code: int = 200) -> BaselineProfile:
        """
        建立成功基线
        
        Args:
            response_text: 响应文本
            status_code: HTTP状态码
            
        Returns:
            BaselineProfile对象
        """
        self.baseline = BaselineProfile(
            status_code=status_code,
            content_length=len(response_text),
            content_hash=self._compute_hash(response_text),
            structure_signature=self._extract_structure(response_text),
            response_sample=response_text[:500]
        )
        return self.baseline
    
    def analyze(self, response_text: str, status_code: int) -> AnalysisResult:
        """
        分析响应
        
        Args:
            response_text: 响应文本
            status_code: HTTP状态码
            
        Returns:
            AnalysisResult对象
        """
        if not self.baseline:
            return AnalysisResult(
                is_success=False,
                confidence=0.0,
                similarity_score=0.0,
                length_ratio=0.0,
                decision_reason="基线未建立",
                is_fake_200=False
            )
        
        # 1. 检查拦截关键词
        failure_keyword = self._check_failure_keywords(response_text)
        
        # 2. 计算结构相似度
        similarity = self._calculate_similarity(response_text)
        
        # 3. 计算长度比例
        length_ratio = len(response_text) / max(self.baseline.content_length, 1)
        
        # 4. 判定逻辑
        is_fake_200 = self._is_fake_200(response_text, status_code, failure_keyword)
        
        if is_fake_200:
            return AnalysisResult(
                is_success=False,
                confidence=0.9,
                similarity_score=similarity,
                length_ratio=length_ratio,
                decision_reason=f"假200检测: 响应包含拦截关键词'{failure_keyword}'",
                is_fake_200=True
            )
        elif failure_keyword:
            return AnalysisResult(
                is_success=False,
                confidence=0.95,
                similarity_score=similarity,
                length_ratio=length_ratio,
                decision_reason=f"检测到拦截关键词: {failure_keyword}",
                is_fake_200=status_code == 200
            )
        elif similarity >= self.baseline.similarity_threshold and status_code == self.baseline.status_code:
            return AnalysisResult(
                is_success=True,
                confidence=similarity,
                similarity_score=similarity,
                length_ratio=length_ratio,
                decision_reason=f"与基线高度相似 ({similarity:.1%})",
                is_fake_200=False
            )
        elif similarity >= 0.7 and 0.8 <= length_ratio <= 1.2:
            return AnalysisResult(
                is_success=True,
                confidence=similarity * 0.8,
                similarity_score=similarity,
                length_ratio=length_ratio,
                decision_reason=f"与基线相似 ({similarity:.1%}), 长度接近 ({length_ratio:.2f})",
                is_fake_200=False
            )
        else:
            return AnalysisResult(
                is_success=False,
                confidence=0.5,
                similarity_score=similarity,
                length_ratio=length_ratio,
                decision_reason=f"与基线差异较大 (相似度:{similarity:.1%}, 长度比:{length_ratio:.2f})",
                is_fake_200=False
            )
    
    def _compute_hash(self, text: str) -> str:
        """计算文本特征哈希"""
        normalized = self._normalize_text(text)
        return hashlib.md5(normalized.encode()).hexdigest()[:16]
    
    def _normalize_text(self, text: str) -> str:
        """归一化文本（移除动态值）"""
        # 移除时间戳
        text = re.sub(r'\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}:\d{2}', '[TIME]', text)
        # 移除长数字
        text = re.sub(r'\d{10,}', '[ID]', text)
        # 移除哈希
        text = re.sub(r'[a-f0-9]{32}', '[HASH]', text)
        return text
    
    def _extract_structure(self, text: str) -> str:
        """提取响应结构签名"""
        text = text.strip()
        
        # JSON响应
        if text.startswith('{') or text.startswith('['):
            try:
                import json
                data = json.loads(text)
                return self._extract_json_structure(data)
            except:
                pass
        
        # HTML响应
        if '<' in text and '>' in text:
            return self._extract_html_structure(text)
        
        # 纯文本
        return f"TEXT|len:{len(text)}|lines:{text.count(chr(10))}"
    
    def _extract_json_structure(self, data, prefix="") -> str:
        """提取JSON结构"""
        if isinstance(data, dict):
            keys = sorted(data.keys())
            parts = []
            for k in keys:
                v = data[k]
                type_str = type(v).__name__
                if isinstance(v, (dict, list)):
                    type_str = self._extract_json_structure(v, prefix + k + ".")
                parts.append(f"{k}:{type_str}")
            return "{" + ",".join(parts) + "}"
        elif isinstance(data, list):
            if data:
                return f"[{self._extract_json_structure(data[0])}]"
            return "[]"
        else:
            return type(data).__name__
    
    def _extract_html_structure(self, text: str) -> str:
        """提取HTML结构"""
        tags = re.findall(r'<(\w+)[\s>]', text)
        from collections import Counter
        tag_counts = Counter(tags)
        parts = [f"{tag}:{cnt}" for tag, cnt in sorted(tag_counts.items())]
        
        # 检查是否包含上传路径
        has_upload_path = bool(re.search(r'/upload/|/files/|/attachment/', text, re.I))
        
        return f"HTML|{'|'.join(parts)}|upload_path:{has_upload_path}"
    
    def _calculate_similarity(self, text: str) -> float:
        """计算与基线的相似度"""
        if not self.baseline:
            return 0.0
        current_structure = self._extract_structure(text)
        return SequenceMatcher(None, self.baseline.structure_signature, current_structure).ratio()
    
    def _check_failure_keywords(self, text: str) -> Optional[str]:
        """检查拦截关键词"""
        text_lower = text.lower()
        for keyword in self.FAILURE_KEYWORDS:
            if keyword.lower() in text_lower:
                return keyword
        return None
    
    def _is_fake_200(self, text: str, status_code: int, failure_keyword: Optional[str]) -> bool:
        """检测假200"""
        if status_code != 200:
            return False
        
        if failure_keyword:
            return True
        
        if self.baseline:
            similarity = self._calculate_similarity(text)
            if similarity < 0.3:
                return True
        
        return False


# 便捷函数
def create_analyzer() -> BaselineAnalyzer:
    """创建分析器实例"""
    return BaselineAnalyzer()


# 测试代码
if __name__ == "__main__":
    print("[测试] BaselineAnalyzer")
    
    analyzer = BaselineAnalyzer()
    
    # 建立基线（上传jpg成功的响应）
    baseline_response = """{"code": 200, "message": "success", "url": "/uploads/test.jpg"}"""
    analyzer.establish_baseline(baseline_response)
    print(f"[基线] 状态码: {analyzer.baseline.status_code}, 长度: {analyzer.baseline.content_length}")
    
    # 测试1: 真正的成功
    success_response = """{"code": 200, "message": "success", "url": "/uploads/shell.php"}"""
    result = analyzer.analyze(success_response, 200)
    print(f"[测试1] 成功场景: is_success={result.is_success}, confidence={result.confidence:.1%}")
    
    # 测试2: 假200
    fake_response = """{"code": 200, "message": "文件类型不允许"}"""
    result = analyzer.analyze(fake_response, 200)
    print(f"[测试2] 假200场景: is_success={result.is_success}, is_fake_200={result.is_fake_200}")
    
    # 测试3: 明确失败
    fail_response = """{"code": 403, "message": "forbidden"}"""
    result = analyzer.analyze(fail_response, 403)
    print(f"[测试3] 失败场景: is_success={result.is_success}, reason={result.decision_reason}")
    
    print("[测试] 完成!")
