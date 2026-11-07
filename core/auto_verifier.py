#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WebShell 自动验证器
上传后自动验证文件是否可执行
"""

import re
import asyncio
import httpx
import json
from typing import Optional, Tuple, List, Dict, Any
from dataclasses import dataclass
from enum import Enum
from urllib.parse import urlparse


class VerificationStatus(Enum):
    """验证状态"""
    VERIFIED_EXEC = "verified_exec"      # 已验证可执行
    VERIFIED_UPLOAD = "verified_upload" # 仅上传成功
    NOT_FOUND = "not_found"             # 文件未找到
    ACCESS_DENIED = "access_denied"     # 访问被拒绝
    FAILED = "failed"                   # 验证失败


@dataclass
class VerificationResult:
    """验证结果"""
    status: VerificationStatus
    verified_url: Optional[str]         # 验证请求的URL
    response_code: int                  # HTTP状态码
    response_preview: str               # 响应内容预览
    execution_confirmed: bool           # 是否确认可执行
    execution_output: Optional[str] = None    # 执行输出
    error: Optional[str] = None                # 错误信息
    
    def is_success(self) -> bool:
        """是否成功"""
        return self.status in [
            VerificationStatus.VERIFIED_EXEC,
            VerificationStatus.VERIFIED_UPLOAD
        ]


class WebShellVerifier:
    """WebShell验证器"""
    
    # 测试代码模式
    TEST_PATTERNS = {
        "php": {
            "code": "<?php echo 'UR_TEST_' . (23*2); ?>",
            "pattern": r"UR_TEST_46",
            "marker": "UR_TEST_"
        },
        "asp": {
            "code": "<% Response.Write 'UR_TEST_' & (23*2) %>",
            "pattern": r"UR_TEST_46",
            "marker": "UR_TEST_"
        },
        "aspx": {
            "code": '<%@ Page Language="C#" %> <% Response.Write("UR_TEST_" + (23*2)); %>',
            "pattern": r"UR_TEST_46",
            "marker": "UR_TEST_"
        },
        "jsp": {
            "code": '<% out.println("UR_TEST_" + (23*2)); %>',
            "pattern": r"UR_TEST_46",
            "marker": "UR_TEST_"
        }
    }
    
    def __init__(self, timeout: int = 10, proxy: Optional[str] = None,
                 proxies: Optional[Dict] = None, verify_ssl: bool = True,
                 marker: str = "UR_TEST_46"):
        self.timeout = timeout
        # 同时兼容旧版 proxy= 与多协议 proxies= 调用方。
        if proxies is None and proxy:
            proxies = {"http://": proxy, "https://": proxy}
        self.proxies = proxies or {}
        self.verify_ssl = verify_ssl
        # 【修复】硬编码特征串 UR_TEST_46 提为构造参数（默认值保持旧行为兼容）。
        # 上传测试代码与判定特征统一使用该参数：自定义 marker（如每轮唯一
        # nonce）时三者同步变化，避免固定特征串被静态回显伪造执行证据。
        self.marker = marker
        self.test_patterns = {
            "php": {
                "code": f"<?php echo '{self.marker}'; ?>",
                "pattern": re.escape(self.marker),
                "marker": self.marker,
            },
            "asp": {
                "code": f"<% Response.Write '{self.marker}' %>",
                "pattern": re.escape(self.marker),
                "marker": self.marker,
            },
            "aspx": {
                "code": '<%@ Page Language="C#" %> <% Response.Write("'
                        + self.marker + '"); %>',
                "pattern": re.escape(self.marker),
                "marker": self.marker,
            },
            "jsp": {
                "code": '<% out.println("' + self.marker + '"); %>',
                "pattern": re.escape(self.marker),
                "marker": self.marker,
            },
        }

    def get_test_code(self, language: str = "php") -> str:
        """返回指定语言的上传测试代码（内容基于构造参数 marker）"""
        pattern = self.test_patterns.get((language or "php").lower()) or self.test_patterns["php"]
        return pattern["code"]

    async def verify(self, upload_url: str, language: str = "php") -> VerificationResult:
        """
        验证上传的WebShell是否可执行

        Args:
            upload_url: 上传后获得的URL
            language: 语言类型 (php/asp/aspx/jsp)

        Returns:
            VerificationResult: 验证结果

        Raises:
            ValueError: upload_url 不是 http/https 绝对地址（相对 URL 无法直接
                请求，httpx 会抛未捕获的 InvalidURL，这里显式拒绝并给出清晰错误）
        """
        # 解析URL
        parsed = self._parse_upload_url(upload_url)
        if not parsed:
            # 【修复】相对 URL（如 /uploads/x.php）不再原样请求——那会抛未捕获
            # 的 httpx.InvalidURL；这里显式拒绝并给出可操作的错误信息。
            raise ValueError(
                f"无法解析上传URL: {upload_url!r}；需要以 http:// 或 https:// "
                f"开头的完整地址（相对路径请先与目标站点 base_url 拼接）"
            )
        
        verify_url, filename = parsed
        
        # 尝试验证
        try:
            client_kwargs = {
                "timeout": self.timeout,
                "verify": self.verify_ssl,
                "follow_redirects": True,
            }
            # httpx 0.28 使用 proxy=；多协议场景用 mounts。
            if self.proxies:
                mounts = {
                    scheme: httpx.AsyncHTTPTransport(proxy=url)
                    for scheme, url in self.proxies.items()
                    if url
                }
                if mounts:
                    client_kwargs["mounts"] = mounts
            async with httpx.AsyncClient(**client_kwargs) as client:
                response = await client.get(verify_url)
                
                # 检查响应
                result = self._check_response(
                    response.status_code,
                    response.text,
                    language,
                    verify_url
                )
                
                return result
                
        except httpx.RequestError as e:
            return VerificationResult(
                status=VerificationStatus.FAILED,
                verified_url=verify_url,
                response_code=0,
                response_preview="",
                execution_confirmed=False,
                error=f"请求失败: {str(e)}"
            )
    
    async def batch_verify(self, upload_urls: List[str], language: str = "php") -> List[VerificationResult]:
        """批量验证"""
        tasks = [self.verify(url, language) for url in upload_urls]
        return await asyncio.gather(*tasks)
    
    def _parse_upload_url(self, upload_url: str) -> Optional[Tuple[str, str]]:
        """解析上传URL

        【修复】只接受 http/https 绝对地址；相对路径（/uploads/x.php）或纯文件名
        返回 None，由 verify() 抛出清晰的 ValueError 拒绝。
        scheme 判断从 startswith('http') 改为 urlparse 后按 scheme 判定，
        避免放过 'httpfoo' 之类的输入。
        """
        text = str(upload_url or "").strip()
        if not text:
            return None
        try:
            parsed = urlparse(text)
        except ValueError:
            return None
        # 如果是完整URL（scheme 必须是 http/https 且带主机）
        if parsed.scheme.lower() in ("http", "https") and parsed.netloc:
            # 提取文件名
            filename = text.split('/')[-1].split('?')[0]
            return text, filename
        # 相对路径/纯文件名：无法直接请求
        return None
    
    def _check_response(self, 
                        status_code: int, 
                        content: str,
                        language: str,
                        url: str) -> VerificationResult:
        """检查响应内容"""
        
        # 404/403 等错误
        if status_code == 404:
            return VerificationResult(
                status=VerificationStatus.NOT_FOUND,
                verified_url=url,
                response_code=status_code,
                response_preview=content[:200],
                execution_confirmed=False,
                error="文件未找到 (404)"
            )
        
        if status_code == 403:
            return VerificationResult(
                status=VerificationStatus.ACCESS_DENIED,
                verified_url=url,
                response_code=status_code,
                response_preview=content[:200],
                execution_confirmed=False,
                error="访问被拒绝 (403)"
            )
        
        # 检查是否是执行输出
        # 【修复】判定统一使用构造参数 marker（上传测试代码与判定同源）；
        # 自定义 marker 时按字面匹配，默认 UR_TEST_46 保持旧的正则兼容回退。
        patterns = getattr(self, "test_patterns", None) or self.TEST_PATTERNS
        test_pattern = patterns.get(language.lower()) or patterns.get("php") or self.TEST_PATTERNS["php"]
        marker_hit = bool(self.marker) and self.marker in content
        legacy_hit = bool(re.search(test_pattern["pattern"], content))

        if marker_hit or legacy_hit:
            # 提取执行输出（旧特征 UR_TEST_<数字> 仍可提取；nonce 化 marker 原样返回）
            match = re.search(rf'{re.escape(test_pattern["marker"])}\d*', content)
            output = match.group(0) if match else (self.marker or "UR_TEST_46")

            return VerificationResult(
                status=VerificationStatus.VERIFIED_EXEC,
                verified_url=url,
                response_code=status_code,
                response_preview=content[:200],
                execution_confirmed=True,
                execution_output=output
            )
        
        # 有响应但不是测试输出
        if status_code == 200 and content:
            return VerificationResult(
                status=VerificationStatus.VERIFIED_UPLOAD,
                verified_url=url,
                response_code=status_code,
                response_preview=content[:200],
                execution_confirmed=False,
                error="文件存在但无法确认执行"
            )
        
        return VerificationResult(
            status=VerificationStatus.FAILED,
            verified_url=url,
            response_code=status_code,
            response_preview=content[:200],
            execution_confirmed=False,
            error="验证失败"
        )


class UploadPathExtractor:
    """上传路径提取器"""
    
    @staticmethod
    def extract(response_text: str, base_url: str) -> List[str]:
        """
        从响应中提取上传路径
        
        Args:
            response_text: 上传接口的响应内容
            base_url: 基础URL
            
        Returns:
            List[str]: 可能的路径列表
        """
        paths = []
        
        # JSON格式
        try:
            data = json.loads(response_text)
            for key in ['url', 'path', 'file', 'filename', 'location', 'link', 'src']:
                if key in data:
                    value = data[key]
                    if isinstance(value, str):
                        paths.append(value)
        except:
            pass
        
        # 正则匹配
        patterns = [
            # 引号包裹的路径
            r'["\']([^"\']*uploads?/[^"\']+)["\']',
            r'["\']([^"\']*files?/[^"\']+)["\']',
            r'["\']([^"\']*images?/[^"\']+)["\']',
            
            # URL格式
            r'(?:href|src)=["\']([^"\']+\.(?:php|asp|jsp|aspx))["\']',
            
            # JSON属性
            r'"(url|path|file|filename)["\s:]+["\']([^"\']+)["\']',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, response_text, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    path = match[-1]  # 取最后一个捕获组
                else:
                    path = match
                
                # 转绝对路径
                if not path.startswith('http'):
                    if path.startswith('/'):
                        from urllib.parse import urlparse
                        parsed = urlparse(base_url)
                        path = f"{parsed.scheme}://{parsed.netloc}{path}"
                    else:
                        path = base_url.rstrip('/') + '/' + path
                
                if path not in paths:
                    paths.append(path)
        
        return paths


# 便捷函数
async def quick_verify(upload_url: str, language: str = "php") -> VerificationResult:
    """快速验证"""
    verifier = WebShellVerifier()
    return await verifier.verify(upload_url, language)


def extract_paths(response_text: str, base_url: str) -> List[str]:
    """提取路径"""
    return UploadPathExtractor.extract(response_text, base_url)
