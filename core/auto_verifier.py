#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WebShell 自动验证器
上传后自动验证文件是否可执行
"""

import re
import asyncio
import httpx
from typing import Optional, Tuple, List, Dict, Any
from dataclasses import dataclass
from enum import Enum


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
    execution_output: Optional[str]    # 执行输出
    error: Optional[str]                # 错误信息
    
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
    
    def __init__(self, timeout: int = 10, proxies: Optional[Dict] = None):
        self.timeout = timeout
        self.proxies = proxies
    
    async def verify(self, upload_url: str, language: str = "php") -> VerificationResult:
        """
        验证上传的WebShell是否可执行
        
        Args:
            upload_url: 上传后获得的URL
            language: 语言类型 (php/asp/aspx/jsp)
            
        Returns:
            VerificationResult: 验证结果
        """
        # 解析URL
        parsed = self._parse_upload_url(upload_url)
        if not parsed:
            return VerificationResult(
                status=VerificationStatus.FAILED,
                verified_url=None,
                response_code=0,
                response_preview="",
                execution_confirmed=False,
                error="无法解析上传URL"
            )
        
        verify_url, filename = parsed
        
        # 尝试验证
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout,
                proxies=self.proxies,
                follow_redirects=True
            ) as client:
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
        """解析上传URL"""
        # 如果是完整URL
        if upload_url.startswith('http'):
            # 提取文件名
            filename = upload_url.split('/')[-1].split('?')[0]
            return upload_url, filename
        
        # 如果是相对路径
        if upload_url.startswith('/'):
            return upload_url, upload_url.split('/')[-1]
        
        # 如果只有文件名
        return None, upload_url
    
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
        test_pattern = self.TEST_PATTERNS.get(language.lower(), self.TEST_PATTERNS["php"])
        
        if re.search(test_pattern["pattern"], content):
            # 提取执行输出
            match = re.search(rf'{test_pattern["marker"]}(\d+)', content)
            output = match.group(0) if match else "UR_TEST_46"
            
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
