#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
异步HTTP客户端 - 使用httpx
支持流量日志记录 - 显示完整请求/响应内容
"""

import httpx
from typing import Dict, Optional, Any, Callable
from datetime import datetime

from .models import TrafficLog


DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
DEFAULT_TIMEOUT = 30


class AsyncHTTPClient:
    """异步HTTP客户端"""
    
    def __init__(self, 
                 proxies: Optional[Dict] = None, 
                 headers: Optional[Dict] = None, 
                 cookies: Optional[Dict] = None,
                 timeout: int = DEFAULT_TIMEOUT):
        
        self.proxies = proxies
        self.headers = headers or {}
        self.cookies = cookies or {}
        self.timeout = timeout
        self.log_callback: Optional[Callable[[TrafficLog], None]] = None
        self.request_counter = 0
        
        # 存储请求体用于日志
        self._last_request_body = b""
        
        # 确保User-Agent已设置
        if "User-Agent" not in self.headers:
            self.headers["User-Agent"] = DEFAULT_USER_AGENT
        
        # 创建httpx客户端
        mounts = {}
        if proxies:
            for scheme, proxy_url in proxies.items():
                mounts[scheme] = httpx.AsyncHTTPTransport(proxy=proxy_url)

        self.client = httpx.AsyncClient(
            headers=self.headers,
            cookies=self.cookies,
            timeout=timeout,
            verify=False,
            trust_env=False,
            mounts=mounts if mounts else None
        )
    
    def set_log_callback(self, callback: Callable[[TrafficLog], None]):
        """设置流量日志回调"""
        self.log_callback = callback
    
    def _format_request_body(self, content: bytes) -> str:
        """格式化请求体 - 尝试多种解码方式，显示完整内容"""
        if not content:
            return ""
        
        # 尝试UTF-8解码
        try:
            decoded = content.decode('utf-8')
            return decoded
        except:
            pass
        
        # 尝试Latin-1解码（不会失败）
        try:
            decoded = content.decode('latin-1')
            return decoded
        except:
            pass
        
        # 尝试GBK解码
        try:
            decoded = content.decode('gbk')
            return decoded
        except:
            pass
        
        # 作为十六进制显示（增大预览，避免 polyglot/图片响应被截得过短）
        if len(content) > 8192:
            hex_content = content[:8192].hex()
            return f"[Binary Content - {len(content)} bytes, showing first 8KB]\n{hex_content}\n... [truncated]"
        return content.hex()
    
    def _format_response_body(self, text: str, content: bytes) -> str:
        """格式化响应体 - 显示完整内容"""
        if text:
            # 返回完整文本内容
            return text
        
        # 尝试解码二进制内容
        if content:
            # 尝试UTF-8解码
            try:
                decoded = content.decode('utf-8')
                return decoded
            except:
                pass
            
            # 尝试Latin-1解码
            try:
                decoded = content.decode('latin-1')
                return decoded
            except:
                pass
            
            # 尝试GBK解码
            try:
                decoded = content.decode('gbk')
                return decoded
            except:
                pass
            
            # 作为十六进制显示（增大预览，便于分析较大二进制响应）
            if len(content) > 32768:
                hex_content = content[:32768].hex()
                return f"[Binary Content - {len(content)} bytes, showing first 32KB]\n{hex_content}\n... [truncated]"
            return content.hex()
        
        return ""
    
    def _log_traffic(self, response: httpx.Response, request_body: bytes = b""):
        """记录流量日志"""
        if self.log_callback:
            self.request_counter += 1
            
            # 格式化请求头
            req_headers = "\n".join([f"{k}: {v}" for k, v in response.request.headers.items()])
            res_headers = "\n".join([f"{k}: {v}" for k, v in response.headers.items()])
            
            # 处理请求体 - 显示完整内容
            req_body = self._format_request_body(request_body)
            
            # 处理响应体 - 显示完整内容
            res_body = self._format_response_body(response.text, response.content)
            
            log = TrafficLog(
                id=self.request_counter,
                timestamp=datetime.now().strftime("%H:%M:%S"),
                method=response.request.method,
                url=str(response.request.url),
                status_code=response.status_code,
                request_headers=req_headers,
                request_body=req_body,
                response_headers=res_headers,
                response_body=res_body
            )
            self.log_callback(log)
    
    async def upload_file(self, 
                          url: str, 
                          file_field_name: str, 
                          filename: str, 
                          file_content: bytes, 
                          content_type: str = "application/octet-stream",
                          extra_data: Optional[Dict] = None,
                          method: str = "POST") -> httpx.Response:
        """上传文件"""
        files = {
            file_field_name: (filename, file_content, content_type)
        }
        
        try:
            if method.upper() == "POST":
                # 构建multipart请求
                response = await self.client.post(url, files=files, data=extra_data)
                
                # 【修复】从 httpx 请求中提取真实的请求内容
                request_body = b""
                try:
                    # 尝试从请求对象的 content 中获取实际发送的请求体
                    if hasattr(response, 'request') and response.request:
                        req = response.request
                        # httpx 的请求对象有 content 属性
                        if hasattr(req, 'content') and req.content:
                            request_body = req.content
                        # 或者从 stream 中获取
                        elif hasattr(req, '_content') and req._content:
                            request_body = req._content
                        else:
                            # 从.headers 获取 Content-Type，手动构建完整请求
                            request_body = self._build_multipart_body(
                                file_field_name, filename, file_content, 
                                content_type, extra_data, req.headers.get('Content-Type', '')
                            )
                except Exception:
                    # 回退：手动构建请求体
                    request_body = self._build_multipart_body(
                        file_field_name, filename, file_content, 
                        content_type, extra_data, 
                        f"multipart/form-data; boundary=----WebKitFormBoundaryUploadRanger"
                    )
                
            elif method.upper() == "PUT":
                response = await self.client.put(url, content=file_content)
                request_body = file_content
            else:
                raise ValueError(f"不支持的HTTP方法: {method}")
            
            self._log_traffic(response, request_body)
            return response
        except Exception as e:
            raise Exception(f"请求失败: {str(e)}")
    
    def _build_multipart_body(self, file_field_name: str, filename: str, 
                              file_content: bytes, content_type: str,
                              extra_data: Optional[Dict], content_type_header: str) -> bytes:
        """手动构建完整的 multipart/form-data 请求体"""
        # 从 Content-Type header 中提取 boundary
        boundary = "----WebKitFormBoundaryUploadRanger"
        if 'boundary=' in content_type_header:
            boundary = content_type_header.split('boundary=')[-1].strip().strip('"')
        
        parts = []
        
        # 添加 extra_data 中的其他字段
        if extra_data:
            for key, value in extra_data.items():
                parts.append(f"--{boundary}\r\n".encode())
                parts.append(f'Content-Disposition: form-data; name="{key}"\r\n\r\n'.encode())
                parts.append(f"{value}\r\n".encode())
        
        # 添加文件部分
        parts.append(f"--{boundary}\r\n".encode())
        parts.append(f'Content-Disposition: form-data; name="{file_field_name}"; filename="{filename}"\r\n'.encode())
        parts.append(f"Content-Type: {content_type}\r\n\r\n".encode())
        parts.append(file_content)
        parts.append(f"\r\n--{boundary}--\r\n".encode())
        
        return b"".join(parts)
    
    async def get(self, url: str, **kwargs) -> httpx.Response:
        """GET请求"""
        try:
            response = await self.client.get(url, **kwargs)
            self._log_traffic(response)
            return response
        except Exception as e:
            raise Exception(f"GET请求失败: {str(e)}")
    
    async def post(self, url: str, **kwargs) -> httpx.Response:
        """POST请求"""
        try:
            response = await self.client.post(url, **kwargs)
            self._log_traffic(response)
            return response
        except Exception as e:
            raise Exception(f"POST请求失败: {str(e)}")
    
    async def check_file_existence(self, url: str) -> httpx.Response:
        """检查文件是否存在"""
        try:
            response = await self.client.get(url)
            self._log_traffic(response)
            return response
        except Exception as e:
            raise Exception(f"文件存在性检查失败: {str(e)}")
    
    async def close(self):
        """关闭客户端"""
        await self.client.aclose()
