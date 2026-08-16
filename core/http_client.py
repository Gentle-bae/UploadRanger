#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HTTP客户端模块 - 处理所有HTTP请求
"""

import requests
import urllib3
from urllib.parse import urljoin, urlparse
import time
import random

# 禁用SSL警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class HTTPClient:
    """HTTP客户端类"""
    
    def __init__(self, timeout=30, proxy=None, verify_ssl=True, delay=0):
        self.session = requests.Session()
        self.timeout = timeout
        self.proxy = proxy
        self.verify_ssl = verify_ssl
        self.delay = delay
        
        # 设置默认headers
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
        })
        
        # 设置代理
        if proxy:
            self.session.proxies = {
                "http": proxy,
                "https": proxy
            }
    
    def set_header(self, key, value):
        """设置请求头"""
        self.session.headers[key] = value
    
    def set_cookie(self, cookie_string):
        """设置Cookie"""
        self.session.headers["Cookie"] = cookie_string
    
    def set_auth(self, auth_type, credentials):
        """设置认证信息"""
        if auth_type == "basic":
            self.session.auth = credentials
        elif auth_type == "bearer":
            self.session.headers["Authorization"] = f"Bearer {credentials}"
    
    def get(self, url, **kwargs):
        """发送GET请求"""
        try:
            if self.delay > 0:
                time.sleep(self.delay + random.uniform(0, 0.5))
            
            response = self.session.get(
                url,
                timeout=self.timeout,
                verify=self.verify_ssl,
                **kwargs
            )
            return response
        except Exception as e:
            return {"error": str(e)}
    
    def post(self, url, data=None, files=None, **kwargs):
        """发送POST请求"""
        try:
            if self.delay > 0:
                time.sleep(self.delay + random.uniform(0, 0.5))
            
            response = self.session.post(
                url,
                data=data,
                files=files,
                timeout=self.timeout,
                verify=self.verify_ssl,
                **kwargs
            )
            return response
        except Exception as e:
            return {"error": str(e)}
    
    def put(self, url, data=None, **kwargs):
        """发送PUT请求"""
        try:
            if self.delay > 0:
                time.sleep(self.delay + random.uniform(0, 0.5))
            
            response = self.session.put(
                url,
                data=data,
                timeout=self.timeout,
                verify=self.verify_ssl,
                **kwargs
            )
            return response
        except Exception as e:
            return {"error": str(e)}
    
    def upload_file(self, url, field_name, file_path, filename=None, 
                    data=None, headers=None, content_type=None):
        """上传文件"""
        try:
            if self.delay > 0:
                time.sleep(self.delay + random.uniform(0, 0.5))
            
            # 准备文件
            filename = filename or file_path.split('/')[-1].split('\\')[-1]
            
            with open(file_path, 'rb') as f:
                file_content = f.read()
            
            files = {
                field_name: (filename, file_content, content_type or 'application/octet-stream')
            }
            
            # 临时修改headers
            original_headers = self.session.headers.copy()
            if headers:
                for key, value in headers.items():
                    self.session.headers[key] = value
            
            # 移除Content-Type让requests自动设置
            if 'Content-Type' in self.session.headers:
                del self.session.headers['Content-Type']
            
            response = self.session.post(
                url,
                files=files,
                data=data or {},
                timeout=self.timeout,
                verify=self.verify_ssl
            )
            
            # 恢复原始headers
            self.session.headers = original_headers
            
            return response
            
        except Exception as e:
            return {"error": str(e)}
    
    def upload_bytes(self, url, field_name, file_bytes, filename, 
                     data=None, headers=None, content_type=None):
        """上传字节数据"""
        try:
            if self.delay > 0:
                time.sleep(self.delay + random.uniform(0, 0.5))
            
            files = {
                field_name: (filename, file_bytes, content_type or 'application/octet-stream')
            }
            
            # 临时修改headers
            original_headers = self.session.headers.copy()
            if headers:
                for key, value in headers.items():
                    self.session.headers[key] = value
            
            if 'Content-Type' in self.session.headers:
                del self.session.headers['Content-Type']
            
            response = self.session.post(
                url,
                files=files,
                data=data or {},
                timeout=self.timeout,
                verify=self.verify_ssl
            )
            
            self.session.headers = original_headers
            
            return response
            
        except Exception as e:
            return {"error": str(e)}
    
    def check_url(self, url):
        """检查URL是否可访问"""
        try:
            response = self.get(url, allow_redirects=True)
            if isinstance(response, dict) and "error" in response:
                return False, response["error"]
            return True, response
        except Exception as e:
            return False, str(e)
    
    def close(self):
        """关闭会话"""
        self.session.close()
