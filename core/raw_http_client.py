#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RawSocket HTTP客户端 - 字节级HTTP控制引擎

完全重写HTTP客户端，绕过requests/httpx的限制：
1. 精确控制 multipart/form-data boundary
2. 自定义 filename 编码和特殊字符注入
3. 支持各种绕过技术的字节级操控


"""

import socket
import ssl
import re
import time
import random
import hashlib
from urllib.parse import urlparse, urlencode
from typing import Dict, Optional, List, Tuple, Any
from dataclasses import dataclass, field


# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class RawHTTPResponse:
    """原生HTTP响应对象"""
    status_code: int = 0
    status_message: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    content: bytes = b""
    raw_request: bytes = b""
    raw_headers: bytes = b""
    raw_response: bytes = b""
    elapsed_time: float = 0.0
    error: Optional[str] = None
    
    @property
    def text(self) -> str:
        """尝试解码响应内容"""
        # 尝试多种编码
        for encoding in ['utf-8', 'gbk', 'gb2312', 'latin-1']:
            try:
                return self.content.decode(encoding)
            except:
                continue
        return self.content.decode('utf-8', errors='replace')
    
    @property
    def is_error(self) -> bool:
        return self.error is not None


@dataclass
class MultipartPart:
    """Multipart表单字段"""
    name: str
    filename: Optional[str] = None
    content: Optional[bytes] = None
    content_type: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)


# =============================================================================
# Encoding Utilities
# =============================================================================

class FilenameEncoder:
    """Filename编码器 - 支持各种绕过技术的特殊字符"""
    
    ENCODING_MODES = {
        'normal': None,                    # 正常编码
        'null_byte': '\x00',               # Null字节截断
        'url_null': '%00',                  # URL编码的null
        'double_ext': None,                 # 双扩展名
        'case_flip': None,                  # 大小写混合
        'space_trailing': ' ',              # 尾部空格
        'dot_trailing': '.',                # 尾部点
        'semicolon': ';',                   # 分号(IIS)
        'colon': ':',                       # 冒号(NTFS ADS)
        'data_stream': '::$DATA',           # NTFS数据流
        'path_traversal': '../',            # 路径穿越
        'double_dot': '..',                 # 双点
        'unicode': '\u202E',               # Unicode RTL覆盖
        'utf8_overlong': None,              # UTF-8超长编码
        'no_quotes': None,                  # 无引号
        'single_quotes': "'",               # 单引号
        'backslash': '\\',                   # 反斜杠(Windows)
        'forward_slash': '/',               # 正斜杠
    }
    
    @classmethod
    def encode(cls, filename: str, mode: str) -> str:
        """根据指定模式编码filename"""
        if mode == 'normal' or mode not in cls.ENCODING_MODES:
            return filename
        
        modifier = cls.ENCODING_MODES.get(mode)
        if modifier is None:
            # 对于需要特殊处理的模式
            return cls._special_encode(filename, mode)
        
        # 在合适的位置插入修饰符
        if mode in ['null_byte', 'url_null', 'space_trailing', 'dot_trailing']:
            return filename + modifier
        elif mode in ['semicolon', 'colon', 'data_stream']:
            return filename + modifier
        elif mode == 'path_traversal':
            return modifier + filename
        else:
            return filename + modifier
    
    @classmethod
    def _special_encode(cls, filename: str, mode: str) -> str:
        """特殊编码模式"""
        if '.' not in filename:
            return filename
        
        base, ext = filename.rsplit('.', 1)
        
        if mode == 'double_ext':
            # test.jpg -> shell.php.jpg
            safe_exts = ['jpg', 'png', 'gif']
            for safe_ext in safe_exts:
                if safe_ext in filename.lower():
                    idx = filename.lower().rfind(safe_ext)
                    return filename[:idx] + f'.php.{safe_ext}'
            return f'{base}.php.{ext}'
        
        elif mode == 'case_flip':
            # Php -> PhP
            result = []
            for i, c in enumerate(ext):
                result.append(c.upper() if i % 2 else c.lower())
            return f'{base}.{"".join(result)}'
        
        elif mode == 'no_quotes':
            return filename.replace('"', '')
        
        elif mode == 'single_quotes':
            return filename.replace('"', "'")
        
        elif mode == 'backslash':
            return filename.replace('/', '\\')
        
        elif mode == 'forward_slash':
            return filename.replace('\\', '/')
        
        return filename


# =============================================================================
# Raw HTTP Builder
# =============================================================================

class RawHTTPBuilder:
    """原始HTTP请求构建器"""
    
    CRLF = b'\r\n'
    CRLF_S = '\r\n'
    
    def __init__(self):
        self.method = 'POST'
        self.path = '/'
        self.host = 'localhost'
        self.port = 80
        self.use_ssl = False
        self.headers: Dict[str, str] = {}
        self.multipart_boundary: Optional[str] = None
        self.parts: List[MultipartPart] = []
        self.body: Optional[bytes] = None
    
    def set_url(self, url: str):
        """解析并设置URL"""
        parsed = urlparse(url)
        self.host = parsed.hostname or 'localhost'
        self.port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        self.use_ssl = parsed.scheme == 'https'
        self.path = parsed.path or '/'
        if parsed.query:
            self.path += '?' + parsed.query
    
    def add_header(self, key: str, value: str):
        """添加请求头"""
        self.headers[key] = value
    
    def set_basic_auth(self, username: str, password: str):
        """设置Basic认证"""
        import base64
        credentials = base64.b64encode(f'{username}:{password}'.encode()).decode()
        self.headers['Authorization'] = f'Basic {credentials}'
    
    def set_bearer_auth(self, token: str):
        """设置Bearer认证"""
        self.headers['Authorization'] = f'Bearer {token}'
    
    def set_multipart_boundary(self, boundary: str):
        """设置multipart boundary"""
        self.multipart_boundary = boundary
    
    def add_multipart_field(self, field: MultipartPart):
        """添加multipart字段"""
        self.parts.append(field)
    
    def set_body(self, body: bytes):
        """设置原始请求体"""
        self.body = body
    
    def build_request_line(self) -> bytes:
        """构建请求行"""
        return f'{self.method} {self.path} HTTP/1.1{self.CRLF_S}'.encode()
    
    def build_headers(self) -> bytes:
        """构建请求头"""
        lines = []
        
        # Host头（必需）— 省略默认端口 (80 for HTTP, 443 for HTTPS)
        default_port = 443 if self.use_ssl else 80
        if self.port == default_port:
            lines.append(f'Host: {self.host}')
        else:
            lines.append(f'Host: {self.host}:{self.port}')
        
        # 用户自定义头
        for key, value in self.headers.items():
            if key.lower() != 'host':  # 避免重复
                lines.append(f'{key}: {value}')
        
        # Content-Length（如果知道的话）
        # 构建完整请求后再计算
        
        return '\r\n'.join(lines).encode() + self.CRLF + self.CRLF
    
    def build_multipart_body(self) -> bytes:
        """构建multipart/form-data请求体"""
        if not self.multipart_boundary:
            raise ValueError("Multipart boundary not set")
        
        body_parts = []
        boundary = self.multipart_boundary.encode()
        
        for part in self.parts:
            # 边界
            body_parts.append(b'--' + boundary + self.CRLF)
            
            # Content-Disposition
            disposition = f'form-data; name="{part.name}"'
            if part.filename:
                # 支持自定义filename编码
                disposition += f'; filename="{part.filename}"'
            
            body_parts.append(f'Content-Disposition: {disposition}{self.CRLF_S}'.encode())
            
            # Content-Type
            if part.content_type:
                body_parts.append(f'Content-Type: {part.content_type}{self.CRLF_S}'.encode())
            
            # 自定义头
            for key, value in part.headers.items():
                body_parts.append(f'{key}: {value}{self.CRLF_S}'.encode())
            
            # 空行
            body_parts.append(self.CRLF)
            
            # 内容
            if part.content:
                body_parts.append(part.content)
            
            body_parts.append(self.CRLF)
        
        # 结束边界
        body_parts.append(b'--' + boundary + b'--' + self.CRLF)
        
        return b''.join(body_parts)
    
    def build(self) -> Tuple[bytes, int]:
        """
        构建完整的HTTP请求
        
        Returns:
            (raw_request_bytes, content_length)
        """
        # 如果有multipart parts，优先使用
        if self.parts and self.multipart_boundary:
            self.body = self.build_multipart_body()
        elif self.body is None:
            self.body = b''
        
        # 添加Content-Length
        if self.body:
            self.headers['Content-Length'] = str(len(self.body))
        
        # 构建完整请求
        request = self.build_request_line() + self.build_headers()
        
        if self.body:
            request += self.body
        
        return request, len(self.body)


# =============================================================================
# Raw HTTP Client
# =============================================================================

class RawHTTPClient:
    """
    原始Socket HTTP客户端
    
    特性：
    1. 字节级HTTP控制
    2. 精确控制multipart boundary
    3. 支持filename编码绕过
    4. 支持代理
    5. SSL/TLS支持
    """
    
    DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    DEFAULT_TIMEOUT = 30
    
    def __init__(self, 
                 timeout: int = DEFAULT_TIMEOUT, 
                 proxy: Optional[str] = None,
                 verify_ssl: bool = False,
                 delay: float = 0,
                 user_agent: Optional[str] = None):
        self.timeout = timeout
        self.proxy = proxy
        self.verify_ssl = verify_ssl
        self.delay = delay
        self.user_agent = user_agent or self.DEFAULT_USER_AGENT
        
        # 会话状态
        self.cookies: Dict[str, str] = {}
        self.custom_headers: Dict[str, str] = {}
        
        # 用于保持连接
        self._sock: Optional[socket.socket] = None
        self._last_host: Optional[str] = None
        self._last_port: Optional[int] = None
        self._last_ssl: bool = False
    
    def _get_cookie_header(self) -> str:
        """构建Cookie头"""
        if not self.cookies:
            return ""
        return "; ".join([f"{k}={v}" for k, v in self.cookies.items()])
    
    def _create_socket(self, host: str, port: int, use_ssl: bool) -> socket.socket:
        """创建Socket连接"""
        # 如果已有连接且目标相同，复用
        if (self._sock and 
            self._last_host == host and 
            self._last_port == port and 
            self._last_ssl == use_ssl):
            try:
                # 【修复】使用select检测连接是否可用，而不是send空数据
                import select
                ready, _, _ = select.select([self._sock], [], [], 0)
                if ready:
                    # 有数据可读，检查是否是对端关闭
                    try:
                        data = self._sock.recv(1, socket.MSG_PEEK)
                        if data == b'':
                            # 连接已关闭
                            self.close()
                        else:
                            return self._sock
                    except:
                        self.close()
                else:
                    # 连接看起来还正常
                    self._sock.settimeout(self.timeout)
                    return self._sock
            except:
                pass
        
        # 关闭旧连接
        self.close()
        
        # 创建新连接
        if use_ssl:
            context = ssl.create_default_context()
            if not self.verify_ssl:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            
            raw_sock = socket.create_connection((host, port), timeout=self.timeout)
            sock = context.wrap_socket(raw_sock, server_hostname=host)
        else:
            sock = socket.create_connection((host, port), timeout=self.timeout)
        
        self._sock = sock
        self._last_host = host
        self._last_port = port
        self._last_ssl = use_ssl
        
        return sock
    
    def _parse_proxy(self) -> Tuple[Optional[str], Optional[int], bool]:
        """解析代理设置"""
        if not self.proxy:
            return None, None, False
        
        parsed = urlparse(self.proxy)
        return parsed.hostname, parsed.port or 8080, parsed.scheme == 'https'
    
    def _build_proxy_request(self, builder: RawHTTPBuilder) -> bytes:
        """构建代理请求（CONNECT或直接转发）"""
        proxy_host, proxy_port, proxy_ssl = self._parse_proxy()
        
        if not proxy_host:
            return builder.build()[0]
        
        # HTTP代理
        if proxy_ssl:
            # HTTPS代理需要CONNECT
            connect_request = f"CONNECT {builder.host}:{builder.port} HTTP/1.1\r\n"
            connect_request += f"Host: {builder.host}:{builder.port}\r\n"
            connect_request += "\r\n"
            
            # 先发送CONNECT建立隧道
            proxy_sock = socket.create_connection((proxy_host, proxy_port), timeout=self.timeout)
            
            if builder.use_ssl:
                context = ssl.create_default_context()
                sock = context.wrap_socket(proxy_sock, server_hostname=builder.host)
            else:
                sock = proxy_sock
            
            # 发送CONNECT
            sock.send(connect_request.encode())
            
            # 读取CONNECT响应
            response = b""
            while b"\r\n\r\n" not in response:
                response += sock.recv(4096)
            
            # 检查是否成功
            if b"200" not in response.split(b"\r\n")[0]:
                raise Exception(f"Proxy CONNECT failed: {response.decode()}")
            
            # 保存连接
            self._sock = sock
            self._last_host = builder.host
            self._last_port = builder.port
            self._last_ssl = builder.use_ssl
            
            # 发送实际请求
            request, _ = builder.build()
            sock.send(request)
            return b""  # 请求已直接发送
        
        else:
            # HTTP代理，直接转发
            sock = socket.create_connection((proxy_host, proxy_port), timeout=self.timeout)
            self._sock = sock
            
            request, _ = builder.build()
            sock.send(request)
            return b""
    
    def _send_request(self, builder: RawHTTPBuilder) -> RawHTTPResponse:
        """发送请求并接收响应"""
        start_time = time.time()
        
        try:
            # 解析目标
            host = builder.host
            port = builder.port
            use_ssl = builder.use_ssl
            
            # 如果使用代理，修改目标
            proxy_host, proxy_port, _ = self._parse_proxy()
            
            if proxy_host:
                if use_ssl:
                    # HTTPS over HTTP Proxy -> CONNECT
                    sock = self._create_socket(proxy_host, proxy_port, False)
                    connect_req = f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n"
                    sock.sendall(connect_req.encode())
                    
                    # wait for 200 OK
                    resp = b""
                    while b"\r\n\r\n" not in resp:
                        resp += sock.recv(4096)
                    
                    if b"200" not in resp.split(b"\r\n")[0]:
                        raise Exception(f"Proxy CONNECT failed: {resp.decode('latin-1')}")
                    
                    # wrap SSL
                    context = ssl.create_default_context()
                    if not self.verify_ssl:
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                    sock = context.wrap_socket(sock, server_hostname=host)
                    self._sock = sock
                    self._last_ssl = True
                    
                    request, _ = builder.build()
                    sock.sendall(request)
                else:
                    # HTTP over HTTP Proxy -> absolute URI
                    sock = self._create_socket(proxy_host, proxy_port, False)
                    # modify builder path to absolute URI
                    original_path = builder.path
                    builder.path = f"http://{host}:{port}{original_path}"
                    request, _ = builder.build()
                    builder.path = original_path # restore
                    sock.sendall(request)
            else:
                # 创建连接并发送
                sock = self._create_socket(host, port, use_ssl)
                request, _ = builder.build()
                sock.sendall(request)
            
            # 记录最后一次请求
            header_end = request.find(b'\r\n\r\n')
            if header_end != -1:
                self._last_request = {
                    'headers': request[:header_end].decode('latin-1', errors='replace'),
                    'body': request[header_end+4:] if builder.method != 'GET' else b''
                }

            # 接收响应 - 【修复】添加更严格的超时控制
            response_data = b""
            sock.settimeout(self.timeout)
            start_recv_time = time.time()
            max_recv_time = self.timeout  # 最多接收时间
            
            # Read until headers end
            while b"\r\n\r\n" not in response_data:
                try:
                    # 【修复】检查总接收时间，避免无限等待
                    if time.time() - start_recv_time > max_recv_time:
                        print(f"[RawHTTPClient] 接收headers超时")
                        break
                    
                    sock.settimeout(1.0)  # 每次recv最多等1秒
                    chunk = sock.recv(8192)
                    if not chunk:
                        break
                    response_data += chunk
                except socket.timeout:
                    # 【修复】如果是headers还没读完就超时，直接退出
                    if b"\r\n\r\n" not in response_data:
                        print(f"[RawHTTPClient] 接收headers时超时，已接收 {len(response_data)} bytes")
                        break
            
            # 【修复】重置超时时间
            sock.settimeout(self.timeout)
            
            if b"\r\n\r\n" in response_data:
                header_end = response_data.find(b'\r\n\r\n')
                headers_part = response_data[:header_end]
                body_part = response_data[header_end+4:]
                
                content_length = -1
                is_chunked = False
                for line in headers_part.split(b'\r\n'):
                    if line.lower().startswith(b'content-length:'):
                        try:
                            content_length = int(line.split(b':')[1].strip())
                        except:
                            pass
                    elif line.lower().startswith(b'transfer-encoding:') and b'chunked' in line.lower():
                        is_chunked = True
                
                if content_length >= 0:
                    # 【修复】限制body读取时间
                    body_start_time = time.time()
                    while len(body_part) < content_length:
                        if time.time() - body_start_time > 5:  # 最多5秒读body
                            break
                        try:
                            sock.settimeout(1.0)
                            chunk = sock.recv(8192)
                            if not chunk:
                                break
                            body_part += chunk
                            response_data += chunk
                        except socket.timeout:
                            break
                elif is_chunked:
                    # 【修复】限制chunked读取时间
                    chunked_start_time = time.time()
                    while b"0\r\n\r\n" not in body_part:
                        if time.time() - chunked_start_time > 5:
                            break
                        try:
                            sock.settimeout(1.0)
                            chunk = sock.recv(8192)
                            if not chunk:
                                break
                            body_part += chunk
                            response_data += chunk
                        except socket.timeout:
                            break
                else:
                    # 没有content-length也不是chunked，读取直到超时或连接关闭
                    # 【修复】限制读取时间和数据量
                    no_cl_start_time = time.time()
                    max_no_cl_size = 1024 * 1024  # 最多1MB
                    while len(response_data) < max_no_cl_size:
                        if time.time() - no_cl_start_time > 3:  # 最多3秒
                            break
                        try:
                            sock.settimeout(1.0)
                            chunk = sock.recv(8192)
                            if not chunk:
                                break
                            response_data += chunk
                        except socket.timeout:
                            break
            
            elapsed = time.time() - start_time
            
            # 解析响应
            resp = self._parse_response(response_data, elapsed)
            resp.raw_request = request
            
            # 【修复】请求完成后关闭连接，避免复用导致的超时
            self.close()
            
            return resp
            
        except Exception as e:
            elapsed = time.time() - start_time
            return RawHTTPResponse(
                status_code=0,
                error=str(e),
                raw_request=locals().get("request", b"") if "request" in locals() else b"",
                elapsed_time=elapsed
            )
    
    def _parse_response(self, data: bytes, elapsed: float) -> RawHTTPResponse:
        """解析HTTP响应"""
        if not data:
            return RawHTTPResponse(
                status_code=0,
                error="Empty response",
                elapsed_time=elapsed
            )
        
        # 查找header和body的分隔
        header_end = data.find(b'\r\n\r\n')
        if header_end == -1:
            return RawHTTPResponse(
                status_code=0,
                error="Invalid HTTP response",
                raw_response=data,
                elapsed_time=elapsed
            )
        
        raw_headers = data[:header_end]
        body = data[header_end + 4:]
        
        # 解析状态行
        header_lines = raw_headers.decode('latin-1', errors='replace').split('\r\n')
        status_line = header_lines[0]
        
        status_match = re.match(r'HTTP/\d\.\d\s+(\d+)\s*(.*)', status_line)
        if status_match:
            status_code = int(status_match.group(1))
            status_message = status_match.group(2)
        else:
            status_code = 0
            status_message = ""
        
        # 解析响应头
        headers = {}
        for line in header_lines[1:]:
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip().lower()] = value.strip()
        
        # 处理chunked编码
        if headers.get('transfer-encoding', '').lower() == 'chunked':
            body = self._decode_chunked(body)
        
        # 更新cookies
        if 'set-cookie' in headers:
            self._update_cookies(headers['set-cookie'])
        
        return RawHTTPResponse(
            status_code=status_code,
            status_message=status_message,
            headers=headers,
            content=body,
            raw_headers=raw_headers,
            raw_response=data,
            elapsed_time=elapsed
        )
    
    def _decode_chunked(self, body: bytes) -> bytes:
        """解码chunked传输编码"""
        result = b""
        pos = 0
        
        while pos < len(body):
            # 读取chunk大小
            line_end = body.find(b'\r\n', pos)
            if line_end == -1:
                break
            
            chunk_size = int(body[pos:line_end].split(b';')[0].strip(), 16)
            if chunk_size == 0:
                break
            
            pos = line_end + 2
            result += body[pos:pos + chunk_size]
            pos += chunk_size + 2  # 跳过\r\n
        
        return result
    
    def _update_cookies(self, cookie_header: str):
        """更新Cookie"""
        # Set-Cookie format: "name=value; Path=/; HttpOnly; Expires=..."
        # Only the first "name=value" pair before the first ";" is the actual cookie.
        # Splitting on "," handles multiple Set-Cookie values joined by the header parser.
        for part in cookie_header.split(','):
            # Take only the cookie name=value (before the first ";")
            cookie_part = part.strip().split(';')[0].strip()
            if '=' in cookie_part:
                key, value = cookie_part.split('=', 1)
                key = key.strip()
                value = value.strip()
                if key:
                    self.cookies[key] = value
    
    def set_header(self, key: str, value: str):
        """设置请求头"""
        self.custom_headers[key] = value
    
    def set_cookie(self, cookies: Dict[str, str]):
        """设置Cookie"""
        self.cookies.update(cookies)
    
    def set_auth_basic(self, username: str, password: str):
        """设置Basic认证"""
        import base64
        self.custom_headers['Authorization'] = f'Basic {base64.b64encode(f"{username}:{password}".encode()).decode()}'
    
    def set_auth_bearer(self, token: str):
        """设置Bearer认证"""
        self.custom_headers['Authorization'] = f'Bearer {token}'
    
    # =========================================================================
    # Core Request Methods
    # =========================================================================
    
    def get(self, url: str, **kwargs) -> RawHTTPResponse:
        """发送GET请求"""
        if self.delay > 0:
            time.sleep(self.delay + random.uniform(0, 0.5))
        
        builder = RawHTTPBuilder()
        builder.method = 'GET'
        builder.set_url(url)
        
        self._add_common_headers(builder)
        
        return self._send_request(builder)
    
    def post(self, url: str, data: Optional[bytes] = None, **kwargs) -> RawHTTPResponse:
        """发送POST请求"""
        if self.delay > 0:
            time.sleep(self.delay + random.uniform(0, 0.5))
        
        builder = RawHTTPBuilder()
        builder.method = 'POST'
        builder.set_url(url)
        
        self._add_common_headers(builder)
        
        if data:
            builder.body = data
            builder.headers['Content-Type'] = builder.headers.get('Content-Type', 'application/x-www-form-urlencoded')
        
        return self._send_request(builder)
    
    def _add_common_headers(self, builder: RawHTTPBuilder):
        """添加通用请求头"""
        builder.headers['User-Agent'] = self.user_agent
        builder.headers['Accept'] = 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'
        builder.headers['Accept-Language'] = 'zh-CN,zh;q=0.9,en;q=0.8'
        builder.headers['Accept-Encoding'] = 'gzip, deflate'
        # 【修复】禁用keep-alive，避免连接复用导致的超时问题
        builder.headers['Connection'] = 'close'
        
        # 添加自定义头
        builder.headers.update(self.custom_headers)
        
        # 添加Cookie
        cookie_header = self._get_cookie_header()
        if cookie_header:
            builder.headers['Cookie'] = cookie_header
    
    # =========================================================================
    # Multipart File Upload Methods
    # =========================================================================
    
    def upload_multipart(self, 
                        url: str,
                        fields: List[MultipartPart],
                        boundary: Optional[str] = None,
                        custom_headers: Optional[Dict[str, str]] = None) -> RawHTTPResponse:
        """
        上传multipart/form-data（核心方法）
        
        Args:
            url: 目标URL
            fields: 字段列表
            boundary: 自定义boundary（推荐使用，精确控制）
            custom_headers: 自定义请求头
        
        Returns:
            RawHTTPResponse
        """
        if self.delay > 0:
            time.sleep(self.delay + random.uniform(0, 0.5))
        
        builder = RawHTTPBuilder()
        builder.method = 'POST'
        builder.set_url(url)
        
        # 设置boundary
        if boundary:
            builder.multipart_boundary = boundary
        else:
            builder.multipart_boundary = self._generate_boundary()
        
        # 添加字段
        for field in fields:
            builder.add_multipart_field(field)
        
        # Content-Type
        builder.headers['Content-Type'] = f'multipart/form-data; boundary={builder.multipart_boundary}'
        
        # 添加通用头
        self._add_common_headers(builder)
        
        # 添加自定义头
        if custom_headers:
            builder.headers.update(custom_headers)
        
        return self._send_request(builder)
    
    def upload_file(self,
                   url: str,
                   field_name: str,
                   filename: str,
                   content: bytes,
                   content_type: str = "application/octet-stream",
                   boundary: Optional[str] = None,
                   filename_encoding: Optional[str] = None,
                   extra_fields: Optional[Dict[str, str]] = None) -> RawHTTPResponse:
        """
        上传单个文件（高级方法）
        
        Args:
            url: 目标URL
            field_name: 字段名
            filename: 文件名（支持编码绕过）
            content: 文件内容
            content_type: Content-Type
            boundary: 自定义boundary
            filename_encoding: filename编码模式（null_byte, double_ext, case_flip等）
            extra_fields: 额外的表单字段
        
        Returns:
            RawHTTPResponse
        """
        # 应用filename编码
        if filename_encoding:
            actual_filename = FilenameEncoder.encode(filename, filename_encoding)
        else:
            actual_filename = filename
        
        fields = []
        
        # 添加文件字段
        fields.append(MultipartPart(
            name=field_name,
            filename=actual_filename,
            content=content,
            content_type=content_type
        ))
        
        # 添加额外字段
        if extra_fields:
            for name, value in extra_fields.items():
                fields.append(MultipartPart(
                    name=name,
                    content=value.encode() if isinstance(value, str) else value
                ))
        
        return self.upload_multipart(url, fields, boundary)
    
    def upload_file_raw(self,
                        url: str,
                        field_name: str,
                        filename: str,
                        content: bytes,
                        content_type: str = "application/octet-stream",
                        boundary: Optional[str] = None,
                        extra_fields: Optional[Dict[str, str]] = None,
                        extra_headers: Optional[Dict[str, str]] = None) -> RawHTTPResponse:
        """
        上传文件（最原始版本，完全控制）
        
        完全自定义每个字节，绕过所有自动处理。
        """
        if self.delay > 0:
            time.sleep(self.delay + random.uniform(0, 0.5))
        
        # 生成boundary
        bnd = boundary or self._generate_boundary()
        bnd_bytes = bnd.encode()
        
        # 构建请求体
        body_parts = []
        
        # 文件字段
        body_parts.append(b'--' + bnd_bytes + b'\r\n')
        body_parts.append(f'Content-Disposition: form-data; name="{field_name}"; filename="{filename}"\r\n'.encode())
        body_parts.append(f'Content-Type: {content_type}\r\n'.encode())
        body_parts.append(b'\r\n')
        body_parts.append(content)
        body_parts.append(b'\r\n')
        
        # 额外字段
        if extra_fields:
            for name, value in extra_fields.items():
                body_parts.append(b'--' + bnd_bytes + b'\r\n')
                body_parts.append(f'Content-Disposition: form-data; name="{name}"\r\n'.encode())
                body_parts.append(b'\r\n')
                if isinstance(value, str):
                    value = value.encode()
                body_parts.append(value)
                body_parts.append(b'\r\n')
        
        # 结束边界
        body_parts.append(b'--' + bnd_bytes + b'--\r\n')
        
        body = b''.join(body_parts)
        
        # 构建请求
        builder = RawHTTPBuilder()
        builder.method = 'POST'
        builder.set_url(url)
        
        builder.headers['Content-Type'] = f'multipart/form-data; boundary={bnd}'
        builder.headers['Content-Length'] = str(len(body))
        
        self._add_common_headers(builder)
        
        if extra_headers:
            builder.headers.update(extra_headers)
        
        builder.body = body
        
        return self._send_request(builder)
    
    def _generate_boundary(self) -> str:
        """生成随机boundary"""
        chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
        random_part = ''.join(random.choice(chars) for _ in range(16))
        return f'----WebKitFormBoundaryUploadRanger{random_part}'
    
    # =========================================================================
    # Utility Methods
    # =========================================================================
    
    def check_url(self, url: str) -> Tuple[bool, RawHTTPResponse]:
        """检查URL是否可访问"""
        try:
            response = self.get(url)
            return response.status_code > 0, response
        except Exception as e:
            return False, RawHTTPResponse(error=str(e))
    
    def close(self):
        """关闭连接"""
        if self._sock:
            try:
                self._sock.close()
            except:
                pass
            self._sock = None
            self._last_host = None
            self._last_port = None
            self._last_ssl = False
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


# =============================================================================
# Convenience Functions
# =============================================================================

def create_upload_request(url: str,
                          field_name: str,
                          filename: str,
                          content: bytes,
                          content_type: str = "image/jpeg",
                          boundary: Optional[str] = None,
                          filename_encoding: Optional[str] = None,
                          extra_fields: Optional[Dict[str, str]] = None) -> bytes:
    """
    便捷函数：创建上传请求的原始字节
    
    用于调试或手动发送。
    """
    with RawHTTPClient() as client:
        bnd = boundary or client._generate_boundary()
        
        # 应用filename编码
        if filename_encoding:
            actual_filename = FilenameEncoder.encode(filename, filename_encoding)
        else:
            actual_filename = filename
        
        fields = [MultipartPart(
            name=field_name,
            filename=actual_filename,
            content=content,
            content_type=content_type
        )]
        
        if extra_fields:
            for name, value in extra_fields.items():
                fields.append(MultipartPart(
                    name=name,
                    content=value.encode() if isinstance(value, str) else value
                ))
        
        builder = RawHTTPBuilder()
        builder.method = 'POST'
        builder.set_url(url)
        builder.multipart_boundary = bnd
        
        for field in fields:
            builder.add_multipart_field(field)
        
        builder.headers['Content-Type'] = f'multipart/form-data; boundary={bnd}'
        builder.headers['User-Agent'] = client.user_agent
        
        request, _ = builder.build()
        return request


# =============================================================================
# Testing
# =============================================================================

if __name__ == "__main__":
    print("RawHTTPClient Test")
    print("=" * 50)
    
    # 测试filename编码
    print("\nFilename Encoding Test:")
    test_names = ["shell.php", "test.jpg", "evil.asp"]
    for mode in ['normal', 'null_byte', 'double_ext', 'case_flip']:
        print(f"\n  Mode: {mode}")
        for name in test_names:
            encoded = FilenameEncoder.encode(name, mode)
            print(f"    {name} -> {encoded}")
    
    # 测试基础请求构建
    print("\n\nRequest Building Test:")
    with RawHTTPClient() as client:
        builder = RawHTTPBuilder()
        builder.method = 'POST'
        builder.set_url('http://example.com/upload.php')
        builder.multipart_boundary = 'test-boundary-12345'
        
        builder.add_multipart_field(MultipartPart(
            name='file',
            filename='test.php',
            content=b'<?php echo "test"; ?>',
            content_type='image/jpeg'
        ))
        
        request, length = builder.build()
        print(f"Request length: {length} bytes")
        print("\nRequest preview:")
        print(request[:500].decode('latin-1'))
