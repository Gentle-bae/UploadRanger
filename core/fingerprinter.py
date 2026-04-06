#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Environment Fingerprinter - 环境指纹识别模块

自动识别目标服务器环境，包括：
- Web服务器类型 (Apache/Nginx/IIS/Tomcat等)
- 操作系统类型 (Linux/Windows)
- 后端语言 (PHP/ASP/ASPX/JSP等)
- 语言版本


"""

import re
import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any, Set
from urllib.parse import urljoin, urlparse


# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class EnvironmentProfile:
    """环境指纹配置文件"""
    # 服务器信息
    server: str = "Unknown"  # Apache/Nginx/IIS/Tomcat/Lighttpd/Caddy/Unknown
    server_version: Optional[str] = None
    
    # 操作系统
    os: str = "Unknown"  # Linux/Windows/Unix/Unknown
    os_version: Optional[str] = None
    
    # 后端语言
    language: str = "Unknown"  # PHP/ASP/ASPX/JSP/Python/Ruby/Perl/Unknown
    lang_version: Optional[str] = None
    
    # 框架检测
    framework: Optional[str] = None  # Laravel/Django/Spring/etc
    framework_version: Optional[str] = None
    
    # WAF检测
    waf_detected: bool = False
    waf_name: Optional[str] = None
    
    # 策略配置
    enabled_strategies: List[str] = field(default_factory=list)
    disabled_strategies: List[str] = field(default_factory=list)
    suggested_payloads: List[str] = field(default_factory=list)
    
    # 原始指纹数据
    raw_headers: Dict[str, str] = field(default_factory=dict)
    fingerprint_confidence: float = 0.0  # 0.0-1.0
    
    def to_dict(self) -> Dict:
        """转换为字典"""
        return {
            'server': self.server,
            'server_version': self.server_version,
            'os': self.os,
            'os_version': self.os_version,
            'language': self.language,
            'lang_version': self.lang_version,
            'framework': self.framework,
            'framework_version': self.framework_version,
            'waf_detected': self.waf_detected,
            'waf_name': self.waf_name,
            'enabled_strategies': self.enabled_strategies,
            'disabled_strategies': self.disabled_strategies,
            'suggested_payloads': self.suggested_payloads,
            'fingerprint_confidence': self.fingerprint_confidence
        }
    
    def __str__(self) -> str:
        """字符串表示"""
        parts = [f"{self.server}"]
        if self.server_version:
            parts.append(f"{self.server_version}")
        parts.append(f"on {self.os}")
        if self.language != "Unknown":
            parts.append(f"+ {self.language}")
            if self.lang_version:
                parts.append(f"{self.lang_version}")
        if self.waf_detected:
            parts.append(f"[WAF: {self.waf_name or 'Unknown'}]")
        return " ".join(parts)


# =============================================================================
# Strategy Matrix
# =============================================================================

STRATEGY_MATRIX = {
    'IIS_Windows': {
        'enable': [
            'ntfs_ads', 'iis_semicolon', 'asp', 'aspx', 'asa', 'cer',
            'windows_trailing_dot', 'windows_reserved_names', 'short_name',
            'stream_data', 'alternate_data_stream'
        ],
        'disable': [
            'htaccess', 'user_ini', 'apache_multiext', 'linux_hidden_file',
            'php_wrappers', 'apache_htaccess', 'apache_php_config'
        ],
        'priority': ['iis_semicolon', 'ntfs_ads', 'asp', 'aspx']
    },
    'Apache_Linux': {
        'enable': [
            'htaccess', 'user_ini', 'apache_multiext', 'php', 'php3', 'php4', 'php5',
            'pht', 'phtml', 'phps', 'phar', 'linux_path_traversal',
            'linux_hidden_file', 'double_extension', 'case_bypass'
        ],
        'disable': [
            'ntfs_ads', 'iis_semicolon', 'asp', 'aspx', 'windows_trailing_dot',
            'windows_reserved_names', 'short_name', 'stream_data'
        ],
        'priority': ['htaccess', 'php', 'apache_multiext', 'user_ini']
    },
    'Apache_Windows': {
        'enable': [
            'htaccess', 'php', 'apache_multiext', 'windows_trailing_dot',
            'case_bypass', 'double_extension'
        ],
        'disable': [
            'ntfs_ads', 'iis_semicolon', 'linux_hidden_file'
        ],
        'priority': ['htaccess', 'php', 'apache_multiext']
    },
    'Nginx_Linux': {
        'enable': [
            'php_fpm', 'nginx_path_confusion', 'php', 'php3', 'php4', 'php5',
            'pht', 'phtml', 'phps', 'null_byte', 'linux_path_traversal',
            'cgi_path_info', 'fastcgi_split_path'
        ],
        'disable': [
            'htaccess', 'ntfs_ads', 'iis_semicolon', 'asp', 'aspx',
            'apache_multiext', 'user_ini'
        ],
        'priority': ['nginx_path_confusion', 'php_fpm', 'php', 'null_byte']
    },
    'Nginx_Windows': {
        'enable': [
            'php_fpm', 'php', 'windows_trailing_dot', 'null_byte',
            'cgi_path_info', 'fastcgi_split_path'
        ],
        'disable': [
            'htaccess', 'ntfs_ads', 'iis_semicolon', 'apache_multiext'
        ],
        'priority': ['nginx_path_confusion', 'php_fpm', 'php']
    },
    'Tomcat': {
        'enable': [
            'jsp', 'jspx', 'jsw', 'jsv', 'jspf', 'war', 'do', 'action',
            'java_serialization', 'jndi_injection'
        ],
        'disable': [
            'php', 'asp', 'aspx', 'htaccess', 'ntfs_ads', 'iis_semicolon',
            'apache_multiext', 'user_ini'
        ],
        'priority': ['jsp', 'war', 'jspx']
    },
    'Lighttpd': {
        'enable': [
            'php', 'cgi', 'pl', 'py', 'rb', 'lighttpd_path_info',
            'linux_path_traversal'
        ],
        'disable': [
            'htaccess', 'ntfs_ads', 'iis_semicolon', 'asp'
        ],
        'priority': ['php', 'cgi', 'lighttpd_path_info']
    },
    'Caddy': {
        'enable': [
            'php', 'cgi', 'linux_path_traversal'
        ],
        'disable': [
            'htaccess', 'ntfs_ads', 'iis_semicolon', 'asp', 'apache_multiext'
        ],
        'priority': ['php', 'cgi']
    },
    'Unknown_Linux': {
        'enable': [
            'php', 'jsp', 'cgi', 'pl', 'py', 'rb', 'linux_path_traversal',
            'linux_hidden_file', 'case_bypass', 'double_extension',
            'null_byte', 'special_chars'
        ],
        'disable': [
            'ntfs_ads', 'iis_semicolon', 'windows_trailing_dot',
            'windows_reserved_names'
        ],
        'priority': ['php', 'jsp', 'null_byte', 'linux_path_traversal']
    },
    'Unknown_Windows': {
        'enable': [
            'asp', 'aspx', 'php', 'jsp', 'windows_trailing_dot',
            'case_bypass', 'double_extension', 'null_byte', 'special_chars'
        ],
        'disable': [
            'htaccess', 'user_ini', 'linux_hidden_file'
        ],
        'priority': ['asp', 'aspx', 'php', 'null_byte']
    }
}


# =============================================================================
# Server Fingerprints
# =============================================================================

SERVER_FINGERPRINTS = {
    # Web服务器指纹
    'Apache': {
        'headers': ['Server', 'X-Forwarded-Server'],
        'patterns': [
            (r'Apache[/\s]([\d.]+)', 'version'),
            (r'Apache', 'name'),
        ],
        'indicators': ['mod_', '.htaccess support']
    },
    'Nginx': {
        'headers': ['Server'],
        'patterns': [
            (r'nginx[/\s]([\d.]+)', 'version'),
            (r'nginx', 'name'),
        ],
        'indicators': ['X-FastCGI-Cache']
    },
    'IIS': {
        'headers': ['Server'],
        'patterns': [
            (r'Microsoft-IIS[/\s]([\d.]+)', 'version'),
            (r'IIS', 'name'),
        ],
        'indicators': ['ASP.NET', 'X-Powered-By: ASP.NET']
    },
    'Tomcat': {
        'headers': ['Server'],
        'patterns': [
            (r'Apache-Coyote[/\s]([\d.]+)', 'version'),
            (r'Apache-Tomcat[/\s]([\d.]+)', 'version'),
            (r'Tomcat', 'name'),
        ],
        'indicators': ['JSESSIONID', '.jsp']
    },
    'Lighttpd': {
        'headers': ['Server'],
        'patterns': [
            (r'lighttpd[/\s]([\d.]+)', 'version'),
            (r'lighttpd', 'name'),
        ],
        'indicators': []
    },
    'Caddy': {
        'headers': ['Server'],
        'patterns': [
            (r'Caddy[/\s]([\d.]+)', 'version'),
            (r'Caddy', 'name'),
        ],
        'indicators': []
    },
    'OpenResty': {
        'headers': ['Server'],
        'patterns': [
            (r'openresty[/\s]([\d.]+)', 'version'),
            (r'openresty', 'name'),
        ],
        'indicators': []
    }
}

# 语言指纹
LANGUAGE_FINGERPRINTS = {
    'PHP': {
        'headers': ['X-Powered-By'],
        'patterns': [
            (r'PHP[/\s]([\d.]+)', 'version'),
            (r'PHP', 'name'),
        ],
        'cookies': ['PHPSESSID'],
        'extensions': ['.php', '.php3', '.php4', '.php5', '.phtml', '.pht'],
        'indicators': ['<?php', '<?=']
    },
    'ASP': {
        'headers': ['X-Powered-By'],
        'patterns': [
            (r'ASP[/\s]([\d.]+)', 'version'),
            (r'ASP', 'name'),
        ],
        'cookies': ['ASPSESSIONID'],
        'extensions': ['.asp', '.asa', '.cer'],
        'indicators': ['<%', '%>']
    },
    'ASPX': {
        'headers': ['X-Powered-By', 'X-AspNet-Version'],
        'patterns': [
            (r'ASP\.NET[/\s]([\d.]+)', 'version'),
            (r'\.NET[/\s]([\d.]+)', 'version'),
            (r'X-AspNet-Version:\s*([\d.]+)', 'version'),
        ],
        'cookies': ['ASP.NET_SessionId'],
        'extensions': ['.aspx', '.ashx', '.asmx', '.ascx'],
        'indicators': ['<%@', '<asp:']
    },
    'JSP': {
        'headers': ['X-Powered-By'],
        'patterns': [
            (r'JSP[/\s]([\d.]+)', 'version'),
            (r'Servlet[/\s]([\d.]+)', 'version'),
            (r'JSP', 'name'),
        ],
        'cookies': ['JSESSIONID'],
        'extensions': ['.jsp', '.jspx', '.jsw', '.jsv'],
        'indicators': ['<%!', '<%@', '<jsp:']
    },
    'Python': {
        'headers': ['X-Powered-By', 'Server'],
        'patterns': [
            (r'Python[/\s]([\d.]+)', 'version'),
            (r'WSGIServer[/\s]([\d.]+)', 'version'),
            (r'gunicorn[/\s]([\d.]+)', 'version'),
            (r'uWSGI[/\s]([\d.]+)', 'version'),
        ],
        'cookies': ['session', 'sessionid'],
        'extensions': ['.py', '.pyc', '.pyo'],
        'indicators': ['wsgi', 'django', 'flask']
    },
    'Ruby': {
        'headers': ['X-Powered-By', 'Server'],
        'patterns': [
            (r'Ruby[/\s]([\d.]+)', 'version'),
            (r'Phusion Passenger[/\s]([\d.]+)', 'version'),
            (r'WEBrick[/\s]([\d.]+)', 'version'),
        ],
        'cookies': ['_session_id', '_csrf_token'],
        'extensions': ['.rb', '.erb'],
        'indicators': ['rails', 'sinatra', 'rack']
    },
    'Perl': {
        'headers': ['Server'],
        'patterns': [
            (r'Perl[/\s]([\d.]+)', 'version'),
            (r'mod_perl[/\s]([\d.]+)', 'version'),
        ],
        'cookies': [],
        'extensions': ['.pl', '.cgi'],
        'indicators': ['#!/usr/bin/perl']
    }
}

# WAF指纹
WAF_FINGERPRINTS = {
    'Cloudflare': {
        'headers': ['CF-RAY', 'CF-Cache-Status', 'CF-Request-ID'],
        'cookies': ['__cfduid', '__cf_bm'],
        'indicators': ['cloudflare', 'Attention Required! | Cloudflare']
    },
    'AWS WAF': {
        'headers': ['X-AMZ-CF-ID', 'Via'],
        'cookies': [],
        'indicators': ['aws', 'amazon']
    },
    'ModSecurity': {
        'headers': ['ModSecurity', 'X-Mod-Security'],
        'cookies': [],
        'indicators': ['mod_security', 'ModSecurity']
    },
    'Imperva': {
        'headers': ['X-Iinfo', 'X-WAF-Event'],
        'cookies': ['visid_incap_', 'incap_ses_'],
        'indicators': ['incapsula', 'imperva']
    },
    'Akamai': {
        'headers': ['X-Akamai-Request-ID', 'X-True-Cache-Key'],
        'cookies': ['AKA_A2'],
        'indicators': ['akamai']
    },
    'F5 BIG-IP': {
        'headers': ['X-WA-Info', 'X-Cnection'],
        'cookies': ['BIGipServer', 'TS'],
        'indicators': ['bigip', 'f5']
    },
    'Sucuri': {
        'headers': ['X-Sucuri-ID', 'X-Sucuri-Cache'],
        'cookies': ['sucuri_', 'sucuri_cloudproxy_'],
        'indicators': ['sucuri', 'Access Denied - Sucuri Website Firewall']
    },
    'Wordfence': {
        'headers': [],
        'cookies': ['wfvt_', 'wordfence_'],
        'indicators': ['wordfence']
    },
    'Barracuda': {
        'headers': ['X-Barracuda'],
        'cookies': [],
        'indicators': ['barracuda']
    },
    'Fortinet': {
        'headers': ['X-WAF-Event'],
        'cookies': [],
        'indicators': ['fortinet', 'fortiwaf']
    }
}


# =============================================================================
# Environment Fingerprinter
# =============================================================================

class EnvironmentFingerprinter:
    """
    环境指纹识别器
    
    通过分析HTTP响应头、Cookie、页面内容等信息，
    自动识别目标服务器的技术栈环境。
    """
    
    def __init__(self):
        self.profile = EnvironmentProfile()
        self.confidence_scores = {
            'server': 0.0,
            'os': 0.0,
            'language': 0.0,
            'waf': 0.0
        }
    
    def fingerprint(self, url: str, response: Any) -> EnvironmentProfile:
        """
        执行环境指纹识别
        
        Args:
            url: 目标URL
            response: HTTP响应对象（需要有 headers, text, status_code 属性）
        
        Returns:
            EnvironmentProfile: 环境配置文件
        """
        self.profile = EnvironmentProfile()
        self.confidence_scores = {
            'server': 0.0,
            'os': 0.0,
            'language': 0.0,
            'waf': 0.0
        }
        
        # 提取响应头
        headers = self._extract_headers(response)
        self.profile.raw_headers = headers
        
        # 1. 识别 Web 服务器
        self._detect_server(headers, response)
        
        # 2. 识别操作系统
        self._detect_os(headers, response)
        
        # 3. 识别后端语言
        self._detect_language(headers, response, url)
        
        # 4. 检测 WAF
        self._detect_waf(headers, response)
        
        # 5. 应用策略矩阵
        self._apply_strategy_matrix()
        
        # 计算总体置信度
        self.profile.fingerprint_confidence = self._calculate_confidence()
        
        return self.profile
    
    def _extract_headers(self, response: Any) -> Dict[str, str]:
        """提取响应头"""
        headers = {}
        
        if hasattr(response, 'headers'):
            if isinstance(response.headers, dict):
                headers = {k.lower(): v for k, v in response.headers.items()}
            elif hasattr(response.headers, 'items'):
                headers = {k.lower(): v for k, v in response.headers.items()}
        
        return headers
    
    def _detect_server(self, headers: Dict[str, str], response: Any) -> None:
        """检测 Web 服务器"""
        server_header = headers.get('server', '')
        powered_by = headers.get('x-powered-by', '')
        
        # 遍历服务器指纹
        for server_name, fingerprint in SERVER_FINGERPRINTS.items():
            for header_name in fingerprint['headers']:
                header_value = headers.get(header_name.lower(), '')
                if not header_value:
                    continue
                
                for pattern, pattern_type in fingerprint['patterns']:
                    match = re.search(pattern, header_value, re.IGNORECASE)
                    if match:
                        self.profile.server = server_name
                        if pattern_type == 'version' and match.groups():
                            self.profile.server_version = match.group(1)
                        self.confidence_scores['server'] = 0.9
                        return
        
        # 如果没有明确匹配，尝试推断
        if 'apache' in server_header.lower():
            self.profile.server = 'Apache'
            self.confidence_scores['server'] = 0.7
        elif 'nginx' in server_header.lower():
            self.profile.server = 'Nginx'
            self.confidence_scores['server'] = 0.7
        elif 'microsoft-iis' in server_header.lower():
            self.profile.server = 'IIS'
            self.confidence_scores['server'] = 0.8
        elif 'caddy' in server_header.lower():
            self.profile.server = 'Caddy'
            self.confidence_scores['server'] = 0.8
        elif 'lighttpd' in server_header.lower():
            self.profile.server = 'Lighttpd'
            self.confidence_scores['server'] = 0.8
        elif 'openresty' in server_header.lower():
            self.profile.server = 'OpenResty'
            self.confidence_scores['server'] = 0.8
    
    def _detect_os(self, headers: Dict[str, str], response: Any) -> None:
        """检测操作系统"""
        server_header = headers.get('server', '')
        
        # Windows 特征
        windows_indicators = [
            'win32', 'win64', 'windows', 'iis', 'microsoft'
        ]
        
        # Linux 特征
        linux_indicators = [
            'ubuntu', 'centos', 'debian', 'fedora', 'rhel', 'linux'
        ]
        
        server_lower = server_header.lower()
        
        # 检查 Windows
        for indicator in windows_indicators:
            if indicator in server_lower:
                self.profile.os = 'Windows'
                self.confidence_scores['os'] = 0.8
                return
        
        # 检查 Linux
        for indicator in linux_indicators:
            if indicator in server_lower:
                self.profile.os = 'Linux'
                self.confidence_scores['os'] = 0.8
                return
        
        # 根据服务器类型推断
        if self.profile.server == 'IIS':
            self.profile.os = 'Windows'
            self.confidence_scores['os'] = 0.9
        elif self.profile.server in ['Apache', 'Nginx', 'Lighttpd', 'Caddy', 'OpenResty']:
            # 这些服务器大多数运行在 Linux 上
            self.profile.os = 'Linux'
            self.confidence_scores['os'] = 0.6
    
    def _detect_language(self, headers: Dict[str, str], response: Any, url: str) -> None:
        """检测后端语言"""
        powered_by = headers.get('x-powered-by', '')
        asp_net_version = headers.get('x-aspnet-version', '')
        
        # ASP.NET 检测（优先级最高，因为最明确）
        if asp_net_version or 'asp.net' in powered_by.lower():
            self.profile.language = 'ASPX'
            self.confidence_scores['language'] = 0.95
            if asp_net_version:
                self.profile.lang_version = asp_net_version
            return
        
        # 遍历语言指纹
        for lang_name, fingerprint in LANGUAGE_FINGERPRINTS.items():
            # 检查 headers
            for header_name in fingerprint['headers']:
                header_value = headers.get(header_name.lower(), '')
                if not header_value:
                    continue
                
                for pattern, pattern_type in fingerprint['patterns']:
                    match = re.search(pattern, header_value, re.IGNORECASE)
                    if match:
                        self.profile.language = lang_name
                        if pattern_type == 'version' and match.groups():
                            self.profile.lang_version = match.group(1)
                        self.confidence_scores['language'] = 0.9
                        return
        
        # Cookie 检测
        cookies = headers.get('set-cookie', '')
        if 'PHPSESSID' in cookies:
            self.profile.language = 'PHP'
            self.confidence_scores['language'] = 0.85
        elif 'ASPSESSIONID' in cookies:
            self.profile.language = 'ASP'
            self.confidence_scores['language'] = 0.85
        elif 'ASP.NET_SessionId' in cookies:
            self.profile.language = 'ASPX'
            self.confidence_scores['language'] = 0.9
        elif 'JSESSIONID' in cookies:
            self.profile.language = 'JSP'
            self.confidence_scores['language'] = 0.85
        
        # URL 扩展名推断
        parsed_url = urlparse(url)
        path = parsed_url.path.lower()
        
        if path.endswith(('.php', '.php3', '.php4', '.php5', '.phtml')):
            if self.profile.language == 'Unknown':
                self.profile.language = 'PHP'
                self.confidence_scores['language'] = 0.7
        elif path.endswith(('.asp', '.asa', '.cer')):
            if self.profile.language == 'Unknown':
                self.profile.language = 'ASP'
                self.confidence_scores['language'] = 0.7
        elif path.endswith(('.aspx', '.ashx', '.asmx')):
            if self.profile.language == 'Unknown':
                self.profile.language = 'ASPX'
                self.confidence_scores['language'] = 0.8
        elif path.endswith(('.jsp', '.jspx')):
            if self.profile.language == 'Unknown':
                self.profile.language = 'JSP'
                self.confidence_scores['language'] = 0.8
    
    def _detect_waf(self, headers: Dict[str, str], response: Any) -> None:
        """检测 WAF"""
        response_text = ''
        if hasattr(response, 'text'):
            response_text = response.text
        elif hasattr(response, 'content'):
            try:
                response_text = response.content.decode('utf-8', errors='ignore')
            except:
                pass
        
        for waf_name, fingerprint in WAF_FINGERPRINTS.items():
            # 检查 headers
            for header in fingerprint['headers']:
                if header.lower() in headers:
                    self.profile.waf_detected = True
                    self.profile.waf_name = waf_name
                    self.confidence_scores['waf'] = 0.9
                    return
            
            # 检查 cookies
            cookies = headers.get('set-cookie', '')
            for cookie_pattern in fingerprint['cookies']:
                if cookie_pattern in cookies:
                    self.profile.waf_detected = True
                    self.profile.waf_name = waf_name
                    self.confidence_scores['waf'] = 0.85
                    return
            
            # 检查响应内容
            for indicator in fingerprint['indicators']:
                if indicator.lower() in response_text.lower():
                    self.profile.waf_detected = True
                    self.profile.waf_name = waf_name
                    self.confidence_scores['waf'] = 0.8
                    return
    
    def _apply_strategy_matrix(self) -> None:
        """应用策略矩阵"""
        # 构建环境键
        env_key = f"{self.profile.server}_{self.profile.os}"
        
        # 如果精确匹配不存在，尝试模糊匹配
        if env_key not in STRATEGY_MATRIX:
            # Tomcat 矩阵键为单键 Tomcat（与 OS 组合键并存）
            if self.profile.server == 'Tomcat' and 'Tomcat' in STRATEGY_MATRIX:
                env_key = 'Tomcat'
            elif self.profile.server == 'OpenResty':
                env_key = 'Nginx_Linux' if self.profile.os == 'Linux' else 'Nginx_Windows'
                if env_key not in STRATEGY_MATRIX:
                    env_key = 'Unknown_Linux' if self.profile.os != 'Windows' else 'Unknown_Windows'
            elif self.profile.os == 'Windows':
                env_key = 'Unknown_Windows'
            elif self.profile.os == 'Linux':
                env_key = 'Unknown_Linux'
            else:
                env_key = 'Unknown_Linux'  # 默认
        
        if env_key in STRATEGY_MATRIX:
            matrix = STRATEGY_MATRIX[env_key]
            self.profile.enabled_strategies = matrix.get('enable', [])
            self.profile.disabled_strategies = matrix.get('disable', [])
            self.profile.suggested_payloads = matrix.get('priority', [])
        else:
            # 默认策略
            self.profile.enabled_strategies = [
                'php', 'jsp', 'null_byte', 'double_extension',
                'case_bypass', 'special_chars'
            ]
            self.profile.disabled_strategies = []
            self.profile.suggested_payloads = ['php', 'null_byte']
    
    def _calculate_confidence(self) -> float:
        """计算总体置信度"""
        weights = {
            'server': 0.3,
            'os': 0.2,
            'language': 0.3,
            'waf': 0.2
        }
        
        total_confidence = 0.0
        for key, weight in weights.items():
            total_confidence += self.confidence_scores.get(key, 0.0) * weight
        
        return round(total_confidence, 2)
    
    def get_fingerprint_summary(self) -> str:
        """获取指纹摘要"""
        lines = [
            f"服务器: {self.profile.server} {self.profile.server_version or ''}",
            f"操作系统: {self.profile.os}",
            f"后端语言: {self.profile.language} {self.profile.lang_version or ''}",
        ]
        
        if self.profile.waf_detected:
            lines.append(f"WAF: {self.profile.waf_name or 'Unknown'} [检测到]")
        
        lines.append(f"置信度: {self.profile.fingerprint_confidence:.0%}")
        lines.append(f"启用策略: {len(self.profile.enabled_strategies)} 个")
        lines.append(f"禁用策略: {len(self.profile.disabled_strategies)} 个")
        
        return "\n".join(lines)


# =============================================================================
# Helper Functions
# =============================================================================

def fingerprint_environment(url: str, response: Any) -> EnvironmentProfile:
    """
    便捷函数：执行环境指纹识别
    
    Args:
        url: 目标URL
        response: HTTP响应对象
    
    Returns:
        EnvironmentProfile: 环境配置文件
    """
    fingerprinter = EnvironmentFingerprinter()
    return fingerprinter.fingerprint(url, response)


def get_recommended_payloads(profile: EnvironmentProfile) -> List[str]:
    """
    根据环境配置获取推荐的 payload 类型
    
    Args:
        profile: 环境配置文件
    
    Returns:
        List[str]: 推荐的 payload 类型列表
    """
    return profile.suggested_payloads if profile.suggested_payloads else profile.enabled_strategies[:5]


def infer_payload_strategies(payload: Dict[str, Any]) -> Set[str]:
    """从异步扫描用的 payload 字典推断策略标签（与 STRATEGY_MATRIX 词汇对齐）"""
    tags: Set[str] = set()
    typ = (payload.get("type") or "").lower()
    ext = (payload.get("ext") or "").lower()
    fn = (payload.get("filename") or "").lower()

    php_exts = ("php", "php3", "php4", "php5", "phtml", "pht", "phar", "phps")
    if typ.startswith("php") or ext in php_exts:
        tags.add("php")
        if ext in php_exts:
            tags.add(ext)
    if "jsp" in typ or ext == "jsp":
        tags.add("jsp")
    if "aspx" in typ or ext in ("aspx", "ashx", "asmx", "asax"):
        tags.add("aspx")
    if typ.startswith("asp_variant") or ext in ("asp", "asa", "cer"):
        tags.update({"asp", "aspx"})
    if "double_ext" in typ or "double" in typ:
        tags.add("double_extension")
    if "null_byte" in typ:
        tags.add("null_byte")
    if "trailing_dot" in typ or typ == "trailing_dot":
        tags.add("windows_trailing_dot")
    if "alternate_data" in typ or "$data" in fn:
        tags.update({"ntfs_ads", "stream_data", "alternate_data_stream"})
    if "semicolon" in typ:
        tags.add("iis_semicolon")
    if "htaccess" in typ:
        tags.add("htaccess")
    if "polyglot" in typ or "magic_" in typ:
        tags.add("php")
    if "xss_svg" in typ or ext == "svg":
        tags.add("special_chars")
    if "eicar" in typ:
        tags.add("special_chars")
    if "file_include" in typ:
        tags.add("php")

    if not tags:
        tags.add("special_chars")
    return tags


def filter_payloads_by_profile(
    payloads: List[Dict[str, Any]],
    profile: EnvironmentProfile,
    max_limit: int,
    apply_disable: bool = True,
    prioritize: bool = True,
) -> List[Dict[str, Any]]:
    """
    按环境指纹过滤（去掉 disabled 策略）并按 suggested 优先级排序后截断。
    若过滤后过少则自动回退为仅排序、不过滤禁用策略。
    """
    if not payloads:
        return []

    disabled = {s.lower() for s in (profile.disabled_strategies or [])}
    priority = profile.suggested_payloads or (profile.enabled_strategies or [])[:12]
    priority_rank = {p.lower(): i for i, p in enumerate(priority)}

    def build(use_disable: bool) -> List[Dict[str, Any]]:
        def rank_for(p: Dict[str, Any]) -> Optional[Tuple[int, str]]:
            tags = {t.lower() for t in infer_payload_strategies(p)}
            if use_disable and tags & disabled:
                return None
            ranks = [priority_rank[t] for t in tags if t in priority_rank]
            primary = min(ranks) if ranks else 500
            return (primary, p.get("type") or "")

        scored: List[Tuple[Tuple[int, str], Dict[str, Any]]] = []
        for p in payloads:
            r = rank_for(p)
            if r is None:
                continue
            scored.append((r, p))

        if prioritize:
            scored.sort(key=lambda x: x[0])
        return [p for _, p in scored[:max_limit]]

    out = build(apply_disable)
    min_keep = max(24, max_limit // 5)
    if apply_disable and len(out) < min_keep:
        out = build(False)
    return out[:max_limit]


# =============================================================================
# Test
# =============================================================================

if __name__ == "__main__":
    # 模拟测试
    class MockResponse:
        def __init__(self):
            self.headers = {
                'Server': 'nginx/1.18.0',
                'X-Powered-By': 'PHP/7.4.3',
                'Content-Type': 'text/html; charset=UTF-8'
            }
            self.text = '<html><body>Test</body></html>'
            self.status_code = 200
    
    mock_response = MockResponse()
    fingerprinter = EnvironmentFingerprinter()
    profile = fingerprinter.fingerprint("http://example.com/upload.php", mock_response)
    
    print("=" * 50)
    print("环境指纹识别结果")
    print("=" * 50)
    print(fingerprinter.get_fingerprint_summary())
    print("=" * 50)
    print(f"\n完整配置: {json.dumps(profile.to_dict(), indent=2, ensure_ascii=False)}")
