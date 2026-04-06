#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
UploadRanger 配置文件
版本: 1.1.0
作者: bae
"""

# 版本信息
VERSION = "1.1.0"
AUTHOR = "bae"
APP_NAME = "UploadRanger"
APP_DESCRIPTION = "文件上传漏洞测试工具"

# 默认配置
DEFAULT_TIMEOUT = 30
DEFAULT_THREADS = 10
DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

# 扫描配置 v2.0
SCAN_CONFIG = {
    'max_payloads': 1200,  # 最大payload数量（提升到1200）
    'max_file_size': 10 * 1024 * 1024,  # 最大文件大小 10MB
    'allowed_extensions': [
        'php', 'php3', 'php4', 'php5', 'pht', 'phtml', 'phps',
        'asp', 'aspx', 'ascx', 'ashx', 'asmx', 'cer', 'asa',
        'jsp', 'jspx', 'jsw', 'jsv', 'jspf', 'war',
        'py', 'rb', 'pl', 'cgi', 'sh', 'bat', 'cmd',
        'html', 'htm', 'shtml', 'xml', 'svg', 'swf',
        'jpg', 'jpeg', 'png', 'gif', 'bmp', 'ico', 'webp',
        'txt', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',
        'zip', 'rar', 'tar', 'gz', 'bz2', '7z',
    ],
    'dangerous_extensions': [
        'php', 'php3', 'php4', 'php5', 'pht', 'phtml', 'phps', 'phar',
        'asp', 'aspx', 'ascx', 'ashx', 'asmx', 'cer', 'asa', 'asax',
        'jsp', 'jspx', 'jsw', 'jsv', 'jspf', 'war', 'do', 'action',
        'py', 'pyc', 'pyo', 'rb', 'rbw', 'pl', 'pm', 'cgi',
        'sh', 'bash', 'bat', 'cmd', 'ps1', 'vbs', 'js', 'jse',
    ],
    'image_extensions': [
        'jpg', 'jpeg', 'png', 'gif', 'bmp', 'ico', 'webp', 'svg'
    ],
    'document_extensions': [
        'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'txt'
    ],
}

# 成功关键词
SUCCESS_KEYWORDS = [
    "uploaded", "success", "completed", "saved", "上传成功", "成功",
    "upload complete", "file saved", "done", "ok", "完成", "已上传",
    "file uploaded", "upload successful", "上传完成"
]

# 失败关键词
FAILURE_KEYWORDS = [
    "error", "failed", "invalid", "blocked", "forbidden", "not allowed",
    "上传失败", "错误", "不允许", "无效", "拒绝", "失败",
    "file type not allowed", "extension not allowed", "invalid file",
    "upload error", "上传错误"
]

# 路径泄露模式
PATH_PATTERNS = [
    r'["\']([^"\']*uploads?/[^"\']*{filename})["\']',
    r'["\']([^"\']*files?/[^"\']*{filename})["\']',
    r'["\']([^"\']*images?/[^"\']*{filename})["\']',
    r'href=["\']?([^"\'>\s]*{filename})["\']?',
    r'src=["\']?([^"\'>\s]*{filename})["\']?',
    r'path["\']?\s*[:=]\s*["\']?([^"\'>\s]*{filename})["\']?',
    r'location["\']?\s*[:=]\s*["\']?([^"\'>\s]*{filename})["\']?',
    r'url["\']?\s*[:=]\s*["\']?([^"\'>\s]*{filename})["\']?',
]

# 代理设置
PROXY_SETTINGS = {
    'http': 'http://127.0.0.1:8080',
    'https': 'http://127.0.0.1:8080',
}

# 请求头
DEFAULT_HEADERS = {
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
    'Accept-Encoding': 'gzip, deflate',
    'Connection': 'keep-alive',
    'Upgrade-Insecure-Requests': '1',
}

# 日志配置
LOG_CONFIG = {
    'level': 'INFO',
    'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    'file': 'uploadranger.log',
}

# 报告配置
REPORT_CONFIG = {
    'output_dir': 'reports',
    'formats': ['html', 'json', 'txt'],
}
