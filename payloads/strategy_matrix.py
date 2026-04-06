#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Strategy Matrix - 环境-策略映射矩阵

根据环境指纹自动选择和过滤 payload 策略
实现智能 payload 推荐和优先级排序

Author: UploadRanger
Version: 2.0.0
"""

import json
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum


# =============================================================================
# Enums
# =============================================================================

class StrategyPriority(Enum):
    """策略优先级"""
    CRITICAL = 5   # 针对该环境最有效的策略
    HIGH = 4       # 高成功率策略
    MEDIUM = 3     # 中等成功率
    LOW = 2        # 低成功率但值得尝试
    MINIMAL = 1    # 边缘情况


class StrategyCategory(Enum):
    """策略类别"""
    EXTENSION_BYPASS = "extension_bypass"      # 扩展名绕过
    CONTENT_TYPE_BYPASS = "content_type"       # Content-Type绕过
    FILENAME_MANIPULATION = "filename"         # 文件名操作
    PATH_TRAVERSAL = "path_traversal"          # 路径遍历
    NULL_BYTE = "null_byte"                    # 空字节截断
    PARSER_DIFFERENCE = "parser"               # 解析器差异
    CONFIG_INJECTION = "config"                # 配置注入
    RACE_CONDITION = "race_condition"          # 条件竞争
    POLYGLOT = "polyglot"                      # 多格式文件
    DOUBLE_ENCODING = "encoding"               # 双重编码


# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class Strategy:
    """策略定义"""
    id: str
    name: str
    description: str
    category: StrategyCategory
    priority: StrategyPriority
    
    # 适用环境
    target_servers: List[str] = field(default_factory=list)  # Apache/Nginx/IIS/etc
    target_os: List[str] = field(default_factory=list)       # Linux/Windows
    target_languages: List[str] = field(default_factory=list) # PHP/ASP/JSP/etc
    
    # 排除环境
    exclude_servers: List[str] = field(default_factory=list)
    exclude_os: List[str] = field(default_factory=list)
    exclude_languages: List[str] = field(default_factory=list)
    
    # 技术要求
    requires: List[str] = field(default_factory=list)  # 需要的条件
    
    # 元数据
    success_rate: float = 0.0  # 历史成功率 0.0-1.0
    severity: str = "Medium"   # Critical/High/Medium/Low
    cve_ids: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    
    def is_applicable(self, server: str, os: str, language: str) -> bool:
        """检查策略是否适用于当前环境"""
        # 检查排除条件
        if self.exclude_servers and server in self.exclude_servers:
            return False
        if self.exclude_os and os in self.exclude_os:
            return False
        if self.exclude_languages and language in self.exclude_languages:
            return False
        
        # 检查适用条件（如果没有指定则默认适用）
        if self.target_servers and server not in self.target_servers:
            return False
        if self.target_os and os not in self.target_os:
            return False
        if self.target_languages and language not in self.target_languages:
            return False
        
        return True
    
    def to_dict(self) -> Dict:
        """转换为字典"""
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'category': self.category.value,
            'priority': self.priority.name,
            'target_servers': self.target_servers,
            'target_os': self.target_os,
            'target_languages': self.target_languages,
            'success_rate': self.success_rate,
            'severity': self.severity
        }


@dataclass
class StrategyResult:
    """策略选择结果"""
    enabled_strategies: List[Strategy] = field(default_factory=list)
    disabled_strategies: List[Strategy] = field(default_factory=list)
    priority_order: List[str] = field(default_factory=list)
    estimated_payload_count: int = 0
    estimated_time: float = 0.0  # 预估扫描时间（秒）
    risk_assessment: str = "Medium"  # Low/Medium/High
    recommendations: List[str] = field(default_factory=list)


# =============================================================================
# Strategy Definitions
# =============================================================================

# 完整的策略定义库
STRATEGY_DEFINITIONS = {
    # IIS + Windows 专用策略
    'iis_semicolon': Strategy(
        id='iis_semicolon',
        name='IIS 分号截断',
        description='利用 IIS 解析漏洞，shell.asp;.jpg 会被当作 ASP 执行',
        category=StrategyCategory.EXTENSION_BYPASS,
        priority=StrategyPriority.CRITICAL,
        target_servers=['IIS'],
        target_os=['Windows'],
        target_languages=['ASP', 'ASPX'],
        success_rate=0.85,
        severity='Critical',
        references=['https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/README.md']
    ),
    
    'ntfs_ads': Strategy(
        id='ntfs_ads',
        name='NTFS 备用数据流',
        description='利用 NTFS ADS 特性，shell.php::$DATA 绕过扩展名检查',
        category=StrategyCategory.EXTENSION_BYPASS,
        priority=StrategyPriority.CRITICAL,
        target_servers=['IIS', 'Apache'],
        target_os=['Windows'],
        target_languages=['PHP', 'ASP', 'ASPX'],
        success_rate=0.80,
        severity='Critical',
        references=['https://docs.microsoft.com/en-us/windows/win32/fileio/file-streams']
    ),
    
    'windows_trailing_dot': Strategy(
        id='windows_trailing_dot',
        name='Windows 尾部点号',
        description='Windows 会自动去除文件名尾部的点和空格',
        category=StrategyCategory.FILENAME_MANIPULATION,
        priority=StrategyPriority.HIGH,
        target_os=['Windows'],
        target_languages=['PHP', 'ASP', 'ASPX'],
        success_rate=0.70,
        severity='High'
    ),
    
    'windows_reserved_names': Strategy(
        id='windows_reserved_names',
        name='Windows 保留名称',
        description='利用 Windows 保留名称如 CON, PRN, AUX 等',
        category=StrategyCategory.FILENAME_MANIPULATION,
        priority=StrategyPriority.MEDIUM,
        target_os=['Windows'],
        success_rate=0.30,
        severity='Medium'
    ),
    
    'short_name': Strategy(
        id='short_name',
        name='Windows 短文件名',
        description='利用 Windows 8.3 短文件名格式',
        category=StrategyCategory.FILENAME_MANIPULATION,
        priority=StrategyPriority.LOW,
        target_os=['Windows'],
        success_rate=0.20,
        severity='Low'
    ),
    
    # Apache + Linux 专用策略
    'htaccess': Strategy(
        id='htaccess',
        name='Apache .htaccess 注入',
        description='上传 .htaccess 文件修改 Apache 配置，将图片解析为 PHP',
        category=StrategyCategory.CONFIG_INJECTION,
        priority=StrategyPriority.CRITICAL,
        target_servers=['Apache'],
        target_os=['Linux', 'Windows'],
        target_languages=['PHP'],
        requires=['writable_htaccess_directory'],
        success_rate=0.90,
        severity='Critical',
        references=['https://httpd.apache.org/docs/2.4/howto/htaccess.html']
    ),
    
    'apache_multiext': Strategy(
        id='apache_multiext',
        name='Apache 多扩展名解析',
        description='利用 Apache 从右向左解析扩展名的特性',
        category=StrategyCategory.EXTENSION_BYPASS,
        priority=StrategyPriority.HIGH,
        target_servers=['Apache'],
        target_languages=['PHP'],
        success_rate=0.75,
        severity='High'
    ),
    
    'user_ini': Strategy(
        id='user_ini',
        name='PHP .user.ini 注入',
        description='上传 .user.ini 文件配置 PHP 自动包含',
        category=StrategyCategory.CONFIG_INJECTION,
        priority=StrategyPriority.HIGH,
        target_languages=['PHP'],
        requires=['php_cgi_mode', 'writable_ini_directory'],
        success_rate=0.70,
        severity='High',
        references=['https://www.php.net/manual/en/configuration.file.per-user.php']
    ),
    
    # Nginx 专用策略
    'nginx_path_confusion': Strategy(
        id='nginx_path_confusion',
        name='Nginx 路径解析漏洞',
        description='Nginx + PHP-FPM 路径解析漏洞，/shell.jpg%00.php',
        category=StrategyCategory.PARSER_DIFFERENCE,
        priority=StrategyPriority.CRITICAL,
        target_servers=['Nginx'],
        target_languages=['PHP'],
        requires=['php_fpm', 'cgi.fix_pathinfo=1'],
        success_rate=0.80,
        severity='Critical',
        references=['https://bugs.php.net/bug.php?id=50852']
    ),
    
    'php_fpm': Strategy(
        id='php_fpm',
        name='PHP-FPM 绕过',
        description='利用 PHP-FPM 的 path_info 处理特性',
        category=StrategyCategory.PARSER_DIFFERENCE,
        priority=StrategyPriority.HIGH,
        target_servers=['Nginx'],
        target_languages=['PHP'],
        requires=['php_fpm'],
        success_rate=0.65,
        severity='High'
    ),
    
    'cgi_path_info': Strategy(
        id='cgi_path_info',
        name='CGI Path Info 漏洞',
        description='利用 CGI 模式的 PATH_INFO 处理',
        category=StrategyCategory.PARSER_DIFFERENCE,
        priority=StrategyPriority.MEDIUM,
        target_servers=['Nginx', 'Lighttpd'],
        target_languages=['PHP'],
        success_rate=0.50,
        severity='Medium'
    ),
    
    # 通用策略（适用于大多数环境）
    'null_byte': Strategy(
        id='null_byte',
        name='空字节截断',
        description='使用 %00 或 0x00 截断文件名',
        category=StrategyCategory.NULL_BYTE,
        priority=StrategyPriority.CRITICAL,
        target_languages=['PHP', 'ASP', 'JSP', 'Python'],
        exclude_languages=['ASPX'],  # .NET 不受空字节影响
        success_rate=0.60,
        severity='Critical',
        references=['https://owasp.org/www-community/attacks/Embedding_Null_Code']
    ),
    
    'double_extension': Strategy(
        id='double_extension',
        name='双重扩展名',
        description='shell.php.jpg 双重扩展名绕过',
        category=StrategyCategory.EXTENSION_BYPASS,
        priority=StrategyPriority.HIGH,
        success_rate=0.55,
        severity='High'
    ),
    
    'case_bypass': Strategy(
        id='case_bypass',
        name='大小写绕过',
        description='使用大小写变体如 shell.PhP',
        category=StrategyCategory.EXTENSION_BYPASS,
        priority=StrategyPriority.MEDIUM,
        target_os=['Windows'],  # Windows 不区分大小写
        success_rate=0.45,
        severity='Medium'
    ),
    
    'path_traversal': Strategy(
        id='path_traversal',
        name='路径遍历',
        description='使用 ../ 遍历到可写目录',
        category=StrategyCategory.PATH_TRAVERSAL,
        priority=StrategyPriority.HIGH,
        success_rate=0.40,
        severity='High'
    ),
    
    'special_chars': Strategy(
        id='special_chars',
        name='特殊字符注入',
        description='使用特殊字符如 :, ;, <, >, ?, * 等',
        category=StrategyCategory.FILENAME_MANIPULATION,
        priority=StrategyPriority.MEDIUM,
        success_rate=0.35,
        severity='Medium'
    ),
    
    'mime_bypass': Strategy(
        id='mime_bypass',
        name='MIME 类型伪造',
        description='伪造 Content-Type 头绕过 MIME 检查',
        category=StrategyCategory.CONTENT_TYPE_BYPASS,
        priority=StrategyPriority.MEDIUM,
        success_rate=0.50,
        severity='Medium'
    ),
    
    'double_url_encode': Strategy(
        id='double_url_encode',
        name='双重 URL 编码',
        description='对特殊字符进行双重 URL 编码',
        category=StrategyCategory.DOUBLE_ENCODING,
        priority=StrategyPriority.LOW,
        success_rate=0.25,
        severity='Low'
    ),
    
    'content_disposition_pollution': Strategy(
        id='content_disposition_pollution',
        name='Content-Disposition 污染',
        description='多个 filename 参数、未闭合引号等',
        category=StrategyCategory.PARSER_DIFFERENCE,
        priority=StrategyPriority.HIGH,
        success_rate=0.45,
        severity='High'
    ),
    
    'race_condition': Strategy(
        id='race_condition',
        name='条件竞争',
        description='利用上传验证和执行的时间差',
        category=StrategyCategory.RACE_CONDITION,
        priority=StrategyPriority.MEDIUM,
        success_rate=0.30,
        severity='High'
    ),
    
    # Polyglot 策略
    'gif_polyglot': Strategy(
        id='gif_polyglot',
        name='GIF Polyglot',
        description='创建既是 GIF 又是 PHP 的文件',
        category=StrategyCategory.POLYGLOT,
        priority=StrategyPriority.HIGH,
        success_rate=0.70,
        severity='High'
    ),
    
    'png_polyglot': Strategy(
        id='png_polyglot',
        name='PNG Polyglot',
        description='创建既是 PNG 又是 PHP 的文件',
        category=StrategyCategory.POLYGLOT,
        priority=StrategyPriority.HIGH,
        success_rate=0.70,
        severity='High'
    ),
    
    'jpg_polyglot': Strategy(
        id='jpg_polyglot',
        name='JPG Polyglot',
        description='创建既是 JPG 又是 PHP 的文件',
        category=StrategyCategory.POLYGLOT,
        priority=StrategyPriority.HIGH,
        success_rate=0.65,
        severity='High'
    ),
    
    'svg_xss': Strategy(
        id='svg_xss',
        name='SVG XSS',
        description='SVG 文件包含 XSS payload',
        category=StrategyCategory.POLYGLOT,
        priority=StrategyPriority.MEDIUM,
        success_rate=0.60,
        severity='Medium'
    ),
    
    # 语言特定策略
    'php_wrapper': Strategy(
        id='php_wrapper',
        name='PHP 伪协议',
        description='使用 php://filter, phar:// 等协议',
        category=StrategyCategory.PARSER_DIFFERENCE,
        priority=StrategyPriority.MEDIUM,
        target_languages=['PHP'],
        success_rate=0.40,
        severity='High',
        references=['https://www.php.net/manual/en/wrappers.php.php']
    ),
    
    'jsp_wrapping': Strategy(
        id='jsp_wrapping',
        name='JSP 包装',
        description='利用 JSP 特性包装恶意代码',
        category=StrategyCategory.PARSER_DIFFERENCE,
        priority=StrategyPriority.HIGH,
        target_languages=['JSP'],
        success_rate=0.55,
        severity='High'
    ),
    
    'war_file': Strategy(
        id='war_file',
        name='WAR 文件部署',
        description='上传 WAR 文件部署 Web 应用',
        category=StrategyCategory.CONFIG_INJECTION,
        priority=StrategyPriority.CRITICAL,
        target_servers=['Tomcat'],
        target_languages=['JSP'],
        success_rate=0.80,
        severity='Critical'
    ),
}


# =============================================================================
# Strategy Matrix
# =============================================================================

class StrategyMatrix:
    """
    策略矩阵管理器
    
    根据环境指纹选择和排序策略
    """
    
    def __init__(self):
        self.strategies = STRATEGY_DEFINITIONS
        self.result = StrategyResult()
    
    def select_strategies(self, 
                         server: str, 
                         os: str, 
                         language: str,
                         waf_detected: bool = False) -> StrategyResult:
        """
        根据环境选择策略
        
        Args:
            server: 服务器类型 (Apache/Nginx/IIS/etc)
            os: 操作系统 (Linux/Windows)
            language: 后端语言 (PHP/ASP/JSP/etc)
            waf_detected: 是否检测到 WAF
        
        Returns:
            StrategyResult: 策略选择结果
        """
        self.result = StrategyResult()
        enabled = []
        disabled = []
        
        for strategy_id, strategy in self.strategies.items():
            if strategy.is_applicable(server, os, language):
                enabled.append(strategy)
            else:
                disabled.append(strategy)
        
        # 按优先级排序
        enabled.sort(key=lambda s: s.priority.value, reverse=True)
        
        # 如果检测到 WAF，调整策略
        if waf_detected:
            enabled = self._adjust_for_waf(enabled)
        
        self.result.enabled_strategies = enabled
        self.result.disabled_strategies = disabled
        self.result.priority_order = [s.id for s in enabled]
        
        # 估算 payload 数量
        self.result.estimated_payload_count = self._estimate_payload_count(enabled)
        
        # 生成建议
        self.result.recommendations = self._generate_recommendations(
            enabled, server, os, language, waf_detected
        )
        
        return self.result
    
    def _adjust_for_waf(self, strategies: List[Strategy]) -> List[Strategy]:
        """针对 WAF 调整策略顺序"""
        # WAF 环境下，优先使用更隐蔽的策略
        waf_friendly = []
        waf_unfriendly = []
        
        for strategy in strategies:
            # 这些策略在 WAF 环境下更容易被检测
            if strategy.category in [
                StrategyCategory.NULL_BYTE,
                StrategyCategory.PATH_TRAVERSAL
            ]:
                waf_unfriendly.append(strategy)
            else:
                waf_friendly.append(strategy)
        
        return waf_friendly + waf_unfriendly
    
    def _estimate_payload_count(self, strategies: List[Strategy]) -> int:
        """估算 payload 数量"""
        # 每个策略平均产生的 payload 数量
        avg_payloads_per_strategy = {
            StrategyCategory.EXTENSION_BYPASS: 15,
            StrategyCategory.CONTENT_TYPE_BYPASS: 8,
            StrategyCategory.FILENAME_MANIPULATION: 12,
            StrategyCategory.PATH_TRAVERSAL: 6,
            StrategyCategory.NULL_BYTE: 5,
            StrategyCategory.PARSER_DIFFERENCE: 10,
            StrategyCategory.CONFIG_INJECTION: 4,
            StrategyCategory.RACE_CONDITION: 3,
            StrategyCategory.POLYGLOT: 8,
            StrategyCategory.DOUBLE_ENCODING: 6
        }
        
        total = 0
        for strategy in strategies:
            avg = avg_payloads_per_strategy.get(strategy.category, 5)
            # 根据优先级调整
            if strategy.priority == StrategyPriority.CRITICAL:
                avg = int(avg * 1.5)
            elif strategy.priority == StrategyPriority.MINIMAL:
                avg = int(avg * 0.5)
            total += avg
        
        return total
    
    def _generate_recommendations(self, 
                                  strategies: List[Strategy],
                                  server: str, 
                                  os: str, 
                                  language: str,
                                  waf_detected: bool) -> List[str]:
        """生成建议"""
        recommendations = []
        
        # 环境特定建议
        if server == 'IIS' and os == 'Windows':
            recommendations.append("IIS + Windows 环境：优先尝试分号截断和 NTFS ADS 策略")
        elif server == 'Apache' and language == 'PHP':
            recommendations.append("Apache + PHP 环境：尝试 .htaccess 注入和 .user.ini 配置")
        elif server == 'Nginx' and language == 'PHP':
            recommendations.append("Nginx + PHP 环境：重点关注路径解析漏洞")
        
        # WAF 建议
        if waf_detected:
            recommendations.append("检测到 WAF：建议使用 Polyglot 和 MIME 伪造等隐蔽策略")
        
        # 高优先级策略建议
        critical = [s for s in strategies if s.priority == StrategyPriority.CRITICAL]
        if critical:
            recommendations.append(f"关键策略 ({len(critical)} 个): {', '.join([s.name for s in critical[:3]])}")
        
        return recommendations
    
    def get_strategy_by_id(self, strategy_id: str) -> Optional[Strategy]:
        """通过 ID 获取策略"""
        return self.strategies.get(strategy_id)
    
    def get_strategies_by_category(self, 
                                   category: StrategyCategory) -> List[Strategy]:
        """获取特定类别的策略"""
        return [s for s in self.strategies.values() if s.category == category]
    
    def filter_payloads_by_strategy(self, 
                                    payloads: List[Dict], 
                                    strategy_ids: List[str]) -> List[Dict]:
        """根据策略过滤 payload"""
        filtered = []
        for payload in payloads:
            # 检查 payload 是否匹配任何启用的策略
            payload_strategy = payload.get('strategy', '')
            if payload_strategy in strategy_ids:
                filtered.append(payload)
        return filtered


# =============================================================================
# Helper Functions
# =============================================================================

def get_strategies_for_environment(server: str, 
                                    os: str, 
                                    language: str,
                                    waf_detected: bool = False) -> StrategyResult:
    """
    便捷函数：获取环境对应的策略
    
    Args:
        server: 服务器类型
        os: 操作系统
        language: 后端语言
        waf_detected: 是否检测到 WAF
    
    Returns:
        StrategyResult: 策略选择结果
    """
    matrix = StrategyMatrix()
    return matrix.select_strategies(server, os, language, waf_detected)


def should_enable_strategy(strategy_id: str, 
                           server: str, 
                           os: str, 
                           language: str) -> bool:
    """
    检查策略是否应该启用
    
    Args:
        strategy_id: 策略 ID
        server: 服务器类型
        os: 操作系统
        language: 后端语言
    
    Returns:
        bool: 是否应该启用
    """
    strategy = STRATEGY_DEFINITIONS.get(strategy_id)
    if not strategy:
        return False
    return strategy.is_applicable(server, os, language)


# =============================================================================
# Test
# =============================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("策略矩阵测试")
    print("=" * 60)
    
    # 测试不同环境
    test_cases = [
        ('Apache', 'Linux', 'PHP', False),
        ('Nginx', 'Linux', 'PHP', True),
        ('IIS', 'Windows', 'ASPX', False),
        ('Tomcat', 'Linux', 'JSP', False),
    ]
    
    matrix = StrategyMatrix()
    
    for server, os, lang, waf in test_cases:
        print(f"\n环境: {server} + {os} + {lang} (WAF: {waf})")
        print("-" * 40)
        
        result = matrix.select_strategies(server, os, lang, waf)
        
        print(f"启用策略: {len(result.enabled_strategies)} 个")
        print(f"禁用策略: {len(result.disabled_strategies)} 个")
        print(f"预估 Payload: {result.estimated_payload_count} 个")
        
        print("\n优先级排序 (前5):")
        for i, strategy in enumerate(result.enabled_strategies[:5], 1):
            print(f"  {i}. [{strategy.priority.name}] {strategy.name}")
        
        if result.recommendations:
            print("\n建议:")
            for rec in result.recommendations:
                print(f"  • {rec}")
