#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
UploadRanger 核心包（应用版本见 config.VERSION，当前 1.1.0）- 统一导出

提供对所有核心组件的统一访问：
- RawHTTPClient: 字节级HTTP控制
- SmartAnalyzer: 智能响应分析
- FilenameEncoder: 文件名编码器
- EnvironmentFingerprinter: 环境指纹识别

Author: bae
"""

from .raw_http_client import (
    RawHTTPClient,
    RawHTTPResponse,
    MultipartPart,
    FilenameEncoder,
    RawHTTPBuilder,
    create_upload_request
)

from .smart_analyzer import (
    SmartResponseAnalyzer,
    AnalysisResult,
    ScoringRule
)

from .fingerprinter import (
    EnvironmentFingerprinter,
    EnvironmentProfile,
    fingerprint_environment,
    get_recommended_payloads,
    STRATEGY_MATRIX
)

from .oob_verifier import (
    OOBVerifier,
    create_verifier,
    PLATFORM_INTERACTSH,
    PLATFORM_CEYE,
    PLATFORM_NONE,
)

# 版本信息
__version__ = "1.1.0"

__all__ = [
    # HTTP客户端
    'RawHTTPClient',
    'RawHTTPResponse', 
    'MultipartPart',
    'FilenameEncoder',
    'RawHTTPBuilder',
    'create_upload_request',
    
    # 分析器
    'SmartResponseAnalyzer',
    'AnalysisResult',
    'ScoringRule',
    
    # 指纹识别
    'EnvironmentFingerprinter',
    'EnvironmentProfile',
    'fingerprint_environment',
    'get_recommended_payloads',
    'STRATEGY_MATRIX',

    # OOB 带外验证
    'OOBVerifier',
    'create_verifier',
    'PLATFORM_INTERACTSH',
    'PLATFORM_CEYE',
    'PLATFORM_NONE',
]
