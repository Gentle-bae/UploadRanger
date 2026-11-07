#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Core 模块 - UploadRanger核心功能
"""

from .async_scanner import AsyncScanner
from .async_http_client import AsyncHTTPClient
from .fingerprinter import EnvironmentFingerprinter, EnvironmentProfile

try:
    from .auto_verifier import WebShellVerifier, UploadPathExtractor
    VERIFIER_AVAILABLE = True
except ImportError:
    VERIFIER_AVAILABLE = False

try:
    from .oob_verifier import OOBVerifier
    OOB_AVAILABLE = True
except ImportError:
    OOB_AVAILABLE = False

__all__ = [
    'AsyncScanner',
    'AsyncHTTPClient',
    'EnvironmentFingerprinter',
    'EnvironmentProfile',
]

if VERIFIER_AVAILABLE:
    __all__.extend(['WebShellVerifier', 'UploadPathExtractor'])

if OOB_AVAILABLE:
    __all__.append('OOBVerifier')
