#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
UploadRanger - 文件上传漏洞测试工具
作者: bae
版本: v1.0.3
"""

import sys
import os
import logging

# 添加当前目录到路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Reduce noisy Qt/asyncio logs.
os.environ.setdefault("QT_LOGGING_RULES", "qt.qpa.fonts=false;qt.webenginecontext=false")
logging.getLogger("asyncio").setLevel(logging.CRITICAL)

# Linux runtime guards to avoid common Qt crashes (Wayland/WebEngine).
if sys.platform.startswith("linux"):
    os.environ.setdefault("QT_QPA_PLATFORM", "xcb")
    os.environ.setdefault("QTWEBENGINE_DISABLE_SANDBOX", "1")
    os.environ.setdefault("QTWEBENGINE_CHROMIUM_FLAGS", "--disable-gpu --disable-software-rasterizer")

from gui.main_window import run_gui

if __name__ == "__main__":
    run_gui()
