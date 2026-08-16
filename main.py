#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
UploadRanger - 文件上传漏洞测试工具
作者: bae
版本: v1.2.0
"""

import sys
import os
import logging
import argparse

if sys.platform.startswith("win"):
    try:
        import ctypes
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("Gentle-bae.UploadRanger.1.2.0")
    except Exception:
        pass

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

def _parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mcp-server", action="store_true")
    parser.add_argument("--transport", choices=("stdio", "sse", "streamable-http"), default="stdio")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=4554)
    return parser.parse_args()

def main():
    args = _parse_args()
    if args.mcp_server:
        from core.mcp.server import create_server
        server = create_server()
        if args.transport != "stdio":
            server.settings.host = args.host
            server.settings.port = args.port
        server.run(transport=args.transport)
        return
    from gui.main_window import run_gui
    run_gui()

if __name__ == "__main__":
    main()
