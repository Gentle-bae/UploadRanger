#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
gui/proxy 子包 - 代理模块拆分后的各组件

拆分前：gui/proxy_widget.py（2052行单文件）
拆分后：
  models.py       - ProxySignals, InterceptedFlow 数据模型
  addon.py        - UploadRangerAddon（mitmproxy addon）
  proxy_thread.py - ProxyThread（mitmproxy 运行线程）
  history_tab.py  - ProxyHistoryTab（流量历史面板，~720行 → 独立文件）
  intercept_tab.py- ProxyInterceptTab（拦截面板，~470行 → 独立文件）

外部代码仍可通过 gui.proxy_widget 导入 ProxyWidget（向后兼容）。
"""

from .models import ProxySignals, InterceptedFlow
from .addon import UploadRangerAddon
from .proxy_thread import ProxyThread
from .history_tab import ProxyHistoryTab
from .intercept_tab import ProxyInterceptTab

__all__ = [
    'ProxySignals',
    'InterceptedFlow',
    'UploadRangerAddon',
    'ProxyThread',
    'ProxyHistoryTab',
    'ProxyInterceptTab',
]
