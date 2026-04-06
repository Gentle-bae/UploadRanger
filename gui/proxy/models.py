#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""代理数据模型 - ProxySignals, InterceptedFlow"""

import time
from PySide6.QtCore import Signal, QObject

class ProxySignals(QObject):
    """代理信号类 - 用于跨线程通信"""
    request_intercepted = Signal(object)  # 请求被拦截
    response_received = Signal(object, object)  # 收到响应
    request_logged = Signal(object)  # 请求被记录
    status_changed = Signal(str)  # 状态改变


class InterceptedFlow:
    """被拦截的流量对象"""
    def __init__(self, flow_id, method, url, headers, content, is_https=False):
        self.id = flow_id
        self.method = method
        self.url = url
        self.host = headers.get('Host', '')
        self.headers = headers
        self.content = content
        self.is_https = is_https
        self.timestamp = time.strftime("%H:%M:%S")
        self.status_code = '-'
        self.response_headers = {}
        self.response_content = b''
        self.intercepted = True
        self.released = False
        self.dropped = False
        self.modified = False
        self._event = None  # asyncio.Event
        self._flow = None  # mitmproxy flow
    
    def set_event(self, event):
        """设置异步事件"""
        self._event = event
    
    def set_flow(self, flow):
        """设置 mitmproxy flow"""
        self._flow = flow
    
    def to_dict(self):
        """转换为字典格式"""
        return {
            'method': self.method,
            'url': self.url,
            'host': self.host,
            'request_headers': '\n'.join([f"{k}: {v}" for k, v in self.headers.items()]),
            'request_body': self.content.decode('utf-8', errors='ignore') if self.content else ''
        }


