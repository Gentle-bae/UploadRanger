#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""mitmproxy Addon - UploadRangerAddon"""

import asyncio

try:
    from mitmproxy import http
    MITMPROXY_AVAILABLE = True
except ImportError:
    MITMPROXY_AVAILABLE = False

from .models import ProxySignals, InterceptedFlow

class UploadRangerAddon:
    """mitmproxy 插件 - 处理流量拦截"""
    
    def __init__(self, signals: ProxySignals, intercept_enabled: bool = True):
        self.signals = signals
        self.intercept_enabled = intercept_enabled
        self.waiting_flows: Dict[str, tuple] = {}  # {flow_id: (flow, event, intercepted_flow)}
        self.flow_counter = 0
        self._pending_tasks: list = []  # 【新增】跟踪所有待处理任务
    
    def set_intercept(self, enabled: bool):
        """设置是否拦截"""
        self.intercept_enabled = enabled
    
    def request(self, flow):
        """处理请求 - 修复：使用flow.intercept()非阻塞拦截，优化本地请求处理"""
        self.flow_counter += 1
        flow_id = str(self.flow_counter)
        
        # 【优化】确保URL正确，处理本地请求
        url = flow.request.url
        # 如果是本地请求，确保URL格式正确
        if flow.request.host in ['127.0.0.1', 'localhost', '::1']:
            # 本地请求正常处理
            pass
        
        # 创建拦截对象
        intercepted = InterceptedFlow(
            flow_id=flow_id,
            method=flow.request.method,
            url=url,
            headers=dict(flow.request.headers),
            content=flow.request.content if flow.request.content else b''
        )
        intercepted.set_flow(flow)
        
        # 如果需要拦截
        if self.intercept_enabled:
            # 【关键修复】使用 mitmproxy 的 flow.intercept() 非阻塞拦截
            flow.intercept()
            
            # 创建异步事件用于等待用户操作
            event = asyncio.Event()
            intercepted.set_event(event)
            
            # 存储等待中的 flow
            self.waiting_flows[flow_id] = (flow, event, intercepted)
            
            # 通知 GUI（使用信号，非阻塞）
            self.signals.request_intercepted.emit(intercepted)
            
            # 创建等待任务（异步，不阻塞事件循环）
            asyncio.create_task(self._wait_for_action(flow_id, event))
        else:
            # 不拦截，直接记录
            intercepted.intercepted = False
            self.signals.request_logged.emit(intercepted)
            # 存储以便后续关联响应
            self.waiting_flows[flow_id] = (flow, None, intercepted)
    
    async def _wait_for_action(self, flow_id: str, event: asyncio.Event):
        """【优化】等待用户操作 - 立即响应，快速清理"""
        try:
            # 【优化】减少超时时间到30秒，提高响应速度
            await asyncio.wait_for(event.wait(), timeout=30)
        except asyncio.TimeoutError:
            # 超时后自动放行
            if flow_id in self.waiting_flows:
                flow, _, intercepted = self.waiting_flows[flow_id]
                try:
                    flow.resume()
                except Exception:
                    pass
                intercepted.released = True
                print(f"Request {flow_id} timeout, auto-released")
        except asyncio.CancelledError:
            # 任务被取消，清理
            if flow_id in self.waiting_flows:
                flow, event, intercepted = self.waiting_flows[flow_id]
                try:
                    flow.kill()  # 取消时丢弃请求
                except Exception:
                    pass
                intercepted.released = True
        except Exception as e:
            print(f"Error in _wait_for_action for {flow_id}: {e}")
        finally:
            # 【关键修复】确保清理
            if flow_id in self.waiting_flows:
                del self.waiting_flows[flow_id]
    
    def cancel_all_tasks(self):
        """取消所有待处理任务"""
        # 直接清空等待列表，mitmproxy 会自动处理
        self.waiting_flows.clear()
    
    def handle_action(self, flow_id: str, action: str, modified_content: bytes = None):
        """【优化】处理用户操作 - 立即触发异步事件"""
        if flow_id not in self.waiting_flows:
            return
        
        flow, event, intercepted = self.waiting_flows[flow_id]
        
        try:
            if action == "forward":
                # 如果提供了修改后的内容
                if modified_content is not None:
                    flow.request.content = modified_content
                    flow.request.headers["Content-Length"] = str(len(modified_content))
                    intercepted.modified = True
                # 【关键】调用 resume() 放行，而不是 kill()
                flow.resume()
                intercepted.released = True
            elif action == "drop":
                flow.kill()
                intercepted.dropped = True
                intercepted.released = True
            
            # 【关键修复】立即唤醒等待的协程
            if event and not event.is_set():
                event.set()
                
                # 【额外保障】确保任务被唤醒后从等待列表中移除
                # 注意：不要在这里立即删除，让 _wait_for_action 清理
        except Exception as e:
            print(f"Error in handle_action: {e}")
            # 出错时也要唤醒协程，避免永久阻塞
            if event and not event.is_set():
                event.set()
    
    def response(self, flow):
        """处理响应 - 优化响应处理速度"""
        # 查找对应的请求 - 优化查找逻辑
        found = False
        for flow_id, (f, event, intercepted) in list(self.waiting_flows.items()):
            if f.id == flow.id:
                # 更新响应信息
                intercepted.status_code = flow.response.status_code
                intercepted.response_headers = dict(flow.response.headers)
                intercepted.response_content = flow.response.content if flow.response.content else b''
                
                # 通知 GUI
                self.signals.response_received.emit(intercepted, flow)
                found = True
                break
        
        # 如果没有找到对应的请求（可能是不拦截模式），创建新的记录
        if not found:
            self.flow_counter += 1
            flow_id = str(self.flow_counter)
            intercepted = InterceptedFlow(
                flow_id=flow_id,
                method=flow.request.method,
                url=flow.request.url,
                headers=dict(flow.request.headers),
                content=flow.request.content if flow.request.content else b''
            )
            intercepted.status_code = flow.response.status_code
            intercepted.response_headers = dict(flow.response.headers)
            intercepted.response_content = flow.response.content if flow.response.content else b''
            intercepted.intercepted = False
            self.signals.request_logged.emit(intercepted)
            self.signals.response_received.emit(intercepted, flow)


