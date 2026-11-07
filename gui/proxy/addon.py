#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""mitmproxy Addon - UploadRangerAddon"""

import asyncio
from typing import Dict, Optional
from urllib.parse import urlsplit

try:
    from mitmproxy import http
    MITMPROXY_AVAILABLE = True
except ImportError:
    MITMPROXY_AVAILABLE = False

from .models import ProxySignals, InterceptedFlow

# 拦截等待超时（秒）：超时后自动放行并通知 GUI 移除对应行
INTERCEPT_TIMEOUT = 30


class UploadRangerAddon:
    """mitmproxy 插件 - 处理流量拦截"""

    def __init__(self, signals: ProxySignals, intercept_enabled: bool = True):
        self.signals = signals
        self.intercept_enabled = intercept_enabled
        # 【修复】{flow_id: (flow, event, intercepted)} —— 放行时只标 released 不删除，
        # 等 response() 完成关联后再清理，修复"响应关联不到原记录 + 重复条目 +
        # waiting_flows 无限增长"（审计 01 号 [高]）
        self.waiting_flows: Dict[str, tuple] = {}
        # 【修复】mitmproxy flow.id -> 本地 flow_id 的直接索引，response() O(1) 关联
        self._index_by_mitm_id: Dict[str, str] = {}
        self.flow_counter = 0
        self._pending_tasks: list = []  # 保存 asyncio 任务引用，供 cancel_all_tasks 真正取消

    def set_intercept(self, enabled: bool):
        """设置是否拦截"""
        self.intercept_enabled = enabled

    # ------------------------------------------------------------------
    # 等待条目管理
    # ------------------------------------------------------------------

    def _store(self, flow_id: str, flow, event, intercepted: InterceptedFlow):
        """登记等待条目并建立 mitm flow.id 直接索引"""
        self.waiting_flows[flow_id] = (flow, event, intercepted)
        self._index_by_mitm_id[flow.id] = flow_id

    def _remove(self, flow_id: str):
        """删除等待条目并同步清理索引"""
        entry = self.waiting_flows.pop(flow_id, None)
        if entry:
            f = entry[0]
            if self._index_by_mitm_id.get(f.id) == flow_id:
                self._index_by_mitm_id.pop(f.id, None)

    # ------------------------------------------------------------------
    # mitmproxy 回调
    # ------------------------------------------------------------------

    def request(self, flow):
        """处理请求 - 使用 flow.intercept() 非阻塞拦截"""
        self.flow_counter += 1
        flow_id = str(self.flow_counter)

        # 创建拦截对象
        intercepted = InterceptedFlow(
            flow_id=flow_id,
            method=flow.request.method,
            url=flow.request.url,
            headers=dict(flow.request.headers),
            content=flow.request.content if flow.request.content else b''
        )
        intercepted.set_flow(flow)

        if self.intercept_enabled:
            # 使用 mitmproxy 的 flow.intercept() 非阻塞拦截
            flow.intercept()

            # 创建异步事件用于等待用户操作
            event = asyncio.Event()
            intercepted.set_event(event)

            # 存储等待中的 flow
            self._store(flow_id, flow, event, intercepted)

            # 通知 GUI（使用信号，非阻塞）
            self.signals.request_intercepted.emit(intercepted)

            # 创建等待任务（异步，不阻塞事件循环）；保存引用防止被 GC 并支持统一取消
            task = asyncio.create_task(self._wait_for_action(flow_id, event))
            self._pending_tasks.append(task)
            task.add_done_callback(
                lambda t: self._pending_tasks.remove(t) if t in self._pending_tasks else None
            )
        else:
            # 不拦截，直接记录
            intercepted.intercepted = False
            self.signals.request_logged.emit(intercepted)
            # 存储以便后续关联响应（response() 处理完统一删除）
            self._store(flow_id, flow, None, intercepted)

    async def _wait_for_action(self, flow_id: str, event: asyncio.Event):
        """等待用户操作 - 立即响应"""
        try:
            await asyncio.wait_for(event.wait(), timeout=INTERCEPT_TIMEOUT)
        except asyncio.TimeoutError:
            entry = self.waiting_flows.get(flow_id)
            if entry:
                flow, _, intercepted = entry
                try:
                    flow.resume()
                except Exception:
                    pass
                # 【修复】只标 released 不删条目，等 response() 关联完成后清理
                intercepted.released = True
                # 【修复】超时自动放行必须通知 GUI 移除对应行，
                # 否则 GUI 侧再点"放行"会因条目状态不一致而静默失效（审计 01 号 [低]）
                self.signals.flow_timeout.emit(flow_id)
                print(f"Request {flow_id} timeout, auto-released")
        except asyncio.CancelledError:
            # 任务被取消，丢弃请求；kill 后不会再有响应，条目直接移除
            entry = self.waiting_flows.get(flow_id)
            if entry:
                flow, _, intercepted = entry
                try:
                    flow.kill()
                except Exception:
                    pass
                intercepted.released = True
                self._remove(flow_id)
        except Exception as e:
            print(f"Error in _wait_for_action for {flow_id}: {e}")
        # 【修复】finally 不再删除条目：放行路径保留条目给 response() 完成关联

    def cancel_all_tasks(self):
        """取消所有待处理任务"""
        for task in list(self._pending_tasks):
            if not task.done():
                task.cancel()
        self._pending_tasks.clear()
        # 清空等待列表与索引
        self.waiting_flows.clear()
        self._index_by_mitm_id.clear()

    # ------------------------------------------------------------------
    # 用户操作
    # ------------------------------------------------------------------

    def handle_action(self, flow_id: str, action: str, modified_content: bytes = None,
                      method: str = None, path: str = None, headers: Optional[Dict[str, str]] = None):
        """处理用户操作 - 立即触发异步事件

        forward 时若携带 method/path/headers（拦截编辑器完整请求文本的重建结果），
        则整体重建 flow.request（编辑器为完整请求文本，含请求行与头）；
        只传 modified_content 时维持旧的 body-only 行为，保持旧调用兼容。
        """
        if flow_id not in self.waiting_flows:
            return

        flow, event, intercepted = self.waiting_flows[flow_id]

        try:
            if action == "forward":
                if method is not None or path is not None or headers is not None:
                    # 【修复】拦截编辑器为完整请求文本，全量重建 flow.request（审计 01 号 [中]）
                    self._rebuild_request(flow, intercepted, method, path, headers, modified_content)
                elif modified_content is not None:
                    # 旧行为：仅替换 body
                    flow.request.content = modified_content
                    flow.request.headers["Content-Length"] = str(len(modified_content))
                    intercepted.modified = True
                # 调用 resume() 放行，而不是 kill()
                flow.resume()
                intercepted.released = True
            elif action == "drop":
                flow.kill()
                intercepted.dropped = True
                intercepted.released = True
                # flow 被丢弃后不会再有响应，条目直接清理
                self._remove(flow_id)

            # 立即唤醒等待的协程
            if event and not event.is_set():
                event.set()
        except Exception as e:
            print(f"Error in handle_action: {e}")
            # 出错时也要唤醒协程，避免永久阻塞
            if event and not event.is_set():
                event.set()

    @staticmethod
    def _rebuild_request(flow, intercepted: InterceptedFlow, method: str,
                         path: str, headers: Optional[Dict[str, str]], body: Optional[bytes]):
        """用编辑器重建的完整请求字段整体重建 flow.request

        - 编辑器首行可能是完整 URL（scheme://host/path），需归一为 origin-form path；
        - Qt 文本框会把 CRLF 归一为 \\n，body 在调用侧已转回 \\r\\n；
        - 头部先清空再逐个写入，保证用户删除的头不残留；
        - body 非空时重算 Content-Length（body 为 None 表示编辑器无 body 段，不动 content）。
        """
        if method:
            flow.request.method = method
        if path:
            if "://" in path:
                # 完整 URL → origin-form：取 path + query
                split = urlsplit(path)
                new_path = split.path or "/"
                if split.query:
                    new_path += f"?{split.query}"
                flow.request.path = new_path
            else:
                flow.request.path = path
        if headers is not None:
            # 先清空再逐个写入，保证用户删除的头不残留
            flow.request.headers.clear()
            for k, v in headers.items():
                flow.request.headers[k] = v
        if body is not None:
            flow.request.content = body
            # 重建后 Content-Length 必须重算
            flow.request.headers["Content-Length"] = str(len(body))
            intercepted.content = body
        intercepted.method = flow.request.method
        intercepted.url = flow.request.url
        intercepted.headers = dict(flow.request.headers)
        intercepted.modified = True

    def response(self, flow):
        """处理响应 - 通过 mitm flow.id 直接索引 O(1) 关联"""
        local_id = self._index_by_mitm_id.get(flow.id)
        if local_id and local_id in self.waiting_flows:
            _, _, intercepted = self.waiting_flows[local_id]
            # 更新响应信息
            intercepted.status_code = flow.response.status_code
            intercepted.response_headers = dict(flow.response.headers)
            intercepted.response_content = flow.response.content if flow.response.content else b''

            # 通知 GUI
            self.signals.response_received.emit(intercepted, flow)

            # 【修复】响应关联完成后再删除条目（拦截放行/非拦截模式统一走这里）
            self._remove(local_id)
            return

        # 未找到对应的请求（如 addon 启动前已存在的流量），创建新的记录。
        # 【修复 P3】去重：同一 flow 只记一次（mitmproxy 对同流可能触发多次回调）。
        if getattr(flow, "_ur_logged", False):
            return
        flow._ur_logged = True
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

    def error(self, flow):
        """【修复 P2】连接失败走 error() 而非 response()：镜像 response() 的关联与清理，
        否则放行/超时放行/非拦截请求在目标不可达时，waiting_flows 与
        _index_by_mitm_id 条目（含 flow 与请求内容）永久泄漏，历史行永远无状态码。"""
        local_id = self._index_by_mitm_id.get(flow.id)
        if local_id and local_id in self.waiting_flows:
            _, _, intercepted = self.waiting_flows[local_id]
            intercepted.status_code = 0
            intercepted.response_headers = {}
            intercepted.response_content = b""
            err = getattr(flow, "error", None)
            intercepted.response_headers["X-UploadRanger-Error"] = str(err) if err else "connection error"
            self.signals.response_received.emit(intercepted, flow)
            self._remove(local_id)
            return
        # 非关联流量同样去重记录（与 response() fallback 一致）
        if getattr(flow, "_ur_logged", False):
            return
        flow._ur_logged = True
        self.flow_counter += 1
        flow_id = str(self.flow_counter)
        intercepted = InterceptedFlow(
            flow_id=flow_id,
            method=flow.request.method,
            url=flow.request.url,
            headers=dict(flow.request.headers),
            content=flow.request.content if flow.request.content else b''
        )
        intercepted.status_code = 0
        err = getattr(flow, "error", None)
        intercepted.response_headers = {"X-UploadRanger-Error": str(err) if err else "connection error"}
        intercepted.response_content = b""
        intercepted.intercepted = False
        self.signals.request_logged.emit(intercepted)
        self.signals.response_received.emit(intercepted, flow)
