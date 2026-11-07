#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ProxyThread - mitmproxy 运行线程"""

import asyncio
import threading
import time
from PySide6.QtCore import QThread

try:
    from mitmproxy.tools.dump import DumpMaster
    from mitmproxy import options
    MITMPROXY_AVAILABLE = True
except ImportError:
    MITMPROXY_AVAILABLE = False

from .models import ProxySignals, InterceptedFlow
from .addon import UploadRangerAddon

class ProxyThread(QThread):
    """代理线程 - 在独立线程中运行 mitmproxy"""

    def __init__(self, host: str = "127.0.0.1", port: int = 8080,
                 upstream_url: str = "", ssl_insecure: bool = True):
        super().__init__()
        self.host = host
        self.port = port
        # 【新增】Issue #8 上游代理链: 浏览器 → 本代理 → 上游代理 → 内网目标
        self.upstream_url = upstream_url or ""
        # 【修复】上游 TLS 校验改为可配置项，不再硬编码关闭（审计 01 号 [中]）
        self.ssl_insecure = ssl_insecure
        self.signals = ProxySignals()
        self.addon = None
        self.master = None
        self.loop = None
        self._running = False
        # 【修复】使用实例变量以便 stop() 方法可以访问
        self._stop_event = None
        # 【修复】保护共享字段（loop/master/addon/_stop_event）的启停竞态
        self._lock = threading.Lock()
        # 【修复 P1】初始拦截态暂存：_toggle_proxy 在 addon 创建前调 set_intercept，
        # 旧实现直接空操作导致"关闭拦截启动"实际仍拦截 30s（客户端先超时）
        self._pending_intercept = True

    def set_intercept(self, enabled: bool):
        """设置是否拦截（addon 尚未创建时暂存，run_proxy 创建后补应用）"""
        with self._lock:
            self._pending_intercept = bool(enabled)
            addon = self.addon
        if addon:
            addon.set_intercept(bool(enabled))

    def forward_request(self, flow_id: str, modified_content: bytes = None,
                        method: str = None, path: str = None, headers: dict = None):
        """放行请求

        method/path/headers 为拦截编辑器完整请求文本的重建结果（可选）；
        旧调用只传 modified_content 时维持 body-only 行为（见 addon.handle_action）。
        """
        with self._lock:
            addon, loop = self.addon, self.loop
        if addon and loop:
            try:
                loop.call_soon_threadsafe(
                    addon.handle_action, flow_id, "forward",
                    modified_content, method, path, headers
                )
            except RuntimeError:
                pass  # 事件循环已在关闭中，run() 线程的 _cleanup() 负责收尾

    def drop_request(self, flow_id: str):
        """丢弃请求"""
        with self._lock:
            addon, loop = self.addon, self.loop
        if addon and loop:
            try:
                loop.call_soon_threadsafe(
                    addon.handle_action, flow_id, "drop"
                )
            except RuntimeError:
                pass
    
    def run(self):
        """线程的主入口"""
        import sys
        
        if not MITMPROXY_AVAILABLE:
            self.signals.status_changed.emit("错误: mitmproxy 未安装")
            return

        # 【修复】只对 mitmproxy 命名空间降噪，不再篡改全局 root logger（审计 01 号 [中]）
        import logging
        mitm_logger = logging.getLogger("mitmproxy")
        # 保存原始设置，finally 中只恢复这些 logger
        self._original_mitm_level = mitm_logger.level
        self._original_mitm_propagate = mitm_logger.propagate
        # 子 logger（mitmproxy.xxx）未显式设级时沿层级继承生效级别，静音父级即可全覆盖；
        # propagate=False 同时阻止记录进入 root handlers（避免事件循环关闭后报错）
        mitm_logger.setLevel(logging.CRITICAL)
        mitm_logger.propagate = False

        # 【修复】为子线程创建独立的事件循环
        self.loop = asyncio.new_event_loop()
        
        # Linux 环境下使用 DefaultSelector
        if sys.platform.startswith('linux'):
            self.loop = asyncio.SelectorEventLoop()
        
        # 设置事件循环
        asyncio.set_event_loop(self.loop)

        # 【修复】使用更可靠的方式运行异步代码
        async def run_proxy():
            """运行代理，并在停止时正确等待"""
            # 创建 mitmproxy master（必须在事件循环内创建）
            opts = options.Options(
                listen_host=self.host,
                listen_port=self.port,
                # 【修复】上游 TLS 校验跟随配置项，不再硬编码 True（审计 01 号 [中]）
                ssl_insecure=self.ssl_insecure
            )
            if self.upstream_url:
                # 【新增】Issue #8 上游链: 浏览器 → 本代理(抓包/拦截) → 上游代理 → 内网目标。
                # mitmproxy>=10 的 mode 为列表语法（实测 12.2.1 可用）
                opts.mode = [f"upstream:{self.upstream_url}"]
            self.master = DumpMaster(opts, with_termlog=False, with_dumper=False)

            # 创建插件
            self.addon = UploadRangerAddon(self.signals)
            self.master.addons.add(self.addon)
            # 【修复 P1】补应用 addon 创建前收到的拦截态（GUI 启动代理时同步勾选状态）
            self.addon.set_intercept(self._pending_intercept)

            self._running = True
            self.signals.status_changed.emit(f"代理运行中: {self.host}:{self.port}")

            # 创建停止事件
            self._stop_event = asyncio.Event()

            async def wait_for_stop():
                """等待停止信号"""
                while not self._stop_event.is_set():
                    await asyncio.sleep(0.1)
                self._running = False

            # 同时运行 master 和等待停止
            master_task = asyncio.create_task(self.master.run())
            stop_task = asyncio.create_task(wait_for_stop())

            try:
                # 等待任一任务完成
                done, pending = await asyncio.wait(
                    [master_task, stop_task],
                    return_when=asyncio.FIRST_COMPLETED
                )

                # 先关闭 master
                try:
                    self.master.shutdown()
                except Exception:
                    pass

                # 取消 pending 任务
                for task in pending:
                    task.cancel()
                    try:
                        await asyncio.wait_for(task, timeout=2.0)
                    except (asyncio.CancelledError, asyncio.TimeoutError, asyncio.InvalidStateError):
                        pass

            except asyncio.CancelledError:
                try:
                    self.master.shutdown()
                except Exception:
                    pass
            except Exception as e:
                self.signals.status_changed.emit(f"代理异常: {str(e)}")

        # 使用 run_until_complete 运行协程
        try:
            self.loop.run_until_complete(run_proxy())
        except (asyncio.CancelledError, RuntimeError) as e:
            # 用户主动停止或事件循环已关闭 - 这是正常现象，不显示错误
            if "Event loop stopped" in str(e):
                self.signals.status_changed.emit("代理已停止")
            else:
                self.signals.status_changed.emit(f"代理线程退出: {str(e)}")
        except Exception as e:
            self.signals.status_changed.emit(f"代理异常: {str(e)}")
        finally:
            self._running = False
            # 【修复】清理动作收敛到 _cleanup()，只由 run() 线程执行，
            # 避免与 stop()（GUI 线程）对共享字段的竞态（审计 01 号 [中]）
            self._cleanup()

    def _cleanup(self):
        """【修复】run() 线程专属清理: 取消任务 → 关 master → 清 addon → 关事件循环 → 恢复日志设置

        stop() 只发停止信号并 wait，实际清理全部收敛到这里。
        """
        with self._lock:
            loop = self.loop
        try:
            # 1. 取消事件循环中所有待处理任务
            if loop and not loop.is_closed():
                try:
                    async def _drain_tasks():
                        """取消所有待处理任务"""
                        try:
                            # 【修复 P1】必须排除当前任务：把 _drain_tasks 自己 cancel 掉
                            # 会让 asyncio.wait 抛 CancelledError，跳过后续清理步骤
                            pending = [t for t in asyncio.all_tasks()
                                       if t is not asyncio.current_task() and not t.done()]
                            if pending:
                                for t in pending:
                                    t.cancel()
                                await asyncio.wait(pending, timeout=1.0)
                        except (Exception, asyncio.CancelledError):
                            # CancelledError 是 BaseException,清理路径必须接住,否则
                            # 会逃出 QThread.run() 触发 "Error calling Python override" 噪音
                            pass

                    loop.run_until_complete(_drain_tasks())
                except (Exception, asyncio.CancelledError):
                    pass

            time.sleep(0.1)

            # 2. 移除 mitmproxy 挂到 root 的日志处理器，避免事件循环关闭后报错
            if self.master:
                try:
                    import logging
                    for handler in logging.root.handlers[:]:
                        if hasattr(handler, 'master'):
                            logging.root.removeHandler(handler)
                except Exception:
                    pass

                # 再关闭 master
                try:
                    self.master.shutdown()
                except Exception:
                    pass

            time.sleep(0.1)

            # 3. 清空 addon 等待列表并取消其任务
            if self.addon:
                self.addon.cancel_all_tasks()

            # 4. 关闭事件循环
            if loop and not loop.is_closed():
                try:
                    loop.stop()
                except Exception:
                    pass

                time.sleep(0.1)

                try:
                    loop.close()
                except Exception:
                    pass
        finally:
            # 5. 加锁清理共享引用（stop()/forward_request 的读端同样走锁）
            with self._lock:
                self.loop = None
                self.master = None
                self.addon = None
                self._stop_event = None
            # 【修复】只恢复 mitmproxy logger 的原始设置，不再动 root
            self._restore_mitm_logging()

    def _restore_mitm_logging(self):
        """恢复 mitmproxy logger 的级别与 propagate 设置"""
        if not hasattr(self, '_original_mitm_level'):
            return
        try:
            import logging
            mitm_logger = logging.getLogger("mitmproxy")
            mitm_logger.setLevel(self._original_mitm_level)
            mitm_logger.propagate = self._original_mitm_propagate
        except Exception:
            pass

    def stop(self):
        """停止代理 - 只发停止信号并等待 run() 线程自行清理，不直接置空共享字段（审计 01 号 [中]）"""
        self._running = False

        with self._lock:
            loop = self.loop
            stop_event = self._stop_event

        # 设置停止事件（asyncio.Event 非线程安全，必须经 call_soon_threadsafe 触发）
        if loop and not loop.is_closed() and stop_event:
            try:
                loop.call_soon_threadsafe(stop_event.set)
            except RuntimeError:
                pass  # 事件循环已关闭，run() 线程即将自行清理

        # 等待 run() 线程完成 _cleanup()
        if not self.wait(5000):
            # 超时兜底：强制停止事件循环（最后手段）
            if loop and not loop.is_closed() and loop.is_running():
                try:
                    loop.call_soon_threadsafe(loop.stop)
                except RuntimeError:
                    pass
            self.wait(2000)


