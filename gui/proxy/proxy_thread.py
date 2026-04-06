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
    
    def __init__(self, host: str = "127.0.0.1", port: int = 8080):
        super().__init__()
        self.host = host
        self.port = port
        self.signals = ProxySignals()
        self.addon = None
        self.master = None
        self.loop = None
        self._running = False
        # 【修复】使用实例变量以便 stop() 方法可以访问
        self._stop_event = None
    
    def set_intercept(self, enabled: bool):
        """设置是否拦截"""
        if self.addon:
            self.addon.set_intercept(enabled)
    
    def forward_request(self, flow_id: str, modified_content: bytes = None):
        """放行请求"""
        if self.addon and self.loop:
            self.loop.call_soon_threadsafe(
                self.addon.handle_action, flow_id, "forward", modified_content
            )
    
    def drop_request(self, flow_id: str):
        """丢弃请求"""
        if self.addon and self.loop:
            self.loop.call_soon_threadsafe(
                self.addon.handle_action, flow_id, "drop"
            )
    
    def run(self):
        """线程的主入口"""
        import sys
        
        if not MITMPROXY_AVAILABLE:
            self.signals.status_changed.emit("错误: mitmproxy 未安装")
            return

        # 【修复】禁用 mitmproxy 的日志处理器，避免程序退出时事件循环关闭后报错
        import logging
        # 保存原始日志级别
        self._original_loglevel = logging.root.level
        # 设置更高的日志级别，过滤掉 mitmproxy 的日志
        logging.root.setLevel(logging.CRITICAL)

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
                ssl_insecure=True
            )
            self.master = DumpMaster(opts, with_termlog=False, with_dumper=False)

            # 创建插件
            self.addon = UploadRangerAddon(self.signals)
            self.master.addons.add(self.addon)

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

            # 【方案A修复】在 finally 块中也进行彻底清理
            import time
            
            # 1. 首先尝试取消所有 asyncio 任务
            if self.loop and not self.loop.is_closed():
                try:
                    async def cleanup_tasks():
                        """清理所有待处理任务"""
                        try:
                            all_tasks = asyncio.all_tasks(self.loop)
                            pending = [t for t in all_tasks if not t.done()]
                            if pending:
                                for t in pending:
                                    t.cancel()
                                await asyncio.wait(pending, timeout=1.0)
                        except Exception:
                            pass
                    
                    if self.loop.is_running():
                        self.loop.run_until_complete(cleanup_tasks())
                except Exception:
                    pass
            
            time.sleep(0.1)

            # 2. 先移除 mitmproxy 的日志处理器，避免事件循环关闭后报错
            if hasattr(self, 'master') and self.master:
                try:
                    # 移除所有日志处理器
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

            # 3. 清空等待列表
            if self.addon:
                self.addon.cancel_all_tasks()

            # 4. 关闭事件循环
            if self.loop and not self.loop.is_closed():
                try:
                    # 停止事件循环，这会取消所有正在等待的任务
                    self.loop.stop()
                except Exception:
                    pass

                time.sleep(0.1)
                
                # 关闭循环
                try:
                    self.loop.close()
                except Exception:
                    pass

            # 5. 清理引用
            self.loop = None
            self.master = None
            self.addon = None
            
            # 【修复】恢复日志级别
            if hasattr(self, '_original_loglevel'):
                import logging
                logging.root.setLevel(self._original_loglevel)

    def stop(self):
        """停止代理 - 彻底清理所有资源"""
        self._running = False
        import time

        # 【修复】使用 run_coroutine_threadsafe 在运行中的事件循环中调度取消任务
        if self.loop and not self.loop.is_closed() and self.loop.is_running():
            try:
                async def cancel_all_tasks():
                    """取消事件循环中的所有待处理任务"""
                    try:
                        all_tasks = asyncio.all_tasks(self.loop)
                        pending_tasks = [t for t in all_tasks if not t.done() and t != asyncio.current_task()]
                        
                        if pending_tasks:
                            for task in pending_tasks:
                                task.cancel()
                            # 等待所有任务完成取消（设置较短的超时）
                            await asyncio.wait_for(
                                asyncio.gather(*pending_tasks, return_exceptions=True),
                                timeout=1.0
                            )
                    except Exception:
                        pass

                # 使用 run_coroutine_threadsafe 在运行中的事件循环中调度任务
                future = asyncio.run_coroutine_threadsafe(cancel_all_tasks(), self.loop)
                # 等待取消操作完成，最多等待1.5秒
                try:
                    future.result(timeout=1.5)
                except Exception:
                    pass  # 忽略超时或取消异常
            except Exception:
                pass

        # 等待任务取消完成
        time.sleep(0.2)

        # 设置停止事件
        if self._stop_event:
            try:
                self._stop_event.set()
            except Exception:
                pass

        # 等待一小段时间
        time.sleep(0.2)

        # 确保 master 已关闭
        if hasattr(self, 'master') and self.master:
            try:
                self.master.shutdown()
            except Exception:
                pass

        # 等待 master 关闭
        time.sleep(0.3)

        # 强制停止事件循环（作为最后手段）
        if self.loop:
            try:
                if self.loop.is_running():
                    self.loop.call_soon_threadsafe(self.loop.stop)
                time.sleep(0.2)
                if not self.loop.is_closed():
                    self.loop.close()
            except Exception as e:
                print(f"停止事件循环时出错: {e}")

        # 清理引用，帮助 GC
        self._stop_event = None
        self.master = None
        self.addon = None
        self.loop = None  # 彻底清理，不复用


