#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
异步扫描工作线程
"""

import asyncio
import threading
from PySide6.QtCore import QThread, Signal

from core.async_scanner import AsyncScanner
from core.models import ScanResult, VulnerabilityFinding, TrafficLog


class AsyncScannerWorker(QThread):
    """异步扫描工作线程"""
    
    finished = Signal(ScanResult)
    progress = Signal(str)  # 日志消息
    finding_found = Signal(VulnerabilityFinding)  # 发现漏洞
    result_found = Signal(dict)  # 发现结果（用于实时显示）
    traffic_log = Signal(TrafficLog)  # 流量日志
    traffic_update = Signal(int, bool)  # 【新增】流量日志更新 (log_id, is_success)
    progress_update = Signal(int, str)  # 进度百分比和消息
    
    def __init__(
        self,
        target_url,
        file_param,
        upload_dir,
        proxies,
        headers,
        cookies,
        max_payloads=None,
        timeout=30,
        use_raw_multipart=True,
        use_fingerprint=True,
        selected_extensions=None,  # 【新增】用户选择的后缀
        scan_mode="security",  # 【新增】扫描模式: security / penetration
        webshell_config=None,  # 【新增】WebShell配置
    ):
        super().__init__()
        self.target_url = target_url
        self.file_param = file_param
        self.upload_dir = upload_dir
        self.proxies = proxies
        self.headers = headers
        self.cookies = cookies
        self.max_payloads = max_payloads
        self.timeout = timeout
        self.use_raw_multipart = use_raw_multipart
        self.use_fingerprint = use_fingerprint
        self.selected_extensions = selected_extensions or [".php", ".phtml", ".php3", ".php4", ".php5", ".phar", ".asp", ".aspx", ".cer", ".cdx", ".asa", ".jsp", ".jspx", ".jspf", ".jhtml", ".pl", ".cgi", ".py"]
        self.scan_mode = scan_mode
        self.webshell_config = webshell_config or {"enabled": False}
        self.scanner = AsyncScanner()
        
        # 确保信号连接正常工作
        self._signal_connected = False
        
    def connect_signals_safe(self):
        """安全连接信号 - 确保在运行前调用"""
        self._signal_connected = True
    
    def _on_log(self, message: str):
        """日志回调"""
        try:
            self.progress.emit(message)
        except Exception:
            pass
    
    def _on_traffic(self, log: TrafficLog):
        """流量日志回调"""
        self.traffic_log.emit(log)
    
    def _on_traffic_update(self, log_id: int, is_success: bool):
        """流量日志更新回调（is_success 更新后调用）"""
        self.traffic_update.emit(log_id, is_success)
    
    def _on_finding(self, finding: VulnerabilityFinding):
        """漏洞发现回调"""
        self.finding_found.emit(finding)
    
    def _on_result(self, result: dict):
        """结果回调（用于实时显示所有结果）"""
        self.result_found.emit(result)
    
    def _on_progress(self, message: str, percent: int):
        """进度回调"""
        try:
            self.progress_update.emit(percent, message)
        except Exception:
            pass
    
    def run(self):
        """运行扫描"""
        import sys
        
        try:
            self.progress.emit("=== AsyncScannerWorker 开始运行 ===")
            self.progress.emit(f"目标URL: {self.target_url}")
            self.progress.emit(f"文件参数: {self.file_param}")
            self.progress.emit(f"最大Payload: {self.max_payloads}")
            self.progress.emit(f"信号连接状态: {self._signal_connected}")
            
            # 确保信号连接正常
            if not self._signal_connected:
                self.progress.emit("警告: 信号可能未正确连接")
            
            # 【关键修复】确保scanner的running状态被重置为True
            self.scanner.running = True
            
            loop = asyncio.new_event_loop()
            
            # Windows上使用ProactorEventLoop，Linux使用SelectorEventLoop
            if sys.platform == 'win32':
                pass
            elif sys.platform.startswith('linux'):
                loop = asyncio.SelectorEventLoop()
            
            asyncio.set_event_loop(loop)
            
            try:
                self.progress.emit("开始扫描...")
                
                result = loop.run_until_complete(self.scanner.scan(
                    target_url=self.target_url,
                    file_param=self.file_param,
                    upload_dir=self.upload_dir,
                    proxies=self.proxies,
                    headers=self.headers,
                    cookies=self.cookies,
                    on_log_callback=self._on_log,
                    on_traffic_callback=self._on_traffic,
                    on_traffic_update_callback=self._on_traffic_update,
                    on_finding_callback=self._on_finding,
                    on_result_callback=self._on_result,
                    progress_callback=self._on_progress,
                    max_payloads=self.max_payloads,
                    timeout=self.timeout,
                    use_raw_multipart=self.use_raw_multipart,
                    use_fingerprint=self.use_fingerprint,
                    selected_extensions=self.selected_extensions,
                    scan_mode=self.scan_mode,  # 【新增】
                    webshell_config=self.webshell_config,  # 【新增】
                ))
                
                print(f"[AsyncScannerWorker] scanner.scan()完成")
                self.progress.emit(f"scanner.scan()完成，结果数量: {len(result.findings) if hasattr(result, 'findings') else 0}")
                self.finished.emit(result)
                
            except Exception as e:
                print(f"[AsyncScannerWorker] scanner.scan()异常: {e}")
                error_msg = f"扫描错误: {str(e)}"
                self.progress.emit(error_msg)
                import traceback
                self.progress.emit("详细错误信息:")
                for line in traceback.format_exc().split('\n'):
                    self.progress.emit(line)
                # 返回空结果
                from datetime import datetime
                empty_result = ScanResult(target=self.target_url, start_time=datetime.now())
                self.finished.emit(empty_result)
        except Exception as e:
            # 捕获所有可能的异常，确保不会静默失败
            final_error = f"Worker运行严重错误: {str(e)}"
            print(f"[AsyncScannerWorker] {final_error}")
            try:
                self.progress.emit(final_error)
                import traceback
                for line in traceback.format_exc().split('\n'):
                    self.progress.emit(line)
            except:
                pass  # 如果连信号都发不出去，就打印到控制台
            
            # 确保发出finished信号，避免GUI卡住
            try:
                from datetime import datetime
                empty_result = ScanResult(target=self.target_url, start_time=datetime.now())
                self.finished.emit(empty_result)
            except:
                pass
        finally:
            try:
                self.progress.emit("=== AsyncScannerWorker 运行结束 ===")
                if loop and not loop.is_closed():
                    try:
                        loop.close()
                    except Exception:
                        pass
            except:
                pass
    
    def stop(self):
        """停止扫描 - 【BUG-9修复】移除 terminate()，避免资源泄露"""
        try:
            self.progress.emit("正在停止扫描...")
            self.scanner.stop()
            self.progress.emit("扫描器已标记停止，等待当前请求完成...")

            if self.isRunning():
                # 给当前进行中的请求一个完成机会（最多5秒）
                if not self.wait(5000):
                    # 超时后记录警告，但不强制 terminate()
                    # terminate() 会绕过 Python finally 块，导致：
                    #   1. asyncio 事件循环不关闭（内存泄露）
                    #   2. RawHTTPClient socket 连接泄露
                    #   3. 可能导致后续扫描状态不一致
                    self.progress.emit("警告: 线程未在5秒内退出，已放弃等待（连接将随进程结束自动关闭）")
                    print("[AsyncScannerWorker] 线程停止超时，放弃等待（不强制 terminate）")
                else:
                    self.progress.emit("线程已正常退出")
            else:
                self.progress.emit("线程已不在运行状态")

        except Exception as e:
            error_msg = f"停止worker时出错: {str(e)}"
            print(f"[AsyncScannerWorker] {error_msg}")
            try:
                self.progress.emit(error_msg)
            except:
                pass  # 如果连信号都发不出去
