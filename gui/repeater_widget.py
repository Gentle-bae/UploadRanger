#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Repeater module with multi-tab support (Burp-style)
"""

import asyncio
import logging
import re
import httpx
from typing import Any, Dict, List, Optional
from PySide6.QtCore import Qt, Signal, QThread, QSignalBlocker
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QComboBox,
    QPushButton, QSplitter, QGroupBox, QPlainTextEdit, QDialog, 
    QListWidget, QDialogButtonBox, QMessageBox, QCheckBox, QTabBar,
    QStackedWidget, QInputDialog
)

from .themes.dark_theme import COLORS
from .syntax_highlighter import HTTPHighlighter
from .response_viewer import ResponseViewerWidget

logger = logging.getLogger(__name__)

# Import payload generators
try:
    from ..payloads.intruder_payloads import generate_intruder_payloads, PayloadFactory, FuzzConfig
    from ..payloads.bypass_payloads import BypassPayloadGenerator
    from ..core.response_analyzer import ResponseAnalyzer
except ImportError:
    from payloads.intruder_payloads import generate_intruder_payloads, PayloadFactory, FuzzConfig
    from payloads.bypass_payloads import BypassPayloadGenerator
    from core.response_analyzer import ResponseAnalyzer


class RepeaterWorker(QThread):
    finished = Signal(dict)
    error = Signal(str)
    request_data: Dict[str, Any]
    _loop: Optional[asyncio.AbstractEventLoop]
    _stopped: bool

    def __init__(self, request_data: Dict[str, Any]):
        super().__init__()
        self.request_data = request_data
        self._loop = None
        self._stopped = False

    def stop(self):
        """停止 worker"""
        self._stopped = True
        if self._loop is not None and not self._loop.is_closed():
            try:
                # 【修复】线程安全：不要在 UI 线程直接操作 worker 线程的事件循环。
                # 必须使用 call_soon_threadsafe，把取消/停止逻辑切回 loop 所在线程执行，
                # 否则在 Windows + ProactorEventLoop 下可能造成卡死/无响应。
                def _cancel_and_stop():
                    try:
                        for task in asyncio.all_tasks(loop=self._loop):
                            task.cancel()
                    except Exception:
                        pass
                    try:
                        self._loop.stop()
                    except Exception:
                        pass

                self._loop.call_soon_threadsafe(_cancel_and_stop)
            except Exception:
                pass

    def run(self):
        try:
            self._loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self._loop)
            result = self._loop.run_until_complete(self._send_request())
            if not self._stopped:
                self.finished.emit(result)
        except Exception as e:
            if not self._stopped:
                self.error.emit(str(e))
        finally:
            if self._loop and not self._loop.is_closed():
                try:
                    self._loop.close()
                except Exception:
                    pass

    async def _send_request(self):
        url = self.request_data.get('url', '')
        method = self.request_data.get('method', 'GET')
        headers = self.request_data.get('headers', {})
        body = self.request_data.get('body', '')
        follow_redirects = bool(self.request_data.get('follow_redirects', False))

        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url

        headers.pop('Content-Length', None)
        headers.pop('content-length', None)

        # Default Burp-like behavior: do NOT auto-follow redirects.
        # When enabled, this may turn a single POST into POST+GET and the final page may include
        # accumulated session flash messages.
        async with httpx.AsyncClient(verify=False, timeout=30, follow_redirects=follow_redirects) as client:
            request_kwargs = {'headers': headers}
            if body:
                request_kwargs['content'] = body.encode('utf-8') if isinstance(body, str) else body

            if method == 'GET':
                response = await client.get(url, **request_kwargs)
            elif method == 'POST':
                response = await client.post(url, **request_kwargs)
            elif method == 'PUT':
                response = await client.put(url, **request_kwargs)
            elif method == 'DELETE':
                response = await client.delete(url, **request_kwargs)
            elif method == 'PATCH':
                response = await client.patch(url, **request_kwargs)
            else:
                response = await client.request(method, url, **request_kwargs)

            res_headers = "\n".join([f"{k}: {v}" for k, v in response.headers.items()])
            return {
                'status_code': response.status_code,
                'headers': res_headers,
                'body': response.text,
                'body_bytes': response.content,
                'url': str(response.url),
            }


class RepeaterTab(QWidget):
    request_sent = Signal(dict, str)

    def __init__(self, tab_name: str = "Repeater"):
        super().__init__()
        self.tab_name = tab_name
        self.worker = None
        self._closing = False
        
        # Initialize payload generators
        self.intruder_factory = PayloadFactory()
        self.bypass_generator = BypassPayloadGenerator()
        self.response_analyzer = ResponseAnalyzer()
        
        self._build_ui()

    def stop_worker(self) -> None:
        """安全停止 worker，避免标签关闭后仍触发回调导致崩溃。
        
        简单原则：断开所有指向本 tab 的信号连接，让 worker 自行结束。
        不要阻塞 wait()，不要强制 delete，避免 Qt 崩溃。
        """
        self._closing = True
        w = getattr(self, "worker", None)
        if not w:
            return
        # 断开信号，防止 worker 回调到即将删除的 widget
        try:
            w.finished.disconnect(self._on_request_finished)
        except Exception:
            pass
        try:
            w.error.disconnect(self._on_request_error)
        except Exception:
            pass
        # 请求停止（线程安全）
        w.stop()
        # 不要 wait()，不要 deleteLater()，让 worker 自行退出和 GC
        self.worker = None

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)

        control_layout = QHBoxLayout()
        control_layout.addWidget(QLabel("URL:"))
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("http://example.com")
        control_layout.addWidget(self.url_input)

        control_layout.addWidget(QLabel("Method:"))
        self.method_combo = QComboBox()
        self.method_combo.addItems(["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
        control_layout.addWidget(self.method_combo)

        self.send_btn = QPushButton("Send")
        self.send_btn.setObjectName("success")
        self.send_btn.setFixedWidth(80)
        self.send_btn.clicked.connect(self._send_request)
        control_layout.addWidget(self.send_btn)

        self.follow_redirects_cb = QCheckBox("跟随重定向")
        self.follow_redirects_cb.setToolTip("开启后会自动跟随 30x 跳转并展示最终页面；关闭则只显示本次请求的直接响应（更接近 Burp Repeater 默认行为）")
        self.follow_redirects_cb.setChecked(False)
        control_layout.addWidget(self.follow_redirects_cb)

        self.strip_cookie_cb = QCheckBox("本次不带Cookie")
        self.strip_cookie_cb.setToolTip("只对本次 Send 生效：发送前移除 Cookie 头，避免靶场把历史提示/flash message 一起渲染出来")
        self.strip_cookie_cb.setChecked(False)
        control_layout.addWidget(self.strip_cookie_cb)

        self.clear_response_btn = QPushButton("清空响应")
        self.clear_response_btn.setFixedWidth(100)
        self.clear_response_btn.clicked.connect(self._clear_response)
        control_layout.addWidget(self.clear_response_btn)

        layout.addLayout(control_layout)

        splitter = QSplitter(Qt.Vertical)

        req_group = QGroupBox("Request")
        req_layout = QVBoxLayout(req_group)
        self.req_edit = QPlainTextEdit()
        self.req_edit.setFont(QFont("Consolas", 10))
        self.highlighter_req = HTTPHighlighter(self.req_edit.document(), is_request=True)
        # 【新增】启用自定义右键菜单
        self.req_edit.setContextMenuPolicy(Qt.CustomContextMenu)
        self.req_edit.customContextMenuRequested.connect(self._on_req_context_menu)
        req_layout.addWidget(self.req_edit)
        splitter.addWidget(req_group)

        res_group = QGroupBox("Response")
        res_layout = QVBoxLayout(res_group)
        self.res_status_label = QLabel("")
        self.res_status_label.setStyleSheet(f"color: {COLORS['accent']}; font-weight: bold;")
        res_layout.addWidget(self.res_status_label)
        self.res_display = ResponseViewerWidget()
        res_layout.addWidget(self.res_display)
        splitter.addWidget(res_group)

        splitter.setSizes([400, 400])
        layout.addWidget(splitter)

    def load_request(self, request_data: dict):
        method = request_data.get('method', 'GET')
        url = request_data.get('url', '')
        headers = request_data.get('request_headers', '')
        body = request_data.get('request_body', '')
        self.url_input.setText(url)
        self.method_combo.setCurrentText(method)
        
        # 【修复】检查 headers 是否已经包含请求行
        if headers.strip().startswith(('GET ', 'POST ', 'PUT ', 'DELETE ', 'PATCH ', 'HEAD ', 'OPTIONS ')):
            # headers 已经包含请求行，直接使用
            req_text = f"{headers}\n\n{body}"
        else:
            # headers 不包含请求行，需要构造
            req_text = f"{method} {url} HTTP/1.1\n{headers}\n\n{body}"
        
        self.req_edit.setPlainText(req_text)
        self.res_display.clear()
        self.res_status_label.setText("")

    def _parse_request(self, req_text: str):
        """解析请求文本，提取方法、URL、请求头和请求体"""
        lines = req_text.strip().splitlines()
        if not lines:
            return None, None, None, None
        first_line = lines[0].strip().split(' ')
        if len(first_line) < 2:
            return None, None, None, None
        method = first_line[0]
        url = first_line[1]
        headers = {}
        body_start = 0
        for i, line in enumerate(lines[1:], 1):
            if line.strip() == '':
                body_start = i + 1
                break
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()
        
        # 【修复】处理 multipart/form-data 请求
        body = '\n'.join(lines[body_start:]) if body_start > 0 else ''
        content_type = headers.get('Content-Type', '').lower()
        
        if 'multipart/form-data' in content_type:
            # 从 Content-Type 中提取 boundary
            if 'boundary=' in content_type:
                boundary = content_type.split('boundary=')[-1].strip().strip('"')
                # 将 \r\n 转换为可读格式用于显示
                # 但原始请求体保持原样用于发送
            # multipart 请求体不需要额外处理，保持原样
        
        if url.startswith('/'):
            host = headers.get('Host') or headers.get('host') or ''
            host = host.strip()
            if host:
                base = self.url_input.text().strip().lower()
                scheme = 'https' if base.startswith('https://') else 'http'
                url = f"{scheme}://{host}{url}"
        return method, url, headers, body

    def _send_request(self):
        url = self.url_input.text().strip()
        if not url:
            self.res_display.raw_view.setPlainText("Error: URL required")
            return

        method = self.method_combo.currentText()
        req_text = self.req_edit.toPlainText()
        parsed_method, parsed_url, headers, body = self._parse_request(req_text)
        if parsed_url and parsed_url != '/':
            url = parsed_url
        if parsed_method:
            method = parsed_method

        if self.strip_cookie_cb.isChecked():
            headers.pop('Cookie', None)
            headers.pop('cookie', None)

        self.send_btn.setEnabled(False)
        self.send_btn.setText("Sending...")

        # 【修复】提取当前文件名用于后续分析
        self._current_filename = self._extract_filename_from_request(req_text)

        self.worker = RepeaterWorker({
            'url': url,
            'method': method,
            'headers': headers,
            'body': body,
            'follow_redirects': self.follow_redirects_cb.isChecked(),
        })
        self.worker.finished.connect(self._on_request_finished)
        self.worker.error.connect(self._on_request_error)
        self.worker.start()

    def _clear_response(self):
        self.res_display.clear()
        self.res_status_label.setText("")

    def _extract_filename_from_request(self, req_text: str) -> str:
        """从请求中提取文件名"""
        # 查找 filename="xxx" 模式
        match = re.search(r'filename="([^"]+)"', req_text, re.IGNORECASE)
        if match:
            return match.group(1)
        # 查找 filename=xxx 模式（没有引号）
        match = re.search(r'filename=([^\s;]+)', req_text, re.IGNORECASE)
        if match:
            return match.group(1)
        return ""

    def _on_request_finished(self, result: dict):
        # 如果正在关闭，忽略响应
        if getattr(self, '_closing', False):
            return
        
        self.send_btn.setEnabled(True)
        self.send_btn.setText("Send")

        status_code = result.get('status_code', 0)
        headers = result.get('headers', '')
        body = result.get('body', '')

        content_type = 'text/plain'
        for line in headers.split('\n'):
            if line.lower().startswith('content-type:'):
                content_type = line.split(':', 1)[1].strip()
                break

        self._update_status_label(status_code)
        
        # 使用ResponseAnalyzer分析响应，提取页面提示
        analysis = self._analyze_response(result)
        if analysis:
            # 将分析结果添加到响应中
            result['analysis'] = analysis
        
        self.res_display.set_response_from_dict(result)
    
    def _analyze_response(self, result: dict) -> dict:
        """分析响应内容，提取页面提示信息（区分当前文件名和历史记录）"""
        try:
            # 创建一个模拟的response对象
            class MockResponse:
                def __init__(self, result):
                    self.status_code = result.get('status_code', 0)
                    self.text = result.get('body', '')
                    self.content = result.get('body_bytes', b'')
                    self.headers = {}
                    self.url = result.get('url', '')
                    # 【修复】lambda需要接受self参数
                    self.elapsed = type('Elapsed', (), {'total_seconds': lambda self: 0})()
                    
                    # 解析headers
                    for line in result.get('headers', '').split('\n'):
                        if ':' in line:
                            k, v = line.split(':', 1)
                            self.headers[k.strip()] = v.strip()
            
            mock_resp = MockResponse(result)
            analysis = self.response_analyzer.analyze(mock_resp)
            
            # 【新增】获取当前文件名
            current_filename = getattr(self, '_current_filename', '')
            
            # 【新增】分析成功消息，过滤掉历史记录
            filtered_success_msgs = []
            for msg in analysis.get('success_messages', []):
                # 如果消息中包含当前文件名，保留它
                if current_filename and current_filename.lower() in msg.lower():
                    filtered_success_msgs.append(f"[当前] {msg}")
                else:
                    # 可能是历史记录，标记出来
                    filtered_success_msgs.append(f"[历史] {msg}")
            
            # 【新增】如果有当前文件名的成功消息，标记为当前成功
            is_current_success = any(
                current_filename and current_filename.lower() in msg.lower()
                for msg in analysis.get('success_messages', [])
            ) if current_filename else False
            
            # 简化返回结果
            return {
                'is_success': is_current_success if current_filename else analysis.get('is_success', False),
                'is_failure': analysis.get('is_failure', False),
                'message': f"当前文件: {current_filename}\n{analysis.get('message', '')}" if current_filename else analysis.get('message', ''),
                'error_messages': analysis.get('error_messages', []),
                'warning_messages': analysis.get('warning_messages', []),
                'success_messages': filtered_success_msgs,
                'hidden_indicators': analysis.get('hidden_indicators', []),
                'uploaded_path': analysis.get('uploaded_path', ''),
            }
        except Exception as e:
            return {'error': str(e)}

    def _on_request_error(self, error_msg: str):
        # 如果正在关闭，忽略错误
        if getattr(self, '_closing', False):
            return
        
        self.send_btn.setEnabled(True)
        self.send_btn.setText("Send")
        self.res_display.clear()
        self.res_display.raw_view.setPlainText(f"Request error: {error_msg}")
        self.res_status_label.setText("Request failed")
        self.res_status_label.setStyleSheet(f"color: {COLORS['danger']}; font-weight: bold;")

    def _update_status_label(self, status_code: int):
        status_text = f"Status: {status_code}"
        if 200 <= status_code < 300:
            status_text += " OK"
            color = COLORS['success']
        elif 300 <= status_code < 400:
            status_text += " Redirect"
            color = COLORS['warning']
        elif 400 <= status_code < 500:
            status_text += " Client Error"
            color = COLORS['danger']
        else:
            status_text += " Server Error"
            color = "#ff6b6b"
        self.res_status_label.setText(status_text)
        self.res_status_label.setStyleSheet(f"color: {color}; font-weight: bold;")

    def _on_req_context_menu(self, pos):
        """【新增】请求编辑器的右键菜单"""
        # 获取标准右键菜单
        menu = self.req_edit.createStandardContextMenu()
        
        # 添加分隔符
        menu.addSeparator()
        
        # 添加"发送到Intruder"选项
        send_intruder_action = menu.addAction("发送到 Intruder")
        
        # 显示菜单并获取用户选择
        action = menu.exec(self.req_edit.mapToGlobal(pos))
        
        if action == send_intruder_action:
            self._send_to_intruder()
    
    def _send_to_intruder(self):
        """【新增】发送当前请求到Intruder"""
        req_text = self.req_edit.toPlainText()
        
        # 解析请求
        lines = req_text.strip().split('\n')
        if not lines:
            QMessageBox.warning(self, "警告", "请求内容为空")
            return
        
        first_line = lines[0].strip()
        parts = first_line.split(' ')
        if len(parts) < 2:
            QMessageBox.warning(self, "警告", "请求格式不正确")
            return
        
        method = parts[0]
        url = parts[1]
        
        # 解析headers
        headers = {}
        body_start = 0
        for i, line in enumerate(lines[1:], 1):
            if line.strip() == '':
                body_start = i + 1
                break
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()
        
        body = '\n'.join(lines[body_start:]) if body_start > 0 else ''
        
        # 构建请求数据
        request_data = {
            'method': method,
            'url': url,
            'request_headers': '\n'.join([f"{k}: {v}" for k, v in headers.items()]),
            'request_body': body
        }
        
        # 发送信号到主窗口，请求创建新标签
        self.request_sent.emit(request_data, "intruder_new")

    def _on_generate_payloads(self):
        """生成文件上传绕过Payloads"""
        request_text = self.req_edit.toPlainText()
        
        # 检查是否包含文件上传相关内容
        if 'filename=' not in request_text and 'multipart' not in request_text.lower():
            QMessageBox.warning(
                self, 
                "提示", 
                "当前请求不包含文件上传表单 (multipart/form-data)\n"
                "请确保请求中包含 filename= 参数"
            )
            return
        
        # 显示Payload配置对话框
        dialog = PayloadConfigDialog(self)
        if dialog.exec() == QDialog.Accepted:
            config = dialog.get_config()
            
            # 生成Payloads
            try:
                payloads = self._generate_upload_payloads(request_text, config)
                
                # 显示Payload选择对话框
                select_dialog = PayloadSelectDialog(payloads, self)
                if select_dialog.exec() == QDialog.Accepted:
                    selected_payload = select_dialog.get_selected_payload()
                    if selected_payload:
                        # 将选中的payload填入请求编辑器
                        self.req_edit.setPlainText(selected_payload)
                        
            except Exception as e:
                QMessageBox.critical(self, "错误", f"生成Payload失败: {str(e)}")
    
    def _generate_upload_payloads(self, template: str, config: dict) -> list:
        """生成上传绕过Payloads
        
        Args:
            template: HTTP请求模板
            config: 配置字典
        
        Returns:
            List[str]: Payload列表
        """
        payloads = []
        
        # 使用Intruder Factory生成高级payloads
        languages = config.get('languages', ['php'])
        max_payloads = config.get('max_payloads', 100)
        
        intruder_payloads = generate_intruder_payloads(
            template, 
            languages=languages, 
            max_payloads=max_payloads
        )
        payloads.extend(intruder_payloads)
        
        # 使用Bypass Generator生成基础payloads
        if config.get('include_bypass', True):
            extensions = {
                'php': '.php',
                'asp': '.asp',
                'aspx': '.aspx',
                'jsp': '.jsp'
            }
            
            for lang in languages:
                if lang in extensions:
                    bypass_payloads = self.bypass_generator.generate_all_payloads(
                        "shell", extensions[lang]
                    )
                    for bp in bypass_payloads[:50]:  # 限制数量
                        # 替换模板中的filename
                        new_payload = re.sub(
                            r'filename="[^"]+"',
                            f'filename="{bp["filename"]}"',
                            template
                        )
                        payloads.append(new_payload)
        
        return payloads[:config.get('max_total', 200)]


class PayloadConfigDialog(QDialog):
    """Payload生成配置对话框"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Payload生成配置")
        self.setMinimumWidth(400)
        self._build_ui()
    
    def _build_ui(self):
        layout = QVBoxLayout(self)
        
        # 目标语言选择
        lang_group = QGroupBox("目标语言")
        lang_layout = QVBoxLayout(lang_group)
        
        self.php_cb = QCheckBox("PHP")
        self.php_cb.setChecked(True)
        self.asp_cb = QCheckBox("ASP")
        self.aspx_cb = QCheckBox("ASPX")
        self.jsp_cb = QCheckBox("JSP")
        
        lang_layout.addWidget(self.php_cb)
        lang_layout.addWidget(self.asp_cb)
        lang_layout.addWidget(self.aspx_cb)
        lang_layout.addWidget(self.jsp_cb)
        layout.addWidget(lang_group)
        
        # 选项
        options_group = QGroupBox("选项")
        options_layout = QVBoxLayout(options_group)
        
        self.bypass_cb = QCheckBox("包含基础绕过Payloads")
        self.bypass_cb.setChecked(True)
        self.bypass_cb.setToolTip("使用BypassPayloadGenerator生成基础绕过payloads")
        options_layout.addWidget(self.bypass_cb)
        
        layout.addWidget(options_group)
        
        # 按钮
        button_box = QDialogButtonBox(
            QDialogButtonBox.Ok | QDialogButtonBox.Cancel
        )
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)
    
    def get_config(self) -> dict:
        """获取配置"""
        languages = []
        if self.php_cb.isChecked():
            languages.append('php')
        if self.asp_cb.isChecked():
            languages.append('asp')
        if self.aspx_cb.isChecked():
            languages.append('aspx')
        if self.jsp_cb.isChecked():
            languages.append('jsp')
        
        return {
            'languages': languages if languages else ['php'],
            'include_bypass': self.bypass_cb.isChecked(),
            'max_payloads': 100,
            'max_total': 200
        }


class PayloadSelectDialog(QDialog):
    """Payload选择对话框"""
    
    def __init__(self, payloads: list, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"选择Payload ({len(payloads)}个可用)")
        self.setMinimumSize(800, 600)
        self.payloads = payloads
        self.selected_payload = None
        self._build_ui()
    
    def _build_ui(self):
        layout = QVBoxLayout(self)
        
        # Payload列表
        self.payload_list = QListWidget()
        self.payload_list.itemDoubleClicked.connect(self._on_item_double_clicked)
        
        # 添加payloads到列表 (显示filename)
        for i, payload in enumerate(self.payloads[:500]):  # 限制显示数量
            # 提取filename
            match = re.search(r'filename="([^"]+)"', payload)
            if match:
                filename = match.group(1)
                self.payload_list.addItem(f"[{i+1}] {filename}")
            else:
                self.payload_list.addItem(f"[{i+1}] Payload {i+1}")
        
        layout.addWidget(QLabel(f"共 {len(self.payloads)} 个Payloads (显示前500个)"))
        layout.addWidget(self.payload_list)
        
        # 预览区域
        preview_group = QGroupBox("预览")
        preview_layout = QVBoxLayout(preview_group)
        self.preview_edit = QPlainTextEdit()
        self.preview_edit.setReadOnly(True)
        self.preview_edit.setFont(QFont("Consolas", 9))
        preview_layout.addWidget(self.preview_edit)
        layout.addWidget(preview_group)
        
        # 连接选择信号
        self.payload_list.currentRowChanged.connect(self._on_selection_changed)
        
        # 按钮
        button_box = QDialogButtonBox(
            QDialogButtonBox.Ok | QDialogButtonBox.Cancel
        )
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)
    
    def _on_selection_changed(self, row: int):
        """选择改变时更新预览"""
        if 0 <= row < len(self.payloads):
            payload = self.payloads[row]
            # 显示payload的前1000个字符
            preview = payload[:1000] + "..." if len(payload) > 1000 else payload
            self.preview_edit.setPlainText(preview)
    
    def _on_item_double_clicked(self, item):
        """双击选择"""
        self.accept()
    
    def get_selected_payload(self) -> str:
        """获取选中的payload"""
        row = self.payload_list.currentRow()
        if 0 <= row < len(self.payloads):
            return self.payloads[row]
        return None
    
    def accept(self):
        """确认选择"""
        row = self.payload_list.currentRow()
        if row < 0:
            QMessageBox.warning(self, "提示", "请先选择一个Payload")
            return
        self.selected_payload = self.payloads[row] if row < len(self.payloads) else None
        super().accept()


class RepeaterWidget(QWidget):
    """多标签页Repeater组件 (Burp-style)"""
    
    def __init__(self):
        super().__init__()
        self._tab_counter = 1
        # 【修复】保存已关闭的 widget 引用，避免立即 deleteLater 导致崩溃
        self._closed_tabs = []
        self._init_ui()
    
    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        
        # 工具栏
        toolbar = QHBoxLayout()
        
        # 新建标签按钮
        self.new_tab_btn = QPushButton("+ 新建标签")
        self.new_tab_btn.setStyleSheet(f"background-color: {COLORS['success']}; color: white; font-weight: bold; padding: 5px 15px;")
        self.new_tab_btn.clicked.connect(self._on_new_tab)
        toolbar.addWidget(self.new_tab_btn)
        
        # 关闭标签按钮
        self.close_tab_btn = QPushButton("关闭标签")
        self.close_tab_btn.setStyleSheet(f"background-color: {COLORS['danger']}; color: white; padding: 5px 15px;")
        self.close_tab_btn.clicked.connect(self._on_close_tab)
        toolbar.addWidget(self.close_tab_btn)
        
        toolbar.addStretch()
        layout.addLayout(toolbar)
        
        # 标签栏 - 设置紧凑样式
        self.tab_bar = QTabBar()
        self.tab_bar.setTabsClosable(True)
        self.tab_bar.setMovable(True)
        self.tab_bar.setExpanding(False)  # 【新增】不自动扩展，保持固定大小
        self.tab_bar.setElideMode(Qt.ElideRight)  # 【新增】文本过长时省略
        self.tab_bar.setStyleSheet("""
            QTabBar::tab {
                min-width: 80px;
                max-width: 150px;
                padding: 5px 10px;
                margin-right: 2px;
            }
        """)
        self.tab_bar.tabCloseRequested.connect(self._on_tab_close_requested)
        self.tab_bar.currentChanged.connect(self._on_tab_changed)
        # 【修复】tab_bar 可拖动时必须同步 content_stack 的 widget 顺序，否则索引会错位
        self.tab_bar.tabMoved.connect(self._on_tab_moved)
        self.tab_bar.tabBarDoubleClicked.connect(self._on_tab_rename)
        layout.addWidget(self.tab_bar)
        
        # 内容区域
        self.content_stack = QStackedWidget()
        layout.addWidget(self.content_stack, stretch=1)
        
        # 创建默认标签
        self._add_tab("Repeater 1")
    
    def _add_tab(self, name: str = None) -> tuple:
        """添加新标签，返回 (tab_bar_index, widget)"""
        if name is None:
            name = f"Repeater {self._tab_counter}"
        self._tab_counter += 1
        
        tab = RepeaterTab(name)
        self.content_stack.addWidget(tab)
        tab_index = self.tab_bar.addTab(name)
        
        self.tab_bar.setCurrentIndex(tab_index)
        return tab_index, tab
    
    def _on_new_tab(self):
        """新建标签"""
        self._add_tab()
    
    def _on_close_tab(self):
        """关闭当前标签"""
        current = self.tab_bar.currentIndex()
        if current >= 0:
            self._on_tab_close_requested(current)
    
    def _on_tab_close_requested(self, index: int):
        """关闭指定标签"""
        if self.tab_bar.count() <= 1:
            QMessageBox.information(self, "提示", "至少需要保留一个标签")
            return
        
        try:
            # index 合法性保护（tab_bar 与 content_stack 可能在拖动/删除后短暂不同步）
            if index < 0 or index >= self.content_stack.count():
                return

            current = self.tab_bar.currentIndex()

            # 删除前先确定一个安全的新 current
            target_current = current
            if current == index:
                target_current = index - 1 if index > 0 else 0

            # 取出要删除的 widget
            widget = self.content_stack.widget(index)
            if widget and isinstance(widget, RepeaterTab):
                widget.stop_worker()

            # 【修复】删除过程中阻断 currentChanged 重入，避免 setCurrentIndex/removeTab 互相触发
            blocker = QSignalBlocker(self.tab_bar)
            try:
                if target_current != current and 0 <= target_current < self.tab_bar.count():
                    self.tab_bar.setCurrentIndex(target_current)
            finally:
                del blocker

            # 延迟执行删除，确保 Qt 完成上述切换事件处理
            from PySide6.QtCore import QTimer
            QTimer.singleShot(0, lambda w=widget, i=index: self._do_remove_tab(w, i))

        except Exception as e:
            import traceback
            traceback.print_exc()

    def _do_remove_tab(self, widget, index: int):
        """实际执行删除标签页"""
        try:
            # 删除前再次校验 index（可能已因其它操作变化）
            if index < 0 or index >= self.tab_bar.count() or index >= self.content_stack.count():
                return

            # 【关键修复】先阻断所有信号，避免 removeTab/removeWidget 触发级联信号导致崩溃
            blocker_tab = QSignalBlocker(self.tab_bar)
            blocker_stack = QSignalBlocker(self.content_stack)
            # 也阻断 widget 自身的信号（如果有子控件连接）
            if widget:
                try:
                    widget.blockSignals(True)
                except Exception:
                    pass
            
            try:
                # 先从 stack 移除 widget，再从 tab_bar 移除 tab
                if widget is None:
                    widget = self.content_stack.widget(index)
                if widget is not None:
                    # 【关键修复】不调用 deleteLater，改为隐藏并保存引用
                    # 等程序真正退出时再统一清理，避免 Qt 立即销毁导致崩溃
                    widget.hide()
                    widget.setParent(None)
                    self._closed_tabs.append(widget)
                    self.content_stack.removeWidget(widget)
                    # 限制缓存数量，避免内存无限增长
                    if len(self._closed_tabs) > 20:
                        old_widget = self._closed_tabs.pop(0)
                        try:
                            old_widget.deleteLater()
                        except Exception:
                            pass
                    
                self.tab_bar.removeTab(index)
            finally:
                # 恢复信号阻断前确保 widget 信号也被恢复
                if widget:
                    try:
                        widget.blockSignals(False)
                    except Exception:
                        pass
                del blocker_stack
                del blocker_tab

            # 删除后修正 currentIndex，使用 QTimer 延迟避免立即信号风暴
            if self.tab_bar.count() > 0:
                new_current = min(self.tab_bar.currentIndex(), self.tab_bar.count() - 1)
                if new_current < 0:
                    new_current = 0
                # 使用 QTimer 延迟切换，避免立即触发信号风暴
                from PySide6.QtCore import QTimer
                QTimer.singleShot(50, lambda: self._safe_set_current(new_current))
        except Exception as e:
            import traceback
            traceback.print_exc()

    def _safe_set_current(self, index: int):
        """安全设置当前标签，带保护"""
        try:
            if 0 <= index < self.tab_bar.count():
                self.tab_bar.setCurrentIndex(index)
            if 0 <= index < self.content_stack.count():
                self.content_stack.setCurrentIndex(index)
        except Exception:
            pass


    def _on_tab_moved(self, from_index: int, to_index: int):
        """同步 tab_bar 的拖动顺序到 content_stack"""
        try:
            if from_index == to_index:
                return
            if from_index < 0 or from_index >= self.content_stack.count():
                return
            w = self.content_stack.widget(from_index)
            if w is None:
                return
            # 阻断信号
            blocker = QSignalBlocker(self.content_stack)
            try:
                self.content_stack.removeWidget(w)
                self.content_stack.insertWidget(to_index, w)
            finally:
                del blocker
        except Exception:
            pass
    
    def _on_tab_changed(self, index: int):
        """切换标签"""
        if index >= 0 and index < self.content_stack.count():
            self.content_stack.setCurrentIndex(index)
    
    def _on_tab_rename(self, index: int):
        """重命名标签"""
        current_name = self.tab_bar.tabText(index)
        dialog = QInputDialog(self)
        dialog.setWindowTitle("重命名标签")
        dialog.setLabelText("请输入新名称:")
        dialog.setTextValue(current_name)
        dialog.resize(400, 150)
        if dialog.exec() == QInputDialog.Accepted:
            new_name = dialog.textValue()
            if new_name:
                self.tab_bar.setTabText(index, new_name)
    
    def load_request(self, request_data: dict, create_new_tab: bool = True):
        """加载请求到Repeater - 默认创建新标签"""
        if create_new_tab:
            # 创建新标签并加载请求
            tab_index, current_widget = self._add_tab()
        else:
            # 加载到当前标签（兼容旧行为）
            current_widget = self.content_stack.currentWidget()
        
        if current_widget and isinstance(current_widget, RepeaterTab):
            current_widget.load_request(request_data)
