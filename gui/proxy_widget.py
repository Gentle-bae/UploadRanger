#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
代理模块入口（重构后的薄包装层）

原 2052 行单文件已拆分为 gui/proxy/ 子包：
  models.py        - ProxySignals, InterceptedFlow
  addon.py         - UploadRangerAddon (mitmproxy addon)
  proxy_thread.py  - ProxyThread
  history_tab.py   - ProxyHistoryTab
  intercept_tab.py - ProxyInterceptTab

本文件仅保留 ProxyWidget 主容器类，以维持向后兼容的 import 路径。
"""

import time
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLineEdit,
    QPushButton, QLabel, QTabWidget, QCheckBox, QMessageBox
)
from PySide6.QtCore import Qt, Signal

from .themes.dark_theme import COLORS
from core.config_manager import ConfigManager

# 从子包导入各组件
from .proxy.models import ProxySignals, InterceptedFlow
from .proxy.addon import UploadRangerAddon
from .proxy.proxy_thread import ProxyThread
from .proxy.history_tab import ProxyHistoryTab
from .proxy.intercept_tab import ProxyInterceptTab

try:
    from mitmproxy import http  # noqa: F401
    MITMPROXY_AVAILABLE = True
except ImportError:
    MITMPROXY_AVAILABLE = False


class ProxyWidget(QWidget):
    """代理主界面（薄容器，组件来自 gui/proxy/ 子包）"""

    send_to_repeater = Signal(object)
    send_to_intruder = Signal(object)

    def __init__(self):
        super().__init__()
        self.proxy_thread = None
        self._is_toggling = False
        self.config_manager = ConfigManager()
        self.init_ui()
        self._load_config()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)

        # 控制栏
        control_layout = QHBoxLayout()
        control_layout.setSpacing(10)

        _input_style = f"""
            QLineEdit {{
                background-color: {COLORS['bg_secondary']};
                color: {COLORS['text_primary']};
                border: 1px solid {COLORS['border']};
                padding: 5px;
                border-radius: 4px;
            }}
        """

        control_layout.addWidget(QLabel("代理地址:"))
        self.host_input = QLineEdit("127.0.0.1")
        self.host_input.setFixedWidth(120)
        self.host_input.setStyleSheet(_input_style)
        control_layout.addWidget(self.host_input)

        control_layout.addWidget(QLabel("端口:"))
        self.port_input = QLineEdit("8080")
        self.port_input.setFixedWidth(80)
        self.port_input.setStyleSheet(_input_style)
        control_layout.addWidget(self.port_input)

        self.start_btn = QPushButton("启动代理")
        self._apply_btn_style(self.start_btn, COLORS['success'], '#059669')
        self.start_btn.clicked.connect(self._toggle_proxy)
        control_layout.addWidget(self.start_btn)

        self.intercept_cb = QCheckBox("拦截请求")
        self.intercept_cb.setChecked(True)
        self.intercept_cb.setStyleSheet(f"color: {COLORS['text_primary']};")
        self.intercept_cb.stateChanged.connect(self._on_intercept_changed)
        control_layout.addWidget(self.intercept_cb)
        control_layout.addStretch()
        layout.addLayout(control_layout)

        # 状态栏
        self.status_label = QLabel("代理未启动")
        self.status_label.setStyleSheet(f"color: {COLORS['text_secondary']}; padding: 5px;")
        layout.addWidget(self.status_label)

        if not MITMPROXY_AVAILABLE:
            warn = QLabel("警告: mitmproxy 未安装，请运行: pip install mitmproxy")
            warn.setStyleSheet(f"color: {COLORS['danger']}; padding: 5px; font-weight: bold;")
            layout.addWidget(warn)

        # 子标签页
        self.tabs = QTabWidget()
        self.tabs.setStyleSheet(f"""
            QTabWidget::pane {{ border: 1px solid {COLORS['border']}; background-color: {COLORS['bg_secondary']}; }}
            QTabBar::tab {{ background-color: {COLORS['bg_tertiary']}; color: {COLORS['text_secondary']}; padding: 8px 16px; margin-right: 2px; }}
            QTabBar::tab:selected {{ background-color: {COLORS['accent']}; color: white; }}
        """)

        self.intercept_tab = ProxyInterceptTab(None)
        self.intercept_tab.send_to_repeater.connect(self._on_send_to_repeater)
        self.intercept_tab.send_to_intruder.connect(self._on_send_to_intruder)
        self.tabs.addTab(self.intercept_tab, "拦截")

        self.history_tab = ProxyHistoryTab(None, self.config_manager)
        self.history_tab.send_to_repeater.connect(self._on_send_to_repeater)
        self.history_tab.send_to_intruder.connect(self._on_send_to_intruder)
        self.tabs.addTab(self.history_tab, "历史")

        layout.addWidget(self.tabs)

        tip_label = QLabel(
            "提示: 1. 监听地址/端口可在上方修改（默认 127.0.0.1:8080）\n"
            "     2. 浏览器代理需与这里填写的 IP、端口一致\n"
            "     3. 首次使用 HTTPS 需要访问 http://mitm.it 安装 mitmproxy 证书"
        )
        tip_label.setStyleSheet(f"color: {COLORS['text_secondary']}; padding: 5px; font-size: 12px;")
        layout.addWidget(tip_label)

    # ------------------------------------------------------------------
    # 代理控制
    # ------------------------------------------------------------------

    def _toggle_proxy(self):
        if not MITMPROXY_AVAILABLE:
            QMessageBox.warning(self, "警告", "mitmproxy 未安装，请先运行: pip install mitmproxy")
            return
        if self._is_toggling:
            return
        self._is_toggling = True
        self.start_btn.setEnabled(False)
        try:
            if self.proxy_thread and self.proxy_thread._running:
                self._stop_proxy_thread()
                self.start_btn.setText("启动代理")
                self._apply_btn_style(self.start_btn, COLORS['success'], '#059669')
                self.status_label.setText("代理未启动")
                self.status_label.setStyleSheet(f"color: {COLORS['text_secondary']}; padding: 5px;")
                self._save_config()
            else:
                self._cleanup_old_thread()
                try:
                    host = self.host_input.text() or "127.0.0.1"
                    port = int(self.port_input.text() or 8080)
                    self.proxy_thread = ProxyThread(host, port)
                    self.proxy_thread.signals.request_intercepted.connect(self._on_intercepted)
                    self.proxy_thread.signals.request_logged.connect(self._on_logged)
                    self.proxy_thread.signals.response_received.connect(self._on_response)
                    self.proxy_thread.signals.status_changed.connect(self._on_status_changed)
                    self.proxy_thread.set_intercept(self.intercept_cb.isChecked())
                    self.proxy_thread.start()
                    self.start_btn.setText("停止代理")
                    self._apply_btn_style(self.start_btn, COLORS['danger'], '#dc2626')
                    self.intercept_tab.proxy_thread = self.proxy_thread
                    self.history_tab.proxy_thread = self.proxy_thread
                except Exception as e:
                    self.status_label.setText(f"启动失败: {e}")
                    self.status_label.setStyleSheet(f"color: {COLORS['danger']}; padding: 5px;")
                    QMessageBox.critical(self, "错误", f"启动代理失败: {e}")
                finally:
                    self._save_config()
        finally:
            self._is_toggling = False
            self.start_btn.setEnabled(True)

    def _stop_proxy_thread(self):
        if self.proxy_thread:
            self.proxy_thread.stop()
            if not self.proxy_thread.wait(5000):
                self.proxy_thread.terminate()
                self.proxy_thread.wait(1000)
            self.proxy_thread = None
        self.intercept_tab.proxy_thread = None
        self.history_tab.proxy_thread = None
        self.intercept_tab.clear_intercepted()

    def _cleanup_old_thread(self):
        if self.proxy_thread:
            self.proxy_thread.stop()
            if self.proxy_thread.isRunning():
                self.proxy_thread.wait(5000)
            if self.proxy_thread.isRunning():
                self.proxy_thread.terminate()
                self.proxy_thread.wait(1000)
            self.proxy_thread = None
            time.sleep(1.0)

    def stop_proxy(self):
        """外部调用：停止代理线程"""
        self._stop_proxy_thread()
        time.sleep(0.5)

    # ------------------------------------------------------------------
    # 信号处理
    # ------------------------------------------------------------------

    def _on_intercept_changed(self, state):
        if self.proxy_thread:
            self.proxy_thread.set_intercept(state == Qt.Checked)

    def _on_status_changed(self, status):
        self.status_label.setText(status)
        if "运行中" in status:
            self.status_label.setStyleSheet(f"color: {COLORS['success']}; font-weight: bold; padding: 5px;")
        else:
            self.status_label.setStyleSheet(f"color: {COLORS['danger']}; padding: 5px;")

    def _on_intercepted(self, intercepted):
        self.intercept_tab.add_intercepted(intercepted)
        self.history_tab.add_request(intercepted)

    def _on_logged(self, intercepted):
        self.history_tab.add_request(intercepted)

    def _on_response(self, intercepted, flow):
        self.history_tab.update_request(intercepted)

    def _on_send_to_repeater(self, request_data):
        self.send_to_repeater.emit(request_data)

    def _on_send_to_intruder(self, request_data):
        self.send_to_intruder.emit(request_data)

    # ------------------------------------------------------------------
    # 配置
    # ------------------------------------------------------------------

    def _load_config(self):
        if not self.config_manager:
            return
        cfg = self.config_manager.get_proxy_config()
        self.host_input.setText(cfg.get('host', '127.0.0.1'))
        self.port_input.setText(str(cfg.get('port', 8080)))
        self.intercept_cb.setChecked(cfg.get('intercept', True))
        self.history_tab.load_filter_config()

    def _save_config(self):
        if not self.config_manager:
            return
        try:
            port = int(self.port_input.text() or 8080)
        except ValueError:
            port = 8080
        self.config_manager.set_proxy_config(
            self.host_input.text() or '127.0.0.1',
            port,
            self.intercept_cb.isChecked()
        )
        self.config_manager.save()

    # ------------------------------------------------------------------
    # 工具方法
    # ------------------------------------------------------------------

    @staticmethod
    def _apply_btn_style(btn: QPushButton, bg: str, hover: str):
        btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {bg};
                color: white;
                border: none;
                padding: 8px 20px;
                border-radius: 4px;
                font-weight: bold;
            }}
            QPushButton:hover {{ background-color: {hover}; }}
        """)
