#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
主窗口 - UploadRanger GUI主界面 v1.1.1
整合upload_forge功能，添加请求/响应查看、Repeater和Intruder功能
"""

import sys
import os
import asyncio
import re
import json
import ssl
from datetime import datetime
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
from threading import Thread

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QTabWidget, QFormLayout,
    QTextEdit, QProgressBar, QTableWidget, QTableWidgetItem,
    QHeaderView, QGroupBox, QCheckBox, QSpinBox, QSplitter,
    QFileDialog, QComboBox, QMessageBox, QPlainTextEdit, QDialog, QInputDialog,
    QMenu, QFrame, QScrollArea, QListWidget, QListWidgetItem,
    QRadioButton, QButtonGroup,
)
from PySide6.QtCore import Qt, QSize, QTimer, QObject, Signal
from PySide6.QtGui import QColor, QFont, QIcon, QAction
import webbrowser

from .themes.dark_theme import apply_dark_theme, COLORS
from .traffic_viewer import TrafficViewer
from .proxy_widget import ProxyWidget
from .repeater_widget import RepeaterWidget
from .intruder_widget import IntruderWidget
from .syntax_highlighter import HTTPHighlighter, WebShellHighlighter
from .wizard_widget import QuickScanWizard


# 导入核心模块

# 【新增】成功状态背景色常量
SUCCESS_BG_COLOR = "#1a3d1a"  # 深绿色背景
VULN_BG_COLOR = "#3d1a3d"    # 深紫色背景（漏洞）

# 导入核心模块
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import VERSION as CURRENT_VERSION
from core.async_scanner import get_builtin_async_payload_count
from core.async_scanner_worker import AsyncScannerWorker
from core.form_parser import FormParser
from payloads.webshells import WebShellGenerator
from payloads.bypass_payloads import BypassPayloadGenerator
from payloads.polyglots import PolyglotGenerator
from core.models import VulnerabilityFinding, RISK_CRITICAL, RISK_HIGH, RISK_MEDIUM

GITHUB_API_URL = "https://api.github.com/repos/Gentle-bae/UploadRanger/releases/latest"
GITHUB_REPO_URL = "https://github.com/Gentle-bae/UploadRanger"


class _UpdateCheckBridge(QObject):
    """工作线程通过信号把结果投递回 GUI 线程（比 QTimer.singleShot 更可靠）。"""

    succeeded = Signal(str, str)
    failed = Signal(str)


class _PageDiscoverBridge(QObject):
    succeeded = Signal(list)
    failed = Signal(str)


class ExtensionSelectorDialog(QDialog):
    """后缀选择对话框"""
    
    # 所有可用后缀定义
    EXTENSION_GROUPS = {
        "PHP": ["php", "phtml", "php3", "php4", "php5", "phar"],
        "ASP": ["asp", "aspx", "cer", "cdx", "asa"],
        "JSP": ["jsp", "jspx", "jspf", "jspa"],
        "Python": ["py", "py3", "pypi"],
        "Perl": ["pl", "pm"],
        "CGI": ["cgi", "fcgi"],
        "Other": ["jhtml", "shtml", "htm", "html", "svg"],
        # 操作系统级后缀
        "Win系统": ["exe", "dll", "bat", "cmd", "vbs", "ps1", "hta", "scr", "cpl"],
        "Linux": ["sh", "bash", "elf", "so"],
        # 配置文件（安全模式为纯文本）
        "配置": ["htaccess", "user.ini", "ini"],
        # Office文档
        "文档": ["docm", "xlsm", "pptm", "pdf", "rtf", "csv"],
        # 【删除】压缩包已移除（zip、rar、tar、gz、bz2、7z）
    }
    
    def __init__(self, parent=None, initial_exts=None):
        super().__init__(parent)
        self.setWindowTitle("选择测试后缀")
        self.setMinimumWidth(450)
        self.setMinimumHeight(400)
        
        # 默认全选
        if initial_exts is None:
            initial_exts = set()
            for exts in self.EXTENSION_GROUPS.values():
                initial_exts.update(exts)
        
        self.selected_exts = set(initial_exts)
        
        self._setup_ui()
    
    def _setup_ui(self):
        layout = QVBoxLayout(self)
        
        # 说明标签
        info_label = QLabel("选择要测试的文件后缀。已确认成功的后缀将自动跳过。")
        info_label.setStyleSheet("color: #aaa; font-size: 12px;")
        layout.addWidget(info_label)
        
        # 快速操作按钮
        btn_row = QHBoxLayout()
        select_all_btn = QPushButton("全选")
        select_all_btn.setFixedWidth(100)  # 修复按钮显示不全
        select_all_btn.clicked.connect(self._select_all)
        deselect_all_btn = QPushButton("取消全选")
        deselect_all_btn.setFixedWidth(100)  # 修复按钮显示不全
        deselect_all_btn.clicked.connect(self._deselect_all)
        btn_row.addWidget(select_all_btn)
        btn_row.addWidget(deselect_all_btn)
        btn_row.addStretch()
        layout.addLayout(btn_row)
        
        # 滚动区域
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll_widget = QWidget()
        scroll_layout = QVBoxLayout(scroll_widget)
        
        # 按语言分组显示
        self.group_widgets = {}
        for group_name, exts in self.EXTENSION_GROUPS.items():
            group_box = QGroupBox(group_name)
            group_layout = QVBoxLayout(group_box)
            
            # 全选/反选按钮
            header_row = QHBoxLayout()
            group_select_all = QPushButton("全选")
            group_select_all.setFixedWidth(80)  # 修复按钮显示不全
            group_select_all.clicked.connect(lambda checked, g=group_name: self._group_select(g))
            header_row.addWidget(group_select_all)
            header_row.addStretch()
            group_layout.addLayout(header_row)
            
            # 后缀复选框网格
            self.group_widgets[group_name] = []
            row_layout = QHBoxLayout()
            row_count = 0
            for ext in exts:
                cb = QCheckBox(ext)
                cb.setChecked(ext in self.selected_exts)
                cb.stateChanged.connect(self._on_ext_changed)
                self.group_widgets[group_name].append(cb)
                row_layout.addWidget(cb)
                row_count += 1
                if row_count >= 4:
                    row_layout.addStretch()
                    group_layout.addLayout(row_layout)
                    row_layout = QHBoxLayout()
                    row_count = 0
            if row_count > 0:
                row_layout.addStretch()
                group_layout.addLayout(row_layout)
            
            scroll_layout.addWidget(group_box)
        
        scroll.setWidget(scroll_widget)
        layout.addWidget(scroll)
        
        # 底部统计和按钮
        bottom_row = QHBoxLayout()
        self.count_label = QLabel()
        self.count_label.setStyleSheet("color: #4fc3f7; font-weight: bold;")
        bottom_row.addWidget(self.count_label)
        bottom_row.addStretch()
        
        ok_btn = QPushButton("确定")
        ok_btn.setFixedWidth(70)
        ok_btn.setDefault(True)
        ok_btn.clicked.connect(self.accept)
        cancel_btn = QPushButton("取消")
        cancel_btn.setFixedWidth(70)
        cancel_btn.clicked.connect(self.reject)
        bottom_row.addWidget(ok_btn)
        bottom_row.addWidget(cancel_btn)
        layout.addLayout(bottom_row)
        
        self._update_count()
    
    def _select_all(self):
        for cbs in self.group_widgets.values():
            for cb in cbs:
                cb.setChecked(True)
    
    def _deselect_all(self):
        for cbs in self.group_widgets.values():
            for cb in cbs:
                cb.setChecked(False)
    
    def _group_select(self, group_name):
        """组内全选"""
        cbs = self.group_widgets.get(group_name, [])
        all_checked = all(cb.isChecked() for cb in cbs)
        for cb in cbs:
            cb.setChecked(not all_checked)
    
    def _on_ext_changed(self):
        self.selected_exts = self.get_selected_extensions()
        self._update_count()
    
    def _update_count(self):
        count = len(self.get_selected_extensions())
        self.count_label.setText(f"已选择 {count} 个后缀")
    
    def get_selected_extensions(self):
        """获取选择的后缀列表"""
        selected = []
        for cbs in self.group_widgets.values():
            for cb in cbs:
                if cb.isChecked():
                    selected.append(cb.text())
        return selected
    
    def get_selected_with_dot(self):
        """获取带点的后缀列表"""
        return ["." + ext for ext in self.get_selected_extensions()]


class WebShellSettingsDialog(QDialog):
    """WebShell设置对话框"""
    
    def __init__(self, parent=None, password="UploadRanger", shell_type="基础eval"):
        super().__init__(parent)
        self.setWindowTitle("WebShell 设置")
        self.setMinimumWidth(350)
        
        self.password = password
        self.shell_type = shell_type
        
        self._setup_ui()
    
    def _setup_ui(self):
        layout = QVBoxLayout(self)
        
        # 说明
        info_label = QLabel("设置渗透测试模式下上传的WebShell参数")
        info_label.setStyleSheet("color: #ff6b6b; font-size: 12px;")
        info_label.setWordWrap(True)
        layout.addWidget(info_label)
        
        # 密码设置
        pwd_layout = QHBoxLayout()
        pwd_layout.addWidget(QLabel("连接密码:"))
        self.password_input = QLineEdit()
        self.password_input.setText(self.password)
        self.password_input.setPlaceholderText("留空使用默认密码")
        self.password_input.setStyleSheet("""
            QLineEdit {
                background-color: #2d2d2d;
                border: 1px solid #444;
                border-radius: 3px;
                padding: 4px 8px;
                color: #00ff00;
            }
        """)
        pwd_layout.addWidget(self.password_input)
        layout.addLayout(pwd_layout)
        
        # Shell类型
        type_layout = QHBoxLayout()
        type_layout.addWidget(QLabel("Shell类型:"))
        self.type_combo = QComboBox()
        self.type_combo.addItems(["基础eval", "Base64免杀", "冰蝎兼容", "蚁剑兼容"])
        if self.shell_type in ["基础eval", "Base64免杀", "冰蝎兼容", "蚁剑兼容"]:
            self.type_combo.setCurrentText(self.shell_type)
        type_layout.addWidget(self.type_combo)
        type_layout.addStretch()
        layout.addLayout(type_layout)
        
        # 类型说明
        type_hint = QLabel("基础eval: 最简单可靠的WebShell\nBase64免杀: 绕过基础检测\n冰蝎兼容: 冰蝎客户端连接\n蚁剑兼容: 蚁剑客户端连接")
        type_hint.setStyleSheet("color: #888; font-size: 11px;")
        type_hint.setWordWrap(True)
        layout.addWidget(type_hint)
        
        layout.addStretch()
        
        # 按钮
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        ok_btn = QPushButton("确定")
        ok_btn.setDefault(True)
        ok_btn.clicked.connect(self._on_ok)
        cancel_btn = QPushButton("取消")
        cancel_btn.clicked.connect(self.reject)
        btn_layout.addWidget(ok_btn)
        btn_layout.addWidget(cancel_btn)
        layout.addLayout(btn_layout)
    
    def _on_ok(self):
        self.password = self.password_input.text() or "UploadRanger"
        self.shell_type = self.type_combo.currentText()
        self.accept()
    
    def get_config(self):
        """获取配置"""
        return {
            "password": self.password,
            "type": self.shell_type
        }


class ResultsTable(QTableWidget):
    """扫描结果表格 - 显示所有测试结果"""
    
    # 信号定义 - 用于发送到Repeater/Intruder/Diff
    send_to_repeater = Signal(dict)
    send_to_intruder = Signal(dict)
    
    def __init__(self):
        super().__init__()
        self.setColumnCount(7)  # 【新增】增加验证状态列
        self.setHorizontalHeaderLabels(["文件名", "类型", "状态码", "状态", "概率", "验证状态", "路径"])
        
        self.setColumnWidth(0, 180)
        self.setColumnWidth(1, 120)
        self.setColumnWidth(2, 60)
        self.setColumnWidth(3, 60)
        self.setColumnWidth(4, 60)
        self.setColumnWidth(5, 80)  # 【新增】验证状态列
        self.setColumnWidth(6, 250)
        
        header = self.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Fixed)
        header.setSectionResizeMode(1, QHeaderView.Fixed)
        header.setSectionResizeMode(2, QHeaderView.Fixed)
        header.setSectionResizeMode(3, QHeaderView.Fixed)
        header.setSectionResizeMode(4, QHeaderView.Fixed)
        header.setSectionResizeMode(5, QHeaderView.Fixed)  # 【新增】验证状态列
        header.setSectionResizeMode(6, QHeaderView.Stretch)
        
        self.verticalHeader().setVisible(False)
        self.setSelectionBehavior(QTableWidget.SelectRows)
        self.setEditTriggers(QTableWidget.NoEditTriggers)  # 【修复】禁用编辑
        self.setAlternatingRowColors(True)
        
        # 【修复】添加表格样式，移除选中边框
        self.setStyleSheet(f"""
            QTableWidget {{
                background-color: {COLORS['bg_secondary']};
                color: {COLORS['text_primary']};
                border: 1px solid {COLORS['border']};
                gridline-color: {COLORS['border']};
            }}
            QTableWidget::item {{
                padding: 4px 8px;
                border: none;
            }}
            QTableWidget::item:selected {{
                background-color: {COLORS['accent']};
                color: white;
                border: none;
                outline: none;
            }}
            QHeaderView::section {{
                background-color: {COLORS['bg_tertiary']};
                color: {COLORS['text_primary']};
                padding: 8px;
                border: none;
                border-right: 1px solid {COLORS['border']};
                border-bottom: 1px solid {COLORS['border']};
                font-weight: bold;
            }}
        """)
        
        # 存储所有结果
        self.results = []
        
        # 【新增】右键菜单
        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self._show_context_menu)
    
    def clear_results(self):
        """清空结果"""
        self.setRowCount(0)
        self.results = []
    
    def add_result(self, result: dict):
        """添加扫描结果"""
        self.results.append(result)
        row = self.rowCount()
        self.insertRow(row)
        
        # 提前获取状态标志（用于后续的颜色设置）
        is_success = result.get('is_success', False)
        is_vulnerability = result.get('is_vulnerability', False)
        
        # === 创建所有 item ===
        
        # 第0列：文件名 - 根据状态设置醒目前景色
        filename_item = QTableWidgetItem(result.get('filename', 'Unknown'))
        filename_item.setData(Qt.UserRole, result)
        if is_vulnerability:
            filename_item.setForeground(QColor("#ffffff"))
            font = filename_item.font()
            font.setBold(True)
            filename_item.setFont(font)
        elif is_success:
            filename_item.setForeground(QColor("#00ff00"))
        
        # 第1列：类型
        type_item = QTableWidgetItem(result.get('payload_type', 'Unknown'))
        
        # 第2列：状态码
        status_code = result.get('status_code', 0)
        status_item = QTableWidgetItem(str(status_code))
        if 200 <= status_code < 300:
            status_item.setForeground(QColor(COLORS['success']))
        elif 300 <= status_code < 400:
            status_item.setForeground(QColor(COLORS['warning']))
        elif 400 <= status_code < 500:
            status_item.setForeground(QColor(COLORS['danger']))
        elif 500 <= status_code:
            status_item.setForeground(QColor("#ff6b6b"))
        
        # 第3列：状态文本
        status_text = "成功" if is_success else "失败"
        status_text_item = QTableWidgetItem(status_text)
        reasons = result.get('decision_reasons', []) or []
        if reasons:
            status_text_item.setToolTip("\n".join([f"- {r}" for r in reasons]))
        if is_success:
            status_text_item.setForeground(QColor(COLORS['success']))
        else:
            status_text_item.setForeground(QColor(COLORS['text_secondary']))
        
        # 第4列：概率
        prob = result.get('success_probability', 0)
        prob_item = QTableWidgetItem(f"{prob}%")
        if prob >= 70:
            prob_item.setForeground(QColor(COLORS['success']))
        elif prob >= 40:
            prob_item.setForeground(QColor(COLORS['warning']))
        else:
            prob_item.setForeground(QColor(COLORS['danger']))
        confidence_level = result.get('confidence_level', 'low')
        prob_item.setToolTip(f"置信度: {confidence_level}")
        
        # 【新增】第5列：验证状态
        verification = result.get('verification', {})
        verify_status = verification.get('status', 'N/A')
        verify_verified = verification.get('verified', False)
        
        if verify_verified:
            verify_text = "已验证"
            verify_color = COLORS['success']
        elif verify_status == 'error':
            verify_text = "错误"
            verify_color = COLORS['danger']
        elif verify_status == 'no_path':
            verify_text = "无路径"
            verify_color = COLORS['text_secondary']
        else:
            verify_text = "未验证"
            verify_color = COLORS['text_secondary']
        
        verify_item = QTableWidgetItem(verify_text)
        verify_item.setForeground(QColor(verify_color))
        
        # 添加验证详情tooltip
        verify_tooltip = f"状态: {verify_status}\n"
        if verification.get('execution_confirmed'):
            verify_tooltip += "执行: 已确认执行\n"
            verify_tooltip += f"输出: {verification.get('execution_output', 'N/A')[:50]}"
        if verification.get('error'):
            verify_tooltip += f"错误: {verification.get('error')}"
        verify_item.setToolTip(verify_tooltip)
        
        # 第6列：路径
        path = result.get('path_leaked') or ''
        path_item = QTableWidgetItem(path)
        path_item.setToolTip(path)
        
        # === 先添加所有 item 到表格 ===
        self.setItem(row, 0, filename_item)
        self.setItem(row, 1, type_item)
        self.setItem(row, 2, status_item)
        self.setItem(row, 3, status_text_item)
        self.setItem(row, 4, prob_item)
        self.setItem(row, 5, verify_item)  # 【新增】验证状态
        self.setItem(row, 6, path_item)
        
        # === 统一设置整行背景色（现在所有 item 都已存在） ===
        # 【修复】禁用交替行颜色，避免覆盖我们的自定义背景色
        self.setAlternatingRowColors(False)
        
        if is_vulnerability:
            bg_color = QColor(VULN_BG_COLOR)
            for col in range(self.columnCount()):
                self.item(row, col).setBackground(bg_color)
        elif is_success:
            bg_color = QColor(SUCCESS_BG_COLOR)
            for col in range(self.columnCount()):
                self.item(row, col).setBackground(bg_color)
        else:
            # 【修复】为普通行设置默认背景色
            for col in range(self.columnCount()):
                self.item(row, col).setBackground(QColor(COLORS['bg_secondary']))
        
        # 滚动到最新行
        self.scrollToBottom()
    
    def _show_context_menu(self, position):
        """显示右键菜单"""
        menu = QMenu(self)
        
        # 注意：扫描结果不提供 Repeater/Intruder 发送，因为请求响应数据不完整
        # 如需测试，请使用 Traffic 标签页中的完整请求
        
        menu.exec(self.viewport().mapToGlobal(position))
    
    def _get_selected_result(self):
        """获取当前选中的结果"""
        selected = self.selectedItems()
        if not selected:
            return None
        row = selected[0].row()
        item = self.item(row, 0)
        if item is None:
            return None
        return item.data(Qt.UserRole)
    
    def _send_result_to_repeater(self):
        """发送结果到Repeater"""
        result = self._get_selected_result()
        if result:
            self.send_to_repeater.emit(result)
    
    def _send_result_to_intruder(self):
        """发送结果到Intruder"""
        result = self._get_selected_result()
        if result:
            self.send_to_intruder.emit(result)


class FindingsTable(QTableWidget):
    """漏洞发现表格"""
    
    def __init__(self):
        super().__init__()
        self.setColumnCount(5)
        self.setHorizontalHeaderLabels(["漏洞名称", "风险等级", "置信度", "Payload", "URL"])
        
        self.setColumnWidth(0, 250)
        self.setColumnWidth(1, 80)
        self.setColumnWidth(2, 80)
        self.setColumnWidth(3, 150)
        
        header = self.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Stretch)
        header.setSectionResizeMode(4, QHeaderView.Stretch)
        
        self.verticalHeader().setVisible(False)
        self.setSelectionBehavior(QTableWidget.SelectRows)
        self.setEditTriggers(QTableWidget.NoEditTriggers)  # 【修复】禁用编辑
        self.setAlternatingRowColors(True)
        
        # 【修复】添加表格样式，移除选中边框
        self.setStyleSheet(f"""
            QTableWidget {{
                background-color: {COLORS['bg_secondary']};
                color: {COLORS['text_primary']};
                border: 1px solid {COLORS['border']};
                gridline-color: {COLORS['border']};
            }}
            QTableWidget::item {{
                padding: 4px 8px;
                border: none;
            }}
            QTableWidget::item:selected {{
                background-color: {COLORS['accent']};
                color: white;
                border: none;
                outline: none;
            }}
            QHeaderView::section {{
                background-color: {COLORS['bg_tertiary']};
                color: {COLORS['text_primary']};
                padding: 8px;
                border: none;
                border-right: 1px solid {COLORS['border']};
                border-bottom: 1px solid {COLORS['border']};
                font-weight: bold;
            }}
        """)
    
    def clear_results(self):
        self.setRowCount(0)
    
    def add_finding(self, finding: VulnerabilityFinding):
        row = self.rowCount()
        self.insertRow(row)
        
        # 漏洞名称
        name_item = QTableWidgetItem(finding.name)
        name_item.setData(Qt.UserRole, finding)
        self.setItem(row, 0, name_item)
        
        # 风险等级
        risk_item = QTableWidgetItem(finding.risk_level)
        if finding.risk_level == RISK_CRITICAL:
            risk_item.setForeground(QColor("#ff4757"))
        elif finding.risk_level == RISK_HIGH:
            risk_item.setForeground(QColor(COLORS['danger']))
        elif finding.risk_level == RISK_MEDIUM:
            risk_item.setForeground(QColor(COLORS['warning']))
        self.setItem(row, 1, risk_item)
        
        # 置信度
        self.setItem(row, 2, QTableWidgetItem(finding.confidence))
        
        # Payload
        payload_item = QTableWidgetItem(finding.payload)
        payload_item.setToolTip(finding.payload)
        self.setItem(row, 3, payload_item)
        
        # URL
        url_item = QTableWidgetItem(finding.url)
        url_item.setToolTip(finding.url)
        self.setItem(row, 4, url_item)
        
        self.scrollToBottom()


class DetailViewer(QPlainTextEdit):
    """带语法高亮的详情查看器"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFont(QFont("Consolas", 10))
        self.setReadOnly(True)
        self.setStyleSheet(f"""
            QPlainTextEdit {{
                background-color: {COLORS['bg_secondary']};
                color: {COLORS['text_primary']};
                border: 1px solid {COLORS['border']};
                border-radius: 4px;
                padding: 8px;
            }}
        """)
        # 添加语法高亮
        self.highlighter = HTTPHighlighter(self.document(), is_request=False)


class PayloadEditor(QPlainTextEdit):
    """Payload编辑器 - 支持WebShell语法高亮"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFont(QFont("Consolas", 10))
        self.setStyleSheet(f"""
            QPlainTextEdit {{
                background-color: {COLORS['bg_secondary']};
                color: {COLORS['text_primary']};
                border: 1px solid {COLORS['border']};
                border-radius: 4px;
                padding: 8px;
            }}
        """)
        # 添加语法高亮
        self.highlighter = WebShellHighlighter(self.document())


class MainWindow(QMainWindow):
    """主窗口类"""
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"UploadRanger - 文件上传漏洞测试工具 {CURRENT_VERSION}")
        self.resize(1315, 875)
        self.setMinimumSize(1200, 700)
        
        # 加载图标
        self._load_icon()
        
        # 初始化组件
        self.worker = None
        self.shell_generator = WebShellGenerator()
        self.bypass_generator = BypassPayloadGenerator()
        self.polyglot_generator = PolyglotGenerator()
        
        # 【新增】WebShell配置（渗透测试模式用）
        self._webshell_config = {
            "password": "UploadRanger",
            "type": "基础eval"
        }
        
        # 【新增】Diff对比功能 - 基准响应存储
        self.baseline_response = None
        
        # 创建UI
        self._create_ui()

        self._update_bridge = _UpdateCheckBridge(self)
        self._update_bridge.succeeded.connect(self._on_update_check_succeeded)
        self._update_bridge.failed.connect(self._on_update_check_failed)
        self._update_watchdog = QTimer(self)
        self._update_watchdog.setSingleShot(True)
        self._update_watchdog.timeout.connect(self._on_update_check_timeout)

        self._discover_bridge = _PageDiscoverBridge(self)
        self._discover_bridge.succeeded.connect(self._on_discover_uploads_succeeded)
        self._discover_bridge.failed.connect(self._on_discover_uploads_failed)

        # 【修复】连接关闭事件
        self.closeEvent = self._on_close_event
    
    def _load_icon(self):
        """加载应用图标"""
        icon_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "assets", "icon.png")
        if os.path.exists(icon_path):
            self.setWindowIcon(QIcon(icon_path))

    def _on_close_event(self, event):
        """窗口关闭前停止所有后台线程 - 修复卡顿问题"""
        # 【修复】先断开标签页切换信号，避免关闭时触发不必要的回调
        try:
            if hasattr(self, 'tabs') and self.tabs:
                self.tabs.currentChanged.disconnect(self._on_tab_changed)
        except Exception:
            pass
        
        self._log("正在关闭应用程序，停止所有后台线程...")
        
        try:
            # 1. 停止扫描worker线程 - 【修复】强制终止事件循环
            if hasattr(self, 'worker') and self.worker:
                if self.worker.isRunning():
                    self._log("正在停止扫描worker线程...")
                    self.worker.stop()
                    # 【修复】缩短等待时间，避免卡顿
                    if not self.worker.wait(1000):
                        self._log("警告: Worker线程停止超时，强制终止...")
                        # 【关键修复】强制终止线程
                        self.worker.terminate()
                        self.worker.wait(500)
                    self.worker = None
            
            # 2. 停止代理线程
            if hasattr(self, 'proxy_widget') and self.proxy_widget:
                self._log("正在停止代理线程...")
                try:
                    self.proxy_widget.stop_proxy()
                except Exception:
                    pass
            
            # 3. 停止Repeater和Intruder中的worker - 【修复】强制终止
            try:
                if hasattr(self, 'repeater') and self.repeater:
                    for i in range(self.repeater.content_stack.count()):
                        tab = self.repeater.content_stack.widget(i)
                        if hasattr(tab, 'worker') and tab.worker:
                            if tab.worker.isRunning():
                                tab.worker.terminate()
                                tab.worker.wait(300)
            except Exception:
                pass
            
            try:
                if hasattr(self, 'intruder') and self.intruder:
                    for i in range(self.intruder.content_stack.count()):
                        tab = self.intruder.content_stack.widget(i)
                        if hasattr(tab, 'worker') and tab.worker:
                            if tab.worker.isRunning():
                                tab.worker.terminate()
                                tab.worker.wait(300)
            except Exception:
                pass
            
            # 4. 停止任何定时器
            if hasattr(self, '_update_watchdog') and self._update_watchdog:
                self._update_watchdog.stop()
            
            self._log("所有后台线程已停止")
            
        except Exception as e:
            print(f"[MainWindow] 关闭时出错: {e}")
        
        # 【修复】接受关闭事件，强制退出
        event.accept()
        # 【修复】强制退出应用程序
        from PySide6.QtWidgets import QApplication
        QApplication.instance().quit()
    
    def _create_ui(self):
        """创建UI界面"""
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
        # 创建标题栏
        self._create_header(main_layout)
        
        # 创建标签页
        self._create_tabs(main_layout)
        
        # 创建状态栏
        self._create_status_bar()
    
    def _create_header(self, parent_layout):
        """创建标题栏"""
        header = QWidget()
        header.setFixedHeight(60)
        header.setStyleSheet(f"background-color: {COLORS['bg_secondary']}; border-bottom: 2px solid {COLORS['accent']};")
        
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(20, 0, 20, 0)
        
        title_label = QLabel("UploadRanger")
        title_label.setStyleSheet(f"font-size: 24px; font-weight: bold; color: {COLORS['accent']};")
        header_layout.addWidget(title_label)
        
        subtitle = QLabel("文件上传漏洞测试工具")
        subtitle.setStyleSheet(f"color: {COLORS['text_secondary']}; margin-left: 10px; font-size: 14px;")
        header_layout.addWidget(subtitle)
        
        header_layout.addStretch()
        
        header_wiz = QPushButton("扫描向导")
        header_wiz.setFixedHeight(32)
        header_wiz.setToolTip("打开快速向导，填写上传 URL 与参数（与扫描页「快速向导」相同）")
        header_wiz.setCursor(Qt.PointingHandCursor)
        header_wiz.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['bg_tertiary']};
                color: {COLORS['text_primary']};
                border: 1px solid {COLORS['border']};
                border-radius: 4px;
                padding: 4px 12px;
            }}
            QPushButton:hover {{
                background-color: {COLORS['accent']};
                color: white;
            }}
        """)
        header_wiz.clicked.connect(self._open_scan_wizard)
        header_layout.addWidget(header_wiz)
        
        # 检查更新按钮
        self.check_update_btn = QPushButton("检查更新")
        self.check_update_btn.setFixedHeight(32)
        self.check_update_btn.setToolTip("检查GitHub最新版本")
        self.check_update_btn.setCursor(Qt.PointingHandCursor)
        self.check_update_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['bg_tertiary']};
                color: {COLORS['text_primary']};
                border: 1px solid {COLORS['border']};
                border-radius: 4px;
                padding: 4px 12px;
            }}
            QPushButton:hover {{
                background-color: #4CAF50;
                color: white;
                border-color: #4CAF50;
            }}
        """)
        self.check_update_btn.clicked.connect(self._check_for_updates)
        header_layout.addWidget(self.check_update_btn)
        
        # GitHub按钮
        self.github_btn = QPushButton("GitHub")
        self.github_btn.setFixedHeight(32)
        self.github_btn.setToolTip("访问GitHub项目主页")
        self.github_btn.setCursor(Qt.PointingHandCursor)
        self.github_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['bg_tertiary']};
                color: {COLORS['text_primary']};
                border: 1px solid {COLORS['border']};
                border-radius: 4px;
                padding: 4px 12px;
                font-weight: bold;
            }}
            QPushButton:hover {{
                background-color: {COLORS['accent']};
                color: white;
                border-color: {COLORS['accent']};
            }}
        """)
        self.github_btn.clicked.connect(self._open_github)
        header_layout.addWidget(self.github_btn)
        
        version = QLabel(f"v{CURRENT_VERSION}")
        version.setStyleSheet(f"color: {COLORS['text_secondary']}; margin-right: 15px; margin-left: 10px;")
        header_layout.addWidget(version)
        
        author = QLabel("by bae")
        author.setStyleSheet(f"color: {COLORS['accent']}; font-weight: bold;")
        header_layout.addWidget(author)
        
        parent_layout.addWidget(header)
    
    def reset_tabs(self):
        """重置标签页 - 用于修复标签页消失问题"""
        try:
            # 使用安全的方式记录日志
            reset_msg = "正在重置标签页..."
            print(f"[UploadRanger] {reset_msg}")
            if hasattr(self, 'log_text') and self.log_text:
                self.log_text.append(f"[{datetime.now().strftime('%H:%M:%S')}] {reset_msg}")
            
            current_index = self.tabs.currentIndex()
            
            # 记录当前各个标签页的状态
            tab_states = {}
            for i in range(self.tabs.count()):
                tab_text = self.tabs.tabText(i)
                tab_widget = self.tabs.widget(i)
                if tab_widget:
                    tab_states[tab_text] = tab_widget
            
            # 清除所有标签页
            while self.tabs.count() > 0:
                self.tabs.removeTab(0)
            
            # 重新创建所有标签页
            self._create_scan_tab()
            self._create_traffic_tab()
            self._create_proxy_tab()
            self._create_repeater_tab()
            self._create_intruder_tab()
            self._create_payload_tab()
            self._create_bypass_tab()
            self._create_polyglot_tab()
            self._create_logs_tab()
            self._create_about_tab()
            
            # 恢复之前的选中状态
            if current_index < self.tabs.count():
                self.tabs.setCurrentIndex(current_index)
            
            success_msg = "标签页重置完成"
            print(f"[UploadRanger] {success_msg}")
            if hasattr(self, 'log_text') and self.log_text:
                self.log_text.append(f"[{datetime.now().strftime('%H:%M:%S')}] {success_msg}")
            
        except Exception as e:
            error_msg = f"重置标签页失败: {str(e)}"
            print(f"[UploadRanger] {error_msg}")
            if hasattr(self, 'log_text') and self.log_text:
                self.log_text.append(f"[{datetime.now().strftime('%H:%M:%S')}] {error_msg}")
            QMessageBox.warning(self, "重置失败", f"标签页重置失败: {str(e)}")
    
    def _check_for_updates(self):
        """检查 GitHub 最新版本（工作线程仅发信号，避免界面永久停在「检查中」）。"""
        if self.check_update_btn.text() == "检查中...":
            return
        self.check_update_btn.setEnabled(False)
        self.check_update_btn.setText("检查中...")
        self._update_watchdog.start(20000)

        bridge = self._update_bridge
        ua_ver = CURRENT_VERSION

        def fetch_version():
            err = None
            latest_version = ""
            download_url = GITHUB_REPO_URL
            try:
                req = Request(
                    GITHUB_API_URL,
                    headers={"User-Agent": f"UploadRanger/{ua_ver}"},
                )
                ctx = ssl.create_default_context()
                with urlopen(req, timeout=12, context=ctx) as response:
                    raw = response.read()
                data = json.loads(raw.decode("utf-8"))
                latest_version = (data.get("tag_name") or "").lstrip("v")
                download_url = data.get("html_url") or GITHUB_REPO_URL
                if not latest_version:
                    err = "GitHub API 未返回有效 tag_name"
            except (URLError, HTTPError, json.JSONDecodeError, OSError, ValueError) as e:
                err = str(e)
            except Exception as e:
                err = str(e)
            if err:
                bridge.failed.emit(err)
            else:
                bridge.succeeded.emit(latest_version, download_url)

        Thread(target=fetch_version, daemon=True).start()

    def _on_update_check_succeeded(self, latest_version: str, download_url: str):
        self._update_watchdog.stop()
        if self.check_update_btn.text() != "检查中...":
            return
        self._show_update_result(latest_version, download_url)

    def _on_update_check_failed(self, error_msg: str):
        self._update_watchdog.stop()
        if self.check_update_btn.text() != "检查中...":
            return
        self._show_update_error(error_msg)

    def _on_update_check_timeout(self):
        if self.check_update_btn.text() != "检查中...":
            return
        self.check_update_btn.setEnabled(True)
        self.check_update_btn.setText("检查更新")
        QMessageBox.warning(
            self,
            "检查更新超时",
            "请求超过 20 秒未完成。\n请检查网络、系统代理或防火墙；若使用抓包代理，请尝试暂时关闭后再检查。",
        )
    
    def _show_update_result(self, latest_version: str, download_url: str):
        """【修复】在主线程安全显示版本更新结果"""
        self.check_update_btn.setEnabled(True)
        self.check_update_btn.setText("检查更新")

        if not (latest_version or "").strip():
            QMessageBox.warning(
                self,
                "检查更新",
                "未能解析远程版本号，请到 GitHub Release 页面手动查看。",
            )
            return
        
        if self._compare_versions(latest_version, CURRENT_VERSION) > 0:
            msg_box = QMessageBox(self)
            msg_box.setWindowTitle("发现新版本")
            msg_box.setIcon(QMessageBox.Information)
            msg_box.setText(f"当前版本: v{CURRENT_VERSION}\n最新版本: v{latest_version}")
            msg_box.setInformativeText("是否前往GitHub下载最新版本？")
            msg_box.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
            msg_box.setDefaultButton(QMessageBox.Yes)
            if msg_box.exec() == QMessageBox.Yes:
                webbrowser.open(download_url)
        else:
            QMessageBox.information(
                self, 
                "已是最新版本", 
                f"当前版本 v{CURRENT_VERSION} 已是最新版本！"
            )
    
    def _show_update_error(self, error_msg: str):
        """【修复】在主线程安全显示版本更新错误"""
        self.check_update_btn.setEnabled(True)
        self.check_update_btn.setText("检查更新")
        QMessageBox.warning(
            self,
            "检查更新失败",
            f"无法检查更新:\n{error_msg}\n\n请检查网络连接后重试。"
        )
    
    def _compare_versions(self, v1: str, v2: str) -> int:
        """
        比较两个版本号
        返回: 1 if v1 > v2, -1 if v1 < v2, 0 if equal
        """
        def parse(v):
            return [int(x) for x in re.findall(r'\d+', v)]
        
        v1_parts = parse(v1)
        v2_parts = parse(v2)
        
        # 补齐长度
        max_len = max(len(v1_parts), len(v2_parts))
        v1_parts += [0] * (max_len - len(v1_parts))
        v2_parts += [0] * (max_len - len(v2_parts))
        
        for p1, p2 in zip(v1_parts, v2_parts):
            if p1 > p2:
                return 1
            elif p1 < p2:
                return -1
        return 0

    def _discover_upload_endpoints(self):
        """拉取页面 HTML，合并表单与 JS 推测的上传端点。"""
        page_url = self.url_input.text().strip()
        if not page_url:
            QMessageBox.information(self, "提示", "请先填写要分析的页面 URL。")
            return
        self.discover_upload_btn.setEnabled(False)
        bridge = self._discover_bridge

        def work():
            try:
                req = Request(
                    page_url,
                    headers={
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
                    },
                )
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with urlopen(req, timeout=20, context=ctx) as resp:
                    html = resp.read().decode("utf-8", errors="replace")
                items = FormParser.collect_upload_hints(page_url, html)
                bridge.succeeded.emit(items)
            except Exception as e:
                bridge.failed.emit(str(e))

        Thread(target=work, daemon=True).start()

    def _on_discover_uploads_succeeded(self, items: list):
        self.discover_upload_btn.setEnabled(True)
        if not items:
            QMessageBox.information(
                self,
                "发现上传点",
                "未找到候选上传端点。\n可尝试填写上传页、个人中心头像页或含 <input type=file> 的页面 URL。",
            )
            return
        if len(items) == 1:
            picked = items[0]
            self.url_input.setText(picked.get("url") or "")
            ff = (picked.get("file_field") or "file").strip()
            if ff:
                self.param_input.setCurrentText(ff)
            self._log(f"[发现上传点] {picked.get('label', picked.get('url', ''))}")
            return
        labels = []
        for i, it in enumerate(items):
            lab = it.get("label") or f"候选{i}"
            if lab in labels:
                lab = f"{lab} ({i})"
            labels.append(lab)
        choice, ok = QInputDialog.getItem(
            self,
            "选择上传点",
            "选择一项填入「目标 URL」与「文件参数名」:",
            labels,
            0,
            False,
        )
        if not ok:
            return
        idx = labels.index(choice)
        picked = items[idx]
        self.url_input.setText(picked.get("url") or "")
        ff = (picked.get("file_field") or "file").strip()
        if ff:
            self.param_input.setCurrentText(ff)
        self._log(f"[发现上传点] {picked.get('label', '')}")

    def _on_discover_uploads_failed(self, msg: str):
        self.discover_upload_btn.setEnabled(True)
        QMessageBox.warning(self, "发现上传点失败", msg)
    
    def _open_extension_selector(self):
        """打开后缀选择对话框"""
        # 获取当前选择的后缀
        current_exts = self._selected_extensions
        
        dialog = ExtensionSelectorDialog(self, current_exts)
        if dialog.exec():
            selected = dialog.get_selected_extensions()
            self._selected_extensions = selected if selected else None
            self._update_extension_label()
            self._update_payload_hint()
            # 根据后缀数量动态计算 payload 上限
            ext_count = len(selected) if selected else 0
            suggested_limit = min(ext_count * 50, 1200)  # 每个后缀50个payload，上限1200
            if suggested_limit > 0:
                self.payload_limit_spin.setValue(suggested_limit)
    
    def _update_extension_label(self):
        """更新后缀选择标签"""
        if self._selected_extensions is None:
            self.ext_count_label.setText("已选: 全部")
        else:
            count = len(self._selected_extensions)
            # 显示前3个后缀
            preview = ", ".join(self._selected_extensions[:3])
            if count > 3:
                preview += f" 等{count}个"
            self.ext_count_label.setText(f"已选: {preview}")
    
    def _on_scan_mode_changed(self):
        """测试模式切换处理"""
        is_penetration = self.penetration_test_rb.isChecked()
        
        # 启用/禁用Shell设置按钮
        self.webshell_settings_btn.setEnabled(is_penetration)
        
        # 更新payload提示
        if is_penetration:
            self._log("[渗透测试模式] 将上传WebShell等攻击载荷")
            config = self._webshell_config
            self._log(f"  - WebShell密码: {config['password']}")
            self._log(f"  - Shell类型: {config['type']}")
        else:
            self._log("[安全测试模式] 将上传无害内容，仅证明漏洞存在")
    
    def _open_webshell_settings(self):
        """打开WebShell设置对话框"""
        dialog = WebShellSettingsDialog(
            self,
            password=self._webshell_config['password'],
            shell_type=self._webshell_config['type']
        )
        if dialog.exec():
            self._webshell_config = dialog.get_config()
            self._log(f"[Shell设置] 密码: {self._webshell_config['password']}, 类型: {self._webshell_config['type']}")
    
    def _get_scan_mode(self):
        """获取当前扫描模式"""
        return "penetration" if self.penetration_test_rb.isChecked() else "security"
    
    def _get_webshell_config(self):
        """获取WebShell配置"""
        if self.penetration_test_rb.isChecked():
            return {
                "enabled": True,
                "password": self._webshell_config['password'],
                "type": self._webshell_config['type']
            }
        return {"enabled": False}
    
    def _update_payload_hint(self):
        """根据选择的后缀更新payload数量提示"""
        if self._selected_extensions is None:
            self.ext_count_label.setText("全部")
        else:
            count = len(self._selected_extensions)
            self.ext_count_label.setText(f"已选{count}个")
    
    def _get_selected_extensions(self):
        """获取用户选择的后缀列表"""
        if self._selected_extensions is None:
            # 返回所有后缀
            all_exts = []
            for group in ExtensionSelectorDialog.EXTENSION_GROUPS.values():
                all_exts.extend(group)
            return ["." + ext for ext in all_exts]
        return ["." + ext for ext in self._selected_extensions]
    
    def _create_tabs(self, parent_layout):
        """创建标签页"""
        self.tabs = QTabWidget()
        parent_layout.addWidget(self.tabs)
        
        # 扫描标签
        self._create_scan_tab()
        
        # 流量查看标签
        self._create_traffic_tab()
        
        # 代理标签 (放在Repeater和Intruder前面)
        self._create_proxy_tab()
        
        # Repeater标签
        self._create_repeater_tab()
        
        # Intruder标签
        self._create_intruder_tab()
        
        # Payload生成器标签
        self._create_payload_tab()
        
        # 绕过技术标签
        self._create_bypass_tab()
        
        # Polyglot标签
        self._create_polyglot_tab()
        
        # 日志标签
        self._create_logs_tab()
        
        # 关于标签
        self._create_about_tab()
        
        # 确保核心标签页可见
        self._ensure_core_tabs_visible()
        
        # 连接标签页变化信号，用于调试
        self.tabs.currentChanged.connect(self._on_tab_changed)
    
    def _ensure_core_tabs_visible(self):
        """确保核心功能标签页可见"""
        core_tabs = ["扫描", "请求/响应", "代理", "Repeater", "Intruder"]
        visible_tabs = []
        
        for i in range(self.tabs.count()):
            tab_text = self.tabs.tabText(i)
            visible_tabs.append(tab_text)
        
        missing_tabs = [tab for tab in core_tabs if tab not in visible_tabs]
        if missing_tabs:
            warning_msg = f"警告: 缺少标签页: {missing_tabs}"
            print(f"[UploadRanger] {warning_msg}")
            if hasattr(self, 'log_text') and self.log_text:
                self.log_text.append(f"[{datetime.now().strftime('%H:%M:%S')}] {warning_msg}")
    
    def _on_tab_changed(self, index):
        """标签页切换事件"""
        if index >= 0:
            tab_text = self.tabs.tabText(index)
            # 使用安全的方式记录标签切换
            log_msg = f"切换到标签页: {tab_text}"
            if hasattr(self, 'log_text') and self.log_text:
                self.log_text.append(f"[{datetime.now().strftime('%H:%M:%S')}] {log_msg}")
            else:
                print(f"[UploadRanger] {log_msg}")
    
    def _create_scan_tab(self):
        """创建扫描标签页"""
        scan_tab = QWidget()
        layout = QHBoxLayout(scan_tab)
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(15)
        
        # 左侧配置面板
        left_panel = QWidget()
        left_panel.setFixedWidth(380)
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(15)
        
        # 目标配置组
        target_group = QGroupBox("目标配置")
        target_layout = QFormLayout(target_group)
        target_layout.setSpacing(10)
        
        url_row = QHBoxLayout()
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("http://example.com/upload.php 或含上传控件的页面")
        url_row.addWidget(self.url_input, 1)
        self.discover_upload_btn = QPushButton("发现上传点")
        self.discover_upload_btn.setToolTip(
            "GET 当前 URL 对应页面，解析 HTML 表单与内联 JS 中的可疑上传接口（实验性，需授权测试）"
        )
        self.discover_upload_btn.setCursor(Qt.PointingHandCursor)
        self.discover_upload_btn.clicked.connect(self._discover_upload_endpoints)
        url_row.addWidget(self.discover_upload_btn)
        target_layout.addRow("目标 URL:", url_row)
        
        self.param_input = QComboBox()
        self.param_input.setEditable(True)
        self.param_input.setInsertPolicy(QComboBox.InsertPolicy.NoInsert)
        self.param_input.setMinimumWidth(200)
        for _name in (
            "file",
            "upload",
            "file_upload",
            "uploadfile",
            "img",
            "image",
            "pic",
            "picture",
            "photo",
            "attachment",
            "multipartFile",
            "data",
        ):
            self.param_input.addItem(_name)
        self.param_input.setCurrentText("file")
        target_layout.addRow("文件参数名:", self.param_input)
        
        self.upload_dir_input = QLineEdit()
        self.upload_dir_input.setPlaceholderText("http://example.com/uploads/ (可选)")
        target_layout.addRow("上传目录:", self.upload_dir_input)
        
        self.cookie_input = QLineEdit()
        self.cookie_input.setPlaceholderText("session=xxx; token=yyy")
        target_layout.addRow("Cookie:", self.cookie_input)
        
        left_layout.addWidget(target_group)
        
        # 代理配置 - 【简化】一行显示
        proxy_row = QHBoxLayout()
        proxy_row.addWidget(QLabel("代理:"))
        self.use_proxy_cb = QCheckBox("启用")
        self.use_proxy_cb.setToolTip("使用HTTP代理")
        proxy_row.addWidget(self.use_proxy_cb)
        self.proxy_input = QLineEdit()
        self.proxy_input.setPlaceholderText("127.0.0.1:8080")
        self.proxy_input.setFixedWidth(150)
        proxy_row.addWidget(self.proxy_input)
        proxy_row.addStretch()
        left_layout.addLayout(proxy_row)
        
        # 扫描选项组 - 【优化】紧凑布局
        options_group = QGroupBox("扫描选项")
        options_layout = QVBoxLayout(options_group)
        
        # 第一行：测试模式 + WebShell设置按钮
        mode_row = QHBoxLayout()
        mode_row.addWidget(QLabel("模式:"))
        
        self.scan_mode_group = QButtonGroup()
        self.security_test_rb = QRadioButton("安全")
        self.security_test_rb.setToolTip("上传无害内容，仅证明漏洞存在")
        self.security_test_rb.setChecked(True)
        self.penetration_test_rb = QRadioButton("渗透")
        self.penetration_test_rb.setToolTip("上传WebShell（需授权）")
        
        self.scan_mode_group.addButton(self.security_test_rb, 1)
        self.scan_mode_group.addButton(self.penetration_test_rb, 2)
        
        mode_row.addWidget(self.security_test_rb)
        mode_row.addWidget(self.penetration_test_rb)
        
        # WebShell设置按钮（仅渗透模式可用）
        self.webshell_settings_btn = QPushButton("Shell设置")
        self.webshell_settings_btn.setFixedWidth(110)  # 修复按钮显示不全
        self.webshell_settings_btn.setEnabled(False)
        self.webshell_settings_btn.setToolTip("设置WebShell密码和类型")
        self.webshell_settings_btn.clicked.connect(self._open_webshell_settings)
        mode_row.addWidget(self.webshell_settings_btn)
        
        mode_row.addStretch()
        options_layout.addLayout(mode_row)
        
        # 连接模式切换信号
        self.security_test_rb.toggled.connect(self._on_scan_mode_changed)
        self.penetration_test_rb.toggled.connect(self._on_scan_mode_changed)
        
        # 第二行：超时和Payload上限（单行紧凑）
        config_row = QHBoxLayout()
        config_row.addWidget(QLabel("超时:"))
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(5, 300)
        self.timeout_spin.setValue(30)
        self.timeout_spin.setFixedWidth(70)
        config_row.addWidget(self.timeout_spin)
        
        config_row.addSpacing(10)
        config_row.addWidget(QLabel("Payload上限:"))
        self.payload_limit_spin = QSpinBox()
        self.payload_limit_spin.setRange(10, 2000)
        _lib_n = get_builtin_async_payload_count()
        self.payload_limit_spin.setValue(min(1200, max(60, _lib_n)))
        self.payload_limit_spin.setFixedWidth(90)  # 修复输入框显示不全
        self.payload_limit_spin.setToolTip(
            f"内置词库约 {_lib_n} 条，实际请求数 ≤ min(上限, 词库)"
        )
        config_row.addWidget(self.payload_limit_spin)
        config_row.addStretch()
        options_layout.addLayout(config_row)
        
        # 第三行：选项复选框
        options_row = QHBoxLayout()
        self.use_raw_upload_cb = QCheckBox("Raw上传")
        self.use_raw_upload_cb.setChecked(True)
        self.use_raw_upload_cb.setToolTip("字节级Raw multipart上传（推荐）")
        options_row.addWidget(self.use_raw_upload_cb)
        
        self.use_fingerprint_cb = QCheckBox("指纹过滤")
        self.use_fingerprint_cb.setChecked(True)
        self.use_fingerprint_cb.setToolTip("环境指纹过滤与排序（推荐）")
        options_row.addWidget(self.use_fingerprint_cb)
        
        options_row.addStretch()  # 先stretch，为按钮留出空间
        
        # 后缀选择按钮
        self.ext_select_btn = QPushButton("后缀选择")
        self.ext_select_btn.setFixedWidth(110)  # 修复按钮显示不全
        self.ext_select_btn.setCursor(Qt.PointingHandCursor)
        self.ext_select_btn.clicked.connect(self._open_extension_selector)
        options_row.addWidget(self.ext_select_btn)
        
        self.ext_count_label = QLabel("全部")
        self.ext_count_label.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 12px;")
        options_row.addWidget(self.ext_count_label)
        options_layout.addLayout(options_row)
        
        # 初始化后缀选择器
        self._selected_extensions = None  # None表示全选
        
        left_layout.addWidget(options_group)
        
        # 控制按钮
        btn_layout = QHBoxLayout()
        
        self.start_btn = QPushButton("开始扫描")
        self.start_btn.setObjectName("success")
        self.start_btn.setCursor(Qt.PointingHandCursor)
        self.start_btn.setFixedHeight(45)
        self.start_btn.clicked.connect(self._start_scan)
        btn_layout.addWidget(self.start_btn)
        
        self.stop_btn = QPushButton("停止")
        self.stop_btn.setObjectName("danger")
        self.stop_btn.setCursor(Qt.PointingHandCursor)
        self.stop_btn.setFixedHeight(45)
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self._stop_scan)
        btn_layout.addWidget(self.stop_btn)
        
        left_layout.addLayout(btn_layout)
        
        # 进度条
        self.progress_bar = QProgressBar()
        self.progress_bar.setTextVisible(True)
        left_layout.addWidget(self.progress_bar)
        
        self.progress_label = QLabel("就绪")
        self.progress_label.setStyleSheet(f"color: {COLORS['text_secondary']};")
        left_layout.addWidget(self.progress_label)
        
        left_layout.addStretch()
        
        # 右侧结果面板 - 使用垂直分割器
        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(0, 0, 0, 0)
        
        # 垂直分割器
        splitter = QSplitter(Qt.Vertical)
        
        # 上半部分: 扫描结果表格
        results_widget = QWidget()
        results_layout = QVBoxLayout(results_widget)
        results_layout.setContentsMargins(0, 0, 0, 0)
        
        results_header = QHBoxLayout()
        results_label = QLabel("扫描结果")
        results_label.setStyleSheet(f"font-weight: bold; color: {COLORS['accent']};")
        results_header.addWidget(results_label)
        
        # 【新增】跳转到成功响应按钮
        jump_success_btn = QPushButton("跳转到成功项")
        jump_success_btn.setFixedWidth(100)
        jump_success_btn.setToolTip("自动滚动到第一个成功的响应")
        jump_success_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['success']};
                color: white;
                border: none;
                border-radius: 4px;
                padding: 4px 8px;
            }}
            QPushButton:hover {{
                background-color: #45a049;
            }}
        """)
        jump_success_btn.clicked.connect(self._jump_to_first_success)
        results_header.addWidget(jump_success_btn)
        
        clear_results_btn = QPushButton("清除")
        clear_results_btn.setFixedWidth(80)
        clear_results_btn.clicked.connect(self._clear_results)
        results_header.addWidget(clear_results_btn)
        
        results_layout.addLayout(results_header)
        
        self.results_table = ResultsTable()
        self.results_table.itemClicked.connect(self._on_result_selected)
        self.results_table.send_to_repeater.connect(self._load_to_repeater)
        self.results_table.send_to_intruder.connect(self._load_to_intruder)
        results_layout.addWidget(self.results_table)
        
        splitter.addWidget(results_widget)
        
        # 下半部分: 漏洞发现和详情
        vulns_widget = QWidget()
        vulns_layout = QVBoxLayout(vulns_widget)
        vulns_layout.setContentsMargins(0, 0, 0, 0)
        
        vulns_header = QHBoxLayout()
        vulns_label = QLabel("漏洞发现")
        vulns_label.setStyleSheet(f"font-weight: bold; color: {COLORS['accent']};")
        vulns_header.addWidget(vulns_label)
        
        clear_vulns_btn = QPushButton("清除")
        clear_vulns_btn.setFixedWidth(80)
        clear_vulns_btn.clicked.connect(self._clear_findings)
        vulns_header.addWidget(clear_vulns_btn)
        
        vulns_layout.addLayout(vulns_header)
        
        self.findings_table = FindingsTable()
        self.findings_table.itemClicked.connect(self._on_finding_selected)
        vulns_layout.addWidget(self.findings_table)
        
        # 详情区域 - 使用带语法高亮的查看器
        details_group = QGroupBox("详细信息 (带语法高亮)")
        details_layout = QVBoxLayout(details_group)
        
        self.details_text = DetailViewer()
        self.details_text.setMaximumHeight(200)
        details_layout.addWidget(self.details_text)
        
        vulns_layout.addWidget(details_group)
        
        splitter.addWidget(vulns_widget)
        
        # 设置分割器比例
        splitter.setSizes([350, 450])
        
        right_layout.addWidget(splitter)
        
        layout.addWidget(left_panel)
        layout.addWidget(right_panel)
        
        self.tabs.addTab(scan_tab, "扫描")
    
    def _create_traffic_tab(self):
        """创建流量查看标签页"""
        self.traffic_viewer = TrafficViewer()
        self.traffic_viewer.send_to_repeater.connect(self._load_to_repeater)
        self.traffic_viewer.send_to_intruder.connect(self._load_to_intruder)
        self.tabs.addTab(self.traffic_viewer, "请求/响应")
    
    def _create_repeater_tab(self):
        """创建Repeater标签页 - 修复版本"""
        try:
            self.repeater = RepeaterWidget()
            self.tabs.addTab(self.repeater, "Repeater")
            # 延迟日志记录，确保不会干扰创建过程
            QTimer.singleShot(100, lambda: self._log("已创建Repeater标签页"))
        except Exception as e:
            error_msg = f"创建Repeater标签页失败: {str(e)}"
            import traceback
            print(f"[MainWindow] {error_msg}")
            print(f"[MainWindow] 详细错误: {traceback.format_exc()}")
            # 创建备用空白标签页
            fallback_widget = QWidget()
            fallback_layout = QVBoxLayout(fallback_widget)
            fallback_layout.addWidget(QLabel(f"Repeater模块加载失败:\n{str(e)}\n\n请检查控制台输出获取详细信息。"))
            self.tabs.addTab(fallback_widget, "Repeater(错误)")
            QTimer.singleShot(100, lambda: self._log(error_msg))
    
    def _create_intruder_tab(self):
        """创建Intruder标签页 - 修复版本"""
        try:
            self.intruder = IntruderWidget()
            self.tabs.addTab(self.intruder, "Intruder")
            # 延迟日志记录，确保不会干扰创建过程
            QTimer.singleShot(100, lambda: self._log("已创建Intruder标签页"))
        except Exception as e:
            error_msg = f"创建Intruder标签页失败: {str(e)}"
            import traceback
            print(f"[MainWindow] {error_msg}")
            print(f"[MainWindow] 详细错误: {traceback.format_exc()}")
            # 创建备用空白标签页
            fallback_widget = QWidget()
            fallback_layout = QVBoxLayout(fallback_widget)
            fallback_layout.addWidget(QLabel(f"Intruder模块加载失败:\n{str(e)}\n\n请检查控制台输出获取详细信息。"))
            self.tabs.addTab(fallback_widget, "Intruder(错误)")
            QTimer.singleShot(100, lambda: self._log(error_msg))
    
    def _create_payload_tab(self):
        """创建Payload生成器标签页"""
        payload_tab = QWidget()
        layout = QVBoxLayout(payload_tab)
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(15)
        
        control_layout = QHBoxLayout()
        
        control_layout.addWidget(QLabel("语言:"))
        self.payload_lang_combo = QComboBox()
        self.payload_lang_combo.addItems(["PHP", "ASP", "JSP", "Python", "Perl"])
        self.payload_lang_combo.currentTextChanged.connect(self._update_payload_types)
        control_layout.addWidget(self.payload_lang_combo)
        
        control_layout.addWidget(QLabel("Shell类型:"))
        self.payload_type_combo = QComboBox()
        self.payload_type_combo.setMinimumWidth(200)
        control_layout.addWidget(self.payload_type_combo)
        
        control_layout.addStretch()
        
        generate_btn = QPushButton("生成")
        generate_btn.setObjectName("success")
        generate_btn.clicked.connect(self._generate_payload)
        control_layout.addWidget(generate_btn)
        
        batch_btn = QPushButton("批量生成")
        batch_btn.clicked.connect(self._batch_generate_payloads)
        control_layout.addWidget(batch_btn)
        
        copy_btn = QPushButton("复制")
        copy_btn.clicked.connect(self._copy_payload)
        control_layout.addWidget(copy_btn)
        
        save_btn = QPushButton("保存")
        save_btn.clicked.connect(self._save_payload)
        control_layout.addWidget(save_btn)
        
        layout.addLayout(control_layout)
        
        self.payload_code = PayloadEditor()
        self.payload_code.setPlaceholderText("选择语言和类型后点击生成...")
        layout.addWidget(self.payload_code)
        
        self._update_payload_types()
        
        self.tabs.addTab(payload_tab, "Payload生成器")
    
    def _create_bypass_tab(self):
        """创建绕过技术标签页"""
        bypass_tab = QWidget()
        layout = QVBoxLayout(bypass_tab)
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(15)
        
        input_layout = QHBoxLayout()
        
        input_layout.addWidget(QLabel("基础文件名:"))
        self.bypass_filename = QLineEdit("shell")
        self.bypass_filename.setFixedWidth(120)
        input_layout.addWidget(self.bypass_filename)
        
        input_layout.addWidget(QLabel("扩展名:"))
        self.bypass_ext = QLineEdit(".php")
        self.bypass_ext.setFixedWidth(80)
        input_layout.addWidget(self.bypass_ext)
        
        generate_btn = QPushButton("生成")
        generate_btn.setObjectName("success")
        generate_btn.clicked.connect(self._generate_bypass)
        input_layout.addWidget(generate_btn)
        
        export_btn = QPushButton("导出字典")
        export_btn.clicked.connect(self._export_bypass)
        input_layout.addWidget(export_btn)
        
        input_layout.addStretch()
        
        layout.addLayout(input_layout)
        
        self.bypass_table = QTableWidget()
        self.bypass_table.setColumnCount(4)
        self.bypass_table.setHorizontalHeaderLabels(["文件名", "技术", "严重程度", "描述"])
        self.bypass_table.setColumnWidth(0, 250)
        self.bypass_table.setColumnWidth(1, 120)
        self.bypass_table.setColumnWidth(2, 80)
        self.bypass_table.horizontalHeader().setStretchLastSection(True)
        self.bypass_table.verticalHeader().setVisible(False)
        self.bypass_table.setAlternatingRowColors(True)
        
        # 设置选中样式，防止边框覆盖文字
        self.bypass_table.setStyleSheet(f"""
            QTableWidget {{
                gridline-color: {COLORS['border']};
                outline: none;
            }}
            QTableWidget::item {{
                padding: 6px 10px;
                border: none;
            }}
            QTableWidget::item:selected {{
                background-color: {COLORS['accent']};
                color: white;
                border: none;
            }}
            QTableWidget::item:focus {{
                border: none;
                outline: none;
            }}
            QTableWidget::item:selected:!active {{
                background-color: {COLORS['accent']};
                color: white;
            }}
        """)
        
        # 禁用编辑，避免双击进入编辑模式
        self.bypass_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        
        layout.addWidget(self.bypass_table)
        
        self.tabs.addTab(bypass_tab, "绕过技术")
    
    def _create_polyglot_tab(self):
        """创建Polyglot标签页"""
        polyglot_tab = QWidget()
        layout = QVBoxLayout(polyglot_tab)
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(15)
        
        control_layout = QHBoxLayout()
        
        control_layout.addWidget(QLabel("类型:"))
        self.polyglot_type = QComboBox()
        self.polyglot_type.setMinimumWidth(200)
        
        polyglots = self.polyglot_generator.get_all_polyglots()
        for key, info in polyglots.items():
            self.polyglot_type.addItem(info['name'], key)
        
        control_layout.addWidget(self.polyglot_type)
        
        control_layout.addWidget(QLabel("PHP代码:"))
        self.polyglot_code = QLineEdit("<?php phpinfo(); ?>")
        self.polyglot_code.setMinimumWidth(300)
        control_layout.addWidget(self.polyglot_code)
        
        control_layout.addStretch()
        
        generate_btn = QPushButton("生成")
        generate_btn.setObjectName("success")
        generate_btn.clicked.connect(self._generate_polyglot)
        control_layout.addWidget(generate_btn)
        
        save_btn = QPushButton("保存")
        save_btn.clicked.connect(self._save_polyglot)
        control_layout.addWidget(save_btn)
        
        layout.addLayout(control_layout)
        
        self.polyglot_info = QLabel("选择类型并点击生成...")
        self.polyglot_info.setStyleSheet(f"color: {COLORS['text_secondary']}; padding: 10px;")
        layout.addWidget(self.polyglot_info)
        
        preview_group = QGroupBox("文件预览 (十六进制)")
        preview_layout = QVBoxLayout(preview_group)
        
        self.polyglot_preview = QTextEdit()
        self.polyglot_preview.setReadOnly(True)
        self.polyglot_preview.setFont(QFont("Consolas", 10))
        preview_layout.addWidget(self.polyglot_preview)
        
        layout.addWidget(preview_group)
        
        self.polyglot_data = None
        self.polyglot_ext = None
        
        self.tabs.addTab(polyglot_tab, "Polyglot")
    
    def _create_proxy_tab(self):
        """创建代理标签页"""
        self.proxy_widget = ProxyWidget()
        self.proxy_widget.send_to_repeater.connect(self._load_to_repeater)
        self.proxy_widget.send_to_intruder.connect(self._load_to_intruder)
        self.tabs.addTab(self.proxy_widget, "代理")
    
    def _create_logs_tab(self):
        """创建日志标签页"""
        logs_tab = QWidget()
        layout = QVBoxLayout(logs_tab)
        layout.setContentsMargins(15, 15, 15, 15)
        
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setFont(QFont("Consolas", 10))
        layout.addWidget(self.log_text)
        
        clear_btn = QPushButton("清除日志")
        clear_btn.clicked.connect(self.log_text.clear)
        layout.addWidget(clear_btn)
        
        self.tabs.addTab(logs_tab, "日志")
        
        # 处理待处理的日志消息
        if hasattr(self, '_pending_logs') and self._pending_logs:
            for pending_message in self._pending_logs:
                self.log_text.append(pending_message)
            self._pending_logs.clear()
    
    def _create_about_tab(self):
        """创建关于标签页"""
        about_tab = QWidget()
        layout = QVBoxLayout(about_tab)
        layout.setAlignment(Qt.AlignCenter)
        
        container = QWidget()
        container.setFixedWidth(600)
        container_layout = QVBoxLayout(container)
        container_layout.setSpacing(20)
        
        title = QLabel("UploadRanger")
        title.setStyleSheet(f"font-size: 36px; font-weight: bold; color: {COLORS['accent']};")
        title.setAlignment(Qt.AlignCenter)
        container_layout.addWidget(title)
        
        version = QLabel(f"版本 v{CURRENT_VERSION}")
        version.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 14px;")
        version.setAlignment(Qt.AlignCenter)
        container_layout.addWidget(version)
        
        desc = QLabel(
            "UploadRanger 是一款现代化的文件上传漏洞测试工具，\n"
            "专为渗透测试人员和安全研究人员设计。"
        )
        desc.setStyleSheet(f"color: {COLORS['text_primary']}; font-size: 14px;")
        desc.setAlignment(Qt.AlignCenter)
        container_layout.addWidget(desc)
        
        features = QLabel(
            "<b>功能特性：</b><br>"
            "• 异步扫描 + 可选 Raw 字节级 multipart（与同步引擎对齐）<br>"
            "• 环境指纹预检与 Payload 策略过滤/排序（可选）<br>"
            "• 请求/响应实时查看 (Burp 风格，带语法高亮)<br>"
            "• Repeater 重放 / Intruder 多模式爆破<br>"
            "• 37+ 种绕过技术测试（生成器页）<br>"
            "• 23 种 WebShell 生成 (PHP/ASP/JSP/Python/Perl)<br>"
            "• 8 种 Polyglot 文件<br>"
            "• 快速向导、GitHub 检查更新<br>"
            "• 结构化 JSON 上传响应判定与可解释原因"
        )
        features.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 13px; line-height: 1.8;")
        features.setAlignment(Qt.AlignCenter)
        container_layout.addWidget(features)
        
        # 浏览器配置说明
        browser_config = QLabel(
            "<b>浏览器配置说明（抓取localhost/127.0.0.1必需）：</b><br>"
            "<b>Chrome/Edge:</b> 启动参数添加 --proxy-bypass-list='&lt;-loopback&gt;'<br>"
            "<b>Firefox:</b> about:config → network.proxy.allow_hijacking_localhost = true<br>"
            "<b>Zero Omega:</b> '不代理的地址列表'必须清空"
        )
        browser_config.setStyleSheet(f"color: {COLORS['warning']}; font-size: 12px; line-height: 1.6;")
        browser_config.setAlignment(Qt.AlignCenter)
        container_layout.addWidget(browser_config)
        
        author = QLabel("作者: bae")
        author.setStyleSheet(f"color: {COLORS['accent']}; font-size: 14px;")
        author.setAlignment(Qt.AlignCenter)
        container_layout.addWidget(author)
        
        warning = QLabel(
            "<b>警告：</b>本工具仅供安全测试使用，<br>"
            "请遵守相关法律法规，仅在授权的系统上使用。"
        )
        warning.setStyleSheet(f"color: {COLORS['danger']}; font-size: 12px;")
        warning.setAlignment(Qt.AlignCenter)
        container_layout.addWidget(warning)
        
        # 添加界面重置按钮
        reset_btn = QPushButton("重置界面")
        reset_btn.setToolTip("如果Repeater或Intruder标签页消失，点击此按钮恢复")
        reset_btn.setFixedWidth(120)
        reset_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['warning']};
                color: white;
                border: none;
                border-radius: 4px;
                padding: 8px 16px;
                font-weight: bold;
            }}
            QPushButton:hover {{
                background-color: {COLORS['accent']};
            }}
        """)
        reset_btn.clicked.connect(self.reset_tabs)
        container_layout.addWidget(reset_btn)
        
        layout.addWidget(container)
        
        self.tabs.addTab(about_tab, "关于")
    
    def _create_status_bar(self):
        """创建状态栏"""
        self.status_bar = self.statusBar()
        self.status_bar.showMessage("就绪")
        
        self.stats_label = QLabel("")
        self.status_bar.addPermanentWidget(self.stats_label)
    
    def _log(self, message):
        """添加日志 - 安全版本，处理log_text未初始化的情况"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_message = f"[{timestamp}] {message}"
        
        # 如果log_text已初始化，直接写入
        if hasattr(self, 'log_text') and self.log_text:
            self.log_text.append(log_message)
        else:
            # 如果log_text还未初始化，先打印到控制台
            print(f"[UploadRanger] {log_message}")
            # 如果后续log_text初始化了，可以尝试追加
            if hasattr(self, '_pending_logs'):
                self._pending_logs.append(log_message)
            else:
                self._pending_logs = [log_message]
    
    def _open_scan_wizard(self):
        """新手快速向导：填入扫描页并切换到扫描标签"""
        wiz = QuickScanWizard(self)
        if wiz.exec() != QDialog.DialogCode.Accepted:
            return
        def _field_str(name: str, default: str = "") -> str:
            v = wiz.field(name)
            if v is None:
                return default
            return str(v).strip() or default

        url = _field_str("targetUrl")
        param = _field_str("fileParam", "file")
        udir = _field_str("uploadDir")
        if url:
            self.url_input.setText(url)
        if param:
            self.param_input.setCurrentText(param)
        self.upload_dir_input.setText(udir)
        for i in range(self.tabs.count()):
            if self.tabs.tabText(i) == "扫描":
                self.tabs.setCurrentIndex(i)
                break
        # 自动开始扫描（与用户期望一致，减少一步点击）
        QTimer.singleShot(100, self._safe_start_scan)
    
    def _safe_start_scan(self):
        """安全的扫描启动方法，用于向导完成后的自动扫描 - 修复版本"""
        try:
            self._log("快速向导准备启动扫描...")
            
            # 验证必要参数
            if not self.url_input.text().strip():
                self._log("错误: 快速向导未提供有效的目标URL")
                return
                
            # 确保UI状态正确，避免重复启动
            if hasattr(self, 'worker') and self.worker and self.worker.isRunning():
                self._log("扫描已在进行中，取消向导自动扫描")
                return
                
            # 检查UI状态
            if not self.start_btn.isEnabled():
                self._log("扫描按钮不可用，可能已有扫描在进行")
                return
            
            self._log("向导自动扫描启动中...")
            self._start_scan()
            
        except Exception as e:
            error_msg = f"快速向导自动扫描失败: {str(e)}"
            self._log(error_msg)
            QMessageBox.warning(self, "扫描失败", f"自动扫描启动失败: {str(e)}")
        finally:
            # 确保UI状态正确
            QTimer.singleShot(500, self._check_ui_state)
    
    def _check_ui_state(self):
        """检查并修复UI状态"""
        try:
            if self.worker and self.worker.isRunning():
                # 扫描进行中，确保按钮状态正确
                if self.start_btn.isEnabled():
                    self.start_btn.setEnabled(False)
                if not self.stop_btn.isEnabled():
                    self.stop_btn.setEnabled(True)
            else:
                # 扫描未进行，确保按钮状态正确
                if not self.start_btn.isEnabled() and not (self.worker and self.worker.isRunning()):
                    self.start_btn.setEnabled(True)
                if self.stop_btn.isEnabled() and not (self.worker and self.worker.isRunning()):
                    self.stop_btn.setEnabled(False)
        except Exception:
            pass
    
    def _open_github(self):
        """打开GitHub项目主页"""
        github_url = "https://github.com/Gentle-bae/UploadRanger.git"
        try:
            webbrowser.open(github_url)
            self._log(f"已打开GitHub: {github_url}")
        except Exception as e:
            QMessageBox.information(
                self, 
                "GitHub项目地址", 
                f"请手动访问:\n{github_url}\n\n错误: {str(e)}"
            )
    
    def _start_scan(self):
        """开始扫描"""
        url = self.url_input.text().strip()
        
        if not url:
            self._log("错误: 请输入目标URL")
            return
        
        self._log(f"=== 开始扫描准备 ===")
        self._log(f"目标URL: {url}")
        self._log(f"文件参数: {self.param_input.currentText().strip() or 'file'}")
        self._log(f"Payload上限: {self.payload_limit_spin.value()}")
        self._log(f"超时时间: {self.timeout_spin.value()}秒")
        self._log(f"Raw上传: {'开' if self.use_raw_upload_cb.isChecked() else '关'}")
        self._log(f"环境指纹: {'开' if self.use_fingerprint_cb.isChecked() else '关'}")
        
        # 获取扫描模式配置
        scan_mode = self._get_scan_mode()
        webshell_config = self._get_webshell_config()
        self._log(f"测试模式: {'渗透测试' if scan_mode == 'penetration' else '安全测试'}")
        if webshell_config.get("enabled"):
            self._log(f"WebShell配置: 密码={webshell_config['password']}, 类型={webshell_config['type']}")
        
        # 获取用户选择的后缀
        selected_exts = self._get_selected_extensions()
        if not selected_exts:
            self._log("错误: 请至少选择一个测试后缀")
            return
        
        # 渗透模式下确认上传 EXE/脚本
        if scan_mode == "penetration":
            # 检查是否选择了可执行文件后缀
            exec_exts = {'exe', 'dll', 'bat', 'cmd', 'vbs', 'ps1', 'hta', 'scr', 'cpl', 'sh', 'bash', 'elf', 'so'}
            selected_exec = [ext for ext in selected_exts if ext.lstrip('.').lower() in exec_exts]
            if selected_exec:
                reply = QMessageBox.question(
                    self,
                    "渗透模式 - 确认上传可执行文件",
                    f"即将上传以下类型的可执行文件：\n• {', '.join(selected_exec)}\n\n"
                    f"这些文件可能在目标服务器执行，可能触发安全防护或造成系统损害。\n\n是否继续上传可执行文件？",
                    QMessageBox.Yes | QMessageBox.No,
                    QMessageBox.No
                )
                if reply == QMessageBox.No:
                    # 用户取消扫描
                    self._log("[取消] 已取消扫描")
                    return
            
        self._log(f"测试后缀: {', '.join(selected_exts)}")
        
        # 收集配置
        proxy = None
        if self.use_proxy_cb.isChecked():
            proxy = self.proxy_input.text().strip()
            self._log(f"代理: {proxy}")
        
        proxy_dict = {"http://": proxy, "https://": proxy} if proxy else None
        
        headers = {}
        
        # 清空结果
        self.results_table.clear_results()
        self.findings_table.clear_results()
        self.details_text.clear()
        self.traffic_viewer.clear_logs()
        
        # 更新UI
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        
        self._log("正在创建扫描工作线程...")
        
        # 启动工作线程
        self.worker = AsyncScannerWorker(
            target_url=url,
            file_param=self.param_input.currentText().strip() or "file",
            upload_dir=self.upload_dir_input.text().strip() or None,
            proxies=proxy_dict,
            headers=headers,
            cookies=self.cookie_input.text().strip() or None,
            max_payloads=self.payload_limit_spin.value(),
            timeout=self.timeout_spin.value(),
            use_raw_multipart=self.use_raw_upload_cb.isChecked(),
            use_fingerprint=self.use_fingerprint_cb.isChecked(),
            selected_extensions=selected_exts,
            scan_mode=scan_mode,  # 【新增】扫描模式
            webshell_config=webshell_config,  # 【新增】WebShell配置
        )
        
        self._log("连接工作线程信号...")
        
        # 确保信号正确连接（使用队列连接避免线程问题）
        from PySide6.QtCore import Qt
        self.worker.progress.connect(self._log, type=Qt.QueuedConnection)
        self.worker.finding_found.connect(self._on_finding, type=Qt.QueuedConnection)
        self.worker.result_found.connect(self._on_result, type=Qt.QueuedConnection)
        self.worker.traffic_log.connect(self._on_traffic, type=Qt.QueuedConnection)
        self.worker.traffic_update.connect(self._on_traffic_update, type=Qt.QueuedConnection)  # 【新增】
        self.worker.progress_update.connect(self._on_progress, type=Qt.QueuedConnection)
        self.worker.finished.connect(self._on_finished, type=Qt.QueuedConnection)
        
        # 通知worker信号已连接
        if hasattr(self.worker, 'connect_signals_safe'):
            self.worker.connect_signals_safe()
        
        self._log("检查worker状态...")
        self._log(f"worker.isRunning(): {self.worker.isRunning()}")
        self._log(f"worker.target_url: {self.worker.target_url}")
        self._log(f"worker.max_payloads: {self.worker.max_payloads}")
        
        self._log("启动工作线程...")
        self.worker.start()
        self._log("工作线程已启动")
        
        # 延迟检查worker状态
        QTimer.singleShot(1000, self._check_worker_status)
    
    def _check_worker_status(self):
        """检查worker线程状态 - 增强版本"""
        if self.worker:
            is_running = self.worker.isRunning()
            self._log(f"Worker状态检查 - isRunning: {is_running}")
            
            if not is_running:
                self._log("警告: Worker线程似乎停止了")
                # 检查是否异常停止
                if hasattr(self.worker, 'isFinished') and self.worker.isFinished():
                    self._log("Worker已完成（可能是正常完成）")
                else:
                    self._log("Worker异常停止")
                    # 尝试恢复UI状态
                    self._on_finished(None)
            else:
                self._log("Worker正在正常运行")
                # 继续监控
                QTimer.singleShot(2000, self._check_worker_status)
        else:
            self._log("警告: Worker线程为None")
            # 恢复UI状态
            self._on_finished(None)
    
    def _stop_scan(self):
        """停止扫描 - 修复版本，立即响应不等待"""
        self._log("用户请求停止扫描...")
        
        # 【修复】先禁用停止按钮，防止重复点击
        self.stop_btn.setEnabled(False)
        
        try:
            if hasattr(self, 'worker') and self.worker:
                if self.worker.isRunning():
                    self._log("正在停止worker线程...")
                    self.worker.stop()
                    
                    # 【修复】不再等待worker线程，立即返回
                    # worker会在后台自行结束，不影响UI响应
                    self._log("已发送停止信号，worker将在后台停止")
                else:
                    self._log("Worker线程未在运行状态")
                
                # 【修复】立即清理worker引用，不等待
                self.worker = None
            else:
                self._log("没有活动的worker线程")
                
        except Exception as e:
            error_msg = f"停止扫描时出错: {str(e)}"
            self._log(error_msg)
            print(f"[MainWindow] {error_msg}")
            import traceback
            traceback.print_exc()
            
        finally:
            # 【修复】统一在finally中恢复UI状态，确保无论是否出错都能恢复
            self._log("恢复UI状态")
            self.start_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)
            self.status_bar.showMessage("扫描已停止")
            self.progress_bar.setValue(0)
            self.progress_label.setText("扫描已停止")
    
    def _on_result(self, result: dict):
        """处理扫描结果 - 实时添加到结果表格"""
        self.results_table.add_result(result)
    
    def _on_finding(self, finding):
        """处理漏洞发现"""
        self.findings_table.add_finding(finding)
    
    def _on_traffic(self, log):
        """处理流量日志"""
        self.traffic_viewer.add_log(log)
    
    def _on_traffic_update(self, log_id: int, is_success: bool):
        """处理流量日志更新（is_success 状态变化）"""
        self.traffic_viewer.update_log_success(log_id, is_success)
    
    def _on_progress(self, percent, message):
        """处理进度更新 - 增强版本"""
        try:
            self._log(f"进度更新: {percent}% - {message}")
            
            # 确保进度条有最小值显示
            if percent == 0:
                self.progress_bar.setValue(1)  # 显示最小进度，避免看起来卡住
                self.progress_bar.setFormat("初始化中...")  # 显示状态文本
            else:
                self.progress_bar.setValue(percent)
                self.progress_bar.setFormat(f"%p%")  # 显示百分比
            
            self.progress_label.setText(message)
            self.status_bar.showMessage(message)
            
            # 强制UI更新，避免界面冻结
            from PySide6.QtWidgets import QApplication
            QApplication.instance().processEvents()
            
        except Exception as e:
            print(f"进度更新异常: {e}")
            # 降级处理，确保UI不崩溃
            try:
                self.progress_bar.setValue(0)
                self.status_bar.showMessage("进度更新错误")
            except:
                pass
    
    def _on_finished(self, result):
        """扫描完成 - 增强版本，处理各种异常情况"""
        self._log("=== 扫描完成处理开始 ===")
        
        # 确保UI状态正确恢复
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        
        # 清理worker引用
        if self.worker:
            try:
                if self.worker.isRunning():
                    self.worker.wait(1000)  # 等待最多1秒
                self.worker = None
            except Exception as e:
                self._log(f"清理worker时出错: {e}")
        
        # 处理结果统计
        try:
            result_count = len(self.results_table.results)

            if result and hasattr(result, 'findings'):
                vuln_count = len(result.findings)
            else:
                vuln_count = 0

            # 【BUG-6修复】区分两种"成功"：
            #   analyzed_success: 分析器判定成功（含分支2，可能无HTTP验证）
            #   verified_success:  HTTP验证通过的成功（等价于 is_vulnerability）
            analyzed_success = sum(1 for r in self.results_table.results if r.get('is_success'))
            verified_success = sum(1 for r in self.results_table.results if r.get('is_vulnerability'))

            if result_count == 0:
                self._log("扫描完成，但没有发现任何结果")
                self.status_bar.showMessage("扫描完成 - 未发现上传漏洞")
            else:
                self.status_bar.showMessage(
                    f"扫描完成 - 共测试 {result_count} 个payload，"
                    f"响应判定成功 {analyzed_success} 个，已验证漏洞 {verified_success} 个，"
                    f"发现 {vuln_count} 个漏洞"
                )

            self.stats_label.setText(
                f"结果: {result_count} | 响应成功: {analyzed_success} | 已验证: {verified_success} | 漏洞: {vuln_count}"
            )
            self._log(
                f"扫描完成！共测试 {result_count} 个payload，"
                f"响应判定成功 {analyzed_success} 个，已验证漏洞 {verified_success} 个，"
                f"发现 {vuln_count} 个漏洞"
            )
            
        except Exception as e:
            self._log(f"处理扫描结果时出错: {e}")
            self.status_bar.showMessage("扫描完成 - 结果处理出错")
            self.stats_label.setText("结果: 错误")
        
        self._log("=== 扫描完成处理结束 ===")
    
    def _on_result_selected(self, item):
        """结果选择事件 - 【修复】添加整行高亮和滚动定位"""
        row = item.row()
        
        # 【修复】选中整行并滚动到该行
        self.results_table.selectRow(row)
        self.results_table.scrollToItem(item, QTableWidget.PositionAtCenter)
        
        result = self.results_table.item(row, 0).data(Qt.UserRole)
        
        if result:
            req_headers = result.get('request_headers', 'N/A')
            res_headers = result.get('response_headers', 'N/A')
            res_body = result.get('response_body', 'N/A')
            
            details = f"""文件名: {result.get('filename', 'N/A')}
类型: {result.get('payload_type', 'N/A')}
描述: {result.get('description', 'N/A')}
状态码: {result.get('status_code', 'N/A')}
是否成功: {'是' if result.get('is_success') else '否'}
成功概率: {result.get('success_probability', 0)}%
路径泄露: {result.get('path_leaked', 'N/A')}
响应长度: {result.get('response_length', 'N/A')} bytes

[请求头]
{req_headers}

[响应头]
{res_headers}

[响应体]
{result.get('response_body', 'N/A')}
"""
            self.details_text.setPlainText(details)
    
    def _on_finding_selected(self, item):
        """漏洞选择事件 - 【修复】添加整行高亮和滚动定位"""
        row = item.row()
        
        # 【修复】选中整行并滚动到该行
        self.findings_table.selectRow(row)
        self.findings_table.scrollToItem(item, QTableWidget.PositionAtCenter)
        
        finding = self.findings_table.item(row, 0).data(Qt.UserRole)
        
        if finding:
            req_data = finding.request_data or 'N/A'
            res_data = finding.response_data or 'N/A'
            
            details = f"""漏洞名称: {finding.name}
描述: {finding.description}
风险等级: {finding.risk_level}
置信度: {finding.confidence}
URL: {finding.url}
Payload: {finding.payload}
证明: {finding.proof}
修复建议: {finding.remediation}
时间: {finding.timestamp.strftime('%Y-%m-%d %H:%M:%S')}

[请求数据]
{req_data}

[响应数据]
{res_data}
"""
            self.details_text.setPlainText(details)
    
    def _clear_results(self):
        """清除结果"""
        self.results_table.clear_results()
    
    def _jump_to_first_success(self):
        """【修复】跳转到成功响应项 - 支持循环跳转到下一个"""
        if not self.results_table.results:
            self._log("没有扫描结果")
            return
        
        # 获取当前选中的行，用于确定从哪个位置开始查找
        current_row = -1
        selected_items = self.results_table.selectedItems()
        if selected_items:
            current_row = selected_items[0].row()
        
        # 查找下一个成功的响应（从当前选中位置之后开始）
        found = False
        start_row = current_row + 1 if current_row >= 0 else 0
        
        # 先查找当前位置之后的
        for row in range(start_row, len(self.results_table.results)):
            result = self.results_table.results[row]
            if result.get('is_success', False):
                self._select_and_jump_to_result(row, result)
                found = True
                return
        
        # 如果没找到，从头开始查找（循环）
        if not found and current_row >= 0:
            for row in range(0, min(start_row, len(self.results_table.results))):
                result = self.results_table.results[row]
                if result.get('is_success', False):
                    self._select_and_jump_to_result(row, result)
                    found = True
                    return
        
        if not found:
            self._log("没有找到成功的响应")
    
    def _select_and_jump_to_result(self, row: int, result: dict):
        """【新增】选中结果并同步跳转到请求/响应界面"""
        # 1. 在扫描结果表格中选中
        self.results_table.selectRow(row)
        item = self.results_table.item(row, 0)
        if item:
            self.results_table.scrollToItem(item, QTableWidget.PositionAtCenter)
            self._on_result_selected(item)
        
        # 2. 【修复】同步跳转到请求/响应界面的对应数据包
        log_id = result.get('log_id')
        if log_id:
            # 切换到请求/响应标签
            for i in range(self.tabs.count()):
                if self.tabs.tabText(i) == "请求/响应":
                    self.tabs.setCurrentIndex(i)
                    break
            # 跳转到对应的流量日志
            if self.traffic_viewer.jump_to_log(log_id):
                self._log(f"已跳转到第 {row + 1} 个成功响应 (ID: {log_id})")
            else:
                self._log(f"已跳转到第 {row + 1} 个成功响应")
        else:
            self._log(f"已跳转到第 {row + 1} 个成功响应")
    
    def _clear_findings(self):
        """清除漏洞发现"""
        self.findings_table.clear_results()
    
    def _load_to_repeater(self, request_data):
        """加载请求到Repeater"""
        # 处理ProxyRequest对象或字典
        if hasattr(request_data, 'method'):
            # ProxyRequest对象
            data = {
                'method': request_data.method,
                'url': request_data.url if request_data.url.startswith('http') else f"http://{request_data.host}{request_data.url}",
                'request_headers': "\n".join([f"{k}: {v}" for k, v in request_data.headers.items()]),
                'request_body': request_data.body.decode('utf-8', errors='ignore') if request_data.body else ''
            }
        elif 'request_body' in request_data:
            # 扫描结果字典
            data = {
                'method': request_data.get('method', 'POST'),
                'url': request_data.get('url', ''),
                'request_headers': request_data.get('request_headers', ''),
                'request_body': request_data.get('request_body', '')
            }
        else:
            data = request_data
        
        self.repeater.load_request(data)
        self.tabs.setCurrentIndex(3)  # 切换到Repeater标签
        self._log("请求已加载到Repeater")
    
    def _load_to_intruder(self, request_data):
        """加载请求到Intruder"""
        # 处理ProxyRequest对象或字典
        if hasattr(request_data, 'method'):
            # ProxyRequest对象
            data = {
                'method': request_data.method,
                'url': request_data.url if request_data.url.startswith('http') else f"http://{request_data.host}{request_data.url}",
                'request_headers': "\n".join([f"{k}: {v}" for k, v in request_data.headers.items()]),
                'request_body': request_data.body.decode('utf-8', errors='ignore') if request_data.body else ''
            }
        elif 'request_body' in request_data:
            # 扫描结果字典
            data = {
                'method': request_data.get('method', 'POST'),
                'url': request_data.get('url', ''),
                'request_headers': request_data.get('request_headers', ''),
                'request_body': request_data.get('request_body', '')
            }
        else:
            data = request_data
        
        self.intruder.load_request(data)
        self.tabs.setCurrentIndex(4)  # 切换到Intruder标签
        self._log("请求已加载到Intruder")
    
    def _update_payload_types(self):
        """更新Payload类型列表"""
        lang = self.payload_lang_combo.currentText().lower()
        
        self.payload_type_combo.clear()
        
        shells = {}
        if lang == "php":
            shells = self.shell_generator.get_php_shells()
        elif lang == "asp":
            shells = self.shell_generator.get_asp_shells()
        elif lang == "jsp":
            shells = self.shell_generator.get_jsp_shells()
        elif lang == "python":
            shells = self.shell_generator.get_python_shells()
        elif lang == "perl":
            shells = self.shell_generator.get_perl_shells()
        
        for key, info in shells.items():
            self.payload_type_combo.addItem(info['name'], key)
    
    def _generate_payload(self):
        """生成Payload"""
        lang = self.payload_lang_combo.currentText().lower()
        shell_type = self.payload_type_combo.currentData()
        
        shell = self.shell_generator.generate_shell(lang, shell_type)
        
        if shell:
            code = f"# {shell['name']}\n"
            code += f"# 用法: {shell.get('usage', 'N/A')}\n\n"
            code += shell['code']
            self.payload_code.setPlainText(code)
    
    def _copy_payload(self):
        """复制Payload"""
        clipboard = QApplication.clipboard()
        clipboard.setText(self.payload_code.toPlainText())
        self._log("代码已复制到剪贴板")
    
    def _save_payload(self):
        """保存Payload"""
        filename, _ = QFileDialog.getSaveFileName(
            self, "保存文件", "shell.php", "PHP文件 (*.php);;所有文件 (*.*)"
        )
        if filename:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(self.payload_code.toPlainText())
            self._log(f"文件已保存: {filename}")
    
    def _batch_generate_payloads(self):
        """批量生成所有Payload"""
        lang = self.payload_lang_combo.currentText().lower()
        
        shells = {}
        if lang == "php":
            shells = self.shell_generator.get_php_shells()
        elif lang == "asp":
            shells = self.shell_generator.get_asp_shells()
        elif lang == "jsp":
            shells = self.shell_generator.get_jsp_shells()
        elif lang == "python":
            shells = self.shell_generator.get_python_shells()
        elif lang == "perl":
            shells = self.shell_generator.get_perl_shells()
        
        # 批量生成所有shell
        all_code = f"# {lang.upper()} WebShell 批量生成\n"
        all_code += f"# 共 {len(shells)} 个\n"
        all_code += "=" * 60 + "\n\n"
        
        for key, info in shells.items():
            shell = self.shell_generator.generate_shell(lang, key)
            if shell:
                all_code += f"# {'=' * 50}\n"
                all_code += f"# {shell['name']}\n"
                all_code += f"# 用法: {shell.get('usage', 'N/A')}\n"
                all_code += f"# {'=' * 50}\n\n"
                all_code += shell['code']
                all_code += "\n\n"
        
        self.payload_code.setPlainText(all_code)
        self._log(f"批量生成完成，共 {len(shells)} 个 {lang.upper()} WebShell")
    
    def _generate_bypass(self):
        """生成绕过payload"""
        filename = self.bypass_filename.text()
        extension = self.bypass_ext.text()
        
        payloads = self.bypass_generator.generate_all_payloads(filename, extension)
        
        self.bypass_table.setRowCount(0)
        
        for payload in payloads:
            row = self.bypass_table.rowCount()
            self.bypass_table.insertRow(row)
            
            self.bypass_table.setItem(row, 0, QTableWidgetItem(payload.get('filename', '')))
            self.bypass_table.setItem(row, 1, QTableWidgetItem(payload.get('technique', '')))
            
            severity = payload.get('severity', '低')
            severity_item = QTableWidgetItem(severity)
            if severity == '高':
                severity_item.setForeground(QColor(COLORS['danger']))
            elif severity == '中':
                severity_item.setForeground(QColor(COLORS['warning']))
            self.bypass_table.setItem(row, 2, severity_item)
            
            desc_item = QTableWidgetItem(payload.get('description', ''))
            desc_item.setToolTip(payload.get('description', ''))
            self.bypass_table.setItem(row, 3, desc_item)
    
    def _export_bypass(self):
        """导出绕过字典"""
        filename, _ = QFileDialog.getSaveFileName(
            self, "导出字典", "bypass_dict.txt", "文本文件 (*.txt)"
        )
        if filename:
            with open(filename, 'w', encoding='utf-8') as f:
                for row in range(self.bypass_table.rowCount()):
                    fname = self.bypass_table.item(row, 0).text()
                    f.write(fname + '\n')
            self._log(f"字典已导出: {filename}")
    
    def _generate_polyglot(self):
        """生成Polyglot"""
        polyglot_type = self.polyglot_type.currentData()
        php_code = self.polyglot_code.text()
        
        polyglots = self.polyglot_generator.get_all_polyglots(php_code)
        
        if polyglot_type in polyglots:
            info = polyglots[polyglot_type]
            self.polyglot_data = info['generator']()
            self.polyglot_ext = info['extension']
            
            # 显示文件类型信息
            is_binary = isinstance(self.polyglot_data, bytes)
            file_type = "二进制" if is_binary else "文本"
            self.polyglot_info.setText(
                f"{info['name']}: {info['description']} "
                f"[{file_type}文件，扩展名: {info['extension']}]"
            )
            
            if is_binary:
                hex_preview = self.polyglot_data[:256].hex(' ')
                formatted = f"# 这是二进制文件的前256字节十六进制预览\n"
                formatted += f"# 文件类型: {info['name']}\n"
                formatted += f"# 完整大小: {len(self.polyglot_data)} 字节\n\n"
                for i in range(0, len(hex_preview), 48):
                    line = hex_preview[i:i+48]
                    formatted += f"{i:04x}: {line}\n"
                self.polyglot_preview.setText(formatted)
    
    def _save_polyglot(self):
        """保存Polyglot"""
        if self.polyglot_data is None:
            self._log("警告: 请先生成polyglot")
            return
        
        # 根据类型确定文件扩展名和描述
        is_binary = isinstance(self.polyglot_data, bytes)
        file_ext = self.polyglot_ext or '.bin'
        
        # 根据扩展名确定文件类型描述
        type_desc = "二进制文件"
        if '.gif' in file_ext:
            type_desc = "GIF图片文件"
        elif '.png' in file_ext:
            type_desc = "PNG图片文件"
        elif '.jpg' in file_ext or '.jpeg' in file_ext:
            type_desc = "JPEG图片文件"
        elif '.svg' in file_ext:
            type_desc = "SVG矢量图文件"
        
        filename, _ = QFileDialog.getSaveFileName(
            self, 
            f"保存{type_desc}", 
            f"polyglot{file_ext}", 
            f"{type_desc} (*{file_ext});;所有文件 (*.*)"
        )
        if filename:
            try:
                if is_binary:
                    with open(filename, 'wb') as f:
                        f.write(self.polyglot_data)
                else:
                    with open(filename, 'w', encoding='utf-8') as f:
                        f.write(self.polyglot_data)
                self._log(f"{type_desc}已保存: {filename}")
                
                # 显示提示信息
                if is_binary:
                    QMessageBox.information(
                        self, 
                        "保存成功", 
                        f"文件已保存: {filename}\n\n"
                        f"这是一个{type_desc}，请使用十六进制编辑器查看，\n"
                        f"直接用文本编辑器打开可能会显示乱码。"
                    )
            except Exception as e:
                QMessageBox.critical(self, "保存失败", f"保存文件时出错: {str(e)}")
                self._log(f"错误: 保存文件失败 - {str(e)}")


def run_gui():
    """运行GUI"""
    # 【修复】过滤PySide6 QThread警告
    import warnings
    warnings.filterwarnings("ignore", category=RuntimeWarning, module="PySide6")

    # 【修复】捕获 mitmproxy 日志处理器在程序退出时的异常
    import logging
    _original_handle = logging.Handler.handle

    def _patched_handle(self, record):
        try:
            return _original_handle(self, record)
        except RuntimeError as e:
            if "Event loop is closed" in str(e):
                return  # 忽略事件循环关闭错误
            raise

    logging.Handler.handle = _patched_handle

    # 【修复】设置事件循环策略，避免QThread崩溃
    # Linux/WSL 使用 DefaultEventLoopPolicy
    # Windows 使用 SelectorEventLoopPolicy 避免 IocpProactor 与 QThread 冲突
    import asyncio
    try:
        if sys.platform.startswith('linux'):
            asyncio.set_event_loop_policy(asyncio.DefaultEventLoopPolicy())
        elif sys.platform == 'win32':
            # Windows 上使用 Selector 事件循环，避免 IocpProactor 问题
            asyncio.set_event_loop_policy(asyncio.SelectorEventLoopPolicy())
    except Exception:
        pass
    
    app = QApplication(sys.argv)
    
    # 【关键修复】防止关闭子标签时整个应用退出
    # 当 Repeater 内部标签关闭时，Qt 可能误判为最后一个窗口关闭而触发 quit
    app.setQuitOnLastWindowClosed(False)
    
    # 【修复】Linux/WSL环境下设置中文字体，防止乱码
    if sys.platform.startswith('linux'):
        from PySide6.QtGui import QFont, QFontDatabase
        # 尝试设置Linux可用的中文字体
        linux_fonts = [
            "WenQuanYi Micro Hei",
            "Noto Sans CJK SC",
            "Source Han Sans SC",
            "SimHei",
            "DejaVu Sans",
            "Liberation Sans"
        ]
        font_db = QFontDatabase()
        available_fonts = font_db.families()
        
        selected_font = None
        for font_name in linux_fonts:
            if font_name in available_fonts:
                selected_font = font_name
                break
        
        if selected_font:
            font = QFont(selected_font, 13)
            font.setStyleHint(QFont.SansSerif)
            app.setFont(font)
    
    apply_dark_theme(app)
    
    window = MainWindow()
    window.show()
    
    sys.exit(app.exec())
