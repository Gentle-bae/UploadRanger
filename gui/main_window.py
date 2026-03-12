#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
主窗口 - UploadRanger GUI主界面 v1.0.3
整合upload_forge功能，添加请求/响应查看、Repeater和Intruder功能
"""

import sys
import os
import asyncio
from datetime import datetime

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QTabWidget, QFormLayout,
    QTextEdit, QProgressBar, QTableWidget, QTableWidgetItem,
    QHeaderView, QGroupBox, QCheckBox, QSpinBox, QSplitter,
    QFileDialog, QComboBox, QMessageBox, QPlainTextEdit
)
from PySide6.QtCore import Qt, QSize
from PySide6.QtGui import QColor, QFont, QIcon

from .themes.dark_theme import apply_dark_theme, COLORS
from .traffic_viewer import TrafficViewer
from .proxy_widget import ProxyWidget
from .repeater_widget import RepeaterWidget
from .intruder_widget import IntruderWidget
from .syntax_highlighter import HTTPHighlighter, WebShellHighlighter

# 导入核心模块
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.async_scanner_worker import AsyncScannerWorker
from payloads.webshells import WebShellGenerator
from payloads.bypass_payloads import BypassPayloadGenerator
from payloads.polyglots import PolyglotGenerator
from core.models import VulnerabilityFinding, RISK_CRITICAL, RISK_HIGH, RISK_MEDIUM


class ResultsTable(QTableWidget):
    """扫描结果表格 - 显示所有测试结果"""
    
    def __init__(self):
        super().__init__()
        self.setColumnCount(6)
        self.setHorizontalHeaderLabels(["文件名", "类型", "状态码", "状态", "概率", "路径"])
        
        self.setColumnWidth(0, 180)
        self.setColumnWidth(1, 120)
        self.setColumnWidth(2, 60)
        self.setColumnWidth(3, 60)
        self.setColumnWidth(4, 60)
        self.setColumnWidth(5, 250)
        
        header = self.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Fixed)
        header.setSectionResizeMode(1, QHeaderView.Fixed)
        header.setSectionResizeMode(2, QHeaderView.Fixed)
        header.setSectionResizeMode(3, QHeaderView.Fixed)
        header.setSectionResizeMode(4, QHeaderView.Fixed)
        header.setSectionResizeMode(5, QHeaderView.Stretch)
        
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
    
    def clear_results(self):
        """清空结果"""
        self.setRowCount(0)
        self.results = []
    
    def add_result(self, result: dict):
        """添加扫描结果"""
        self.results.append(result)
        row = self.rowCount()
        self.insertRow(row)
        
        # 文件名
        filename_item = QTableWidgetItem(result.get('filename', 'Unknown'))
        filename_item.setData(Qt.UserRole, result)
        self.setItem(row, 0, filename_item)
        
        # 类型
        self.setItem(row, 1, QTableWidgetItem(result.get('payload_type', 'Unknown')))
        
        # 状态码
        status_code = result.get('status_code', 0)
        status_item = QTableWidgetItem(str(status_code))
        
        # 根据状态码设置颜色
        if 200 <= status_code < 300:
            status_item.setForeground(QColor(COLORS['success']))
        elif 300 <= status_code < 400:
            status_item.setForeground(QColor(COLORS['warning']))
        elif 400 <= status_code < 500:
            status_item.setForeground(QColor(COLORS['danger']))
        elif 500 <= status_code:
            status_item.setForeground(QColor("#ff6b6b"))
        
        self.setItem(row, 2, status_item)
        
        # 状态
        is_success = result.get('is_success', False)
        status_text = "成功" if is_success else "失败"
        status_text_item = QTableWidgetItem(status_text)
        if is_success:
            status_text_item.setForeground(QColor(COLORS['success']))
        else:
            status_text_item.setForeground(QColor(COLORS['text_secondary']))
        self.setItem(row, 3, status_text_item)
        
        # 概率
        prob = result.get('success_probability', 0)
        prob_item = QTableWidgetItem(f"{prob}%")
        if prob >= 70:
            prob_item.setForeground(QColor(COLORS['success']))
        elif prob >= 40:
            prob_item.setForeground(QColor(COLORS['warning']))
        else:
            prob_item.setForeground(QColor(COLORS['danger']))
        self.setItem(row, 4, prob_item)
        
        # 路径
        path = result.get('path_leaked', '')
        path_item = QTableWidgetItem(path)
        path_item.setToolTip(path)
        self.setItem(row, 5, path_item)
        
        # 滚动到最新行
        self.scrollToBottom()


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
        self.setWindowTitle("UploadRanger - 文件上传漏洞测试工具 v1.0.3")
        self.resize(1600, 1000)
        self.setMinimumSize(1400, 800)
        
        # 加载图标
        self._load_icon()
        
        # 初始化组件
        self.worker = None
        self.shell_generator = WebShellGenerator()
        self.bypass_generator = BypassPayloadGenerator()
        self.polyglot_generator = PolyglotGenerator()
        
        # 创建UI
        self._create_ui()

        # 【修复】连接关闭事件
        self.closeEvent = self._on_close_event
    
    def _load_icon(self):
        """加载应用图标"""
        icon_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "assets", "icon.png")
        if os.path.exists(icon_path):
            self.setWindowIcon(QIcon(icon_path))

    def _on_close_event(self, event):
        """窗口关闭前停止所有后台线程"""
        # 停止代理线程
        if hasattr(self, 'proxy_widget') and self.proxy_widget:
            self.proxy_widget.stop_proxy()

        event.accept()
    
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
        
        version = QLabel("v1.0.3")
        version.setStyleSheet(f"color: {COLORS['text_secondary']}; margin-right: 15px;")
        header_layout.addWidget(version)
        
        author = QLabel("by bae")
        author.setStyleSheet(f"color: {COLORS['accent']}; font-weight: bold;")
        header_layout.addWidget(author)
        
        parent_layout.addWidget(header)
    
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
        
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("http://example.com/upload.php")
        target_layout.addRow("目标 URL:", self.url_input)
        
        self.param_input = QLineEdit("file")
        target_layout.addRow("文件参数名:", self.param_input)
        
        self.upload_dir_input = QLineEdit()
        self.upload_dir_input.setPlaceholderText("http://example.com/uploads/ (可选)")
        target_layout.addRow("上传目录:", self.upload_dir_input)
        
        self.cookie_input = QLineEdit()
        self.cookie_input.setPlaceholderText("session=xxx; token=yyy")
        target_layout.addRow("Cookie:", self.cookie_input)
        
        left_layout.addWidget(target_group)
        
        # 代理配置组
        proxy_group = QGroupBox("代理配置")
        proxy_layout = QVBoxLayout(proxy_group)
        
        self.use_proxy_cb = QCheckBox("使用代理")
        proxy_layout.addWidget(self.use_proxy_cb)
        
        self.proxy_input = QLineEdit()
        self.proxy_input.setPlaceholderText("http://127.0.0.1:8080")
        proxy_layout.addWidget(self.proxy_input)
        
        left_layout.addWidget(proxy_group)
        
        # 扫描选项组
        options_group = QGroupBox("扫描选项")
        options_layout = QVBoxLayout(options_group)
        
        threads_layout = QHBoxLayout()
        threads_layout.addWidget(QLabel("超时(秒):"))
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(5, 300)
        self.timeout_spin.setValue(30)
        threads_layout.addWidget(self.timeout_spin)
        threads_layout.addStretch()
        options_layout.addLayout(threads_layout)
        
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
        
        clear_results_btn = QPushButton("清除")
        clear_results_btn.setFixedWidth(80)
        clear_results_btn.clicked.connect(self._clear_results)
        results_header.addWidget(clear_results_btn)
        
        results_layout.addLayout(results_header)
        
        self.results_table = ResultsTable()
        self.results_table.itemClicked.connect(self._on_result_selected)
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
        """创建Repeater标签页"""
        self.repeater = RepeaterWidget()
        self.tabs.addTab(self.repeater, "Repeater")
    
    def _create_intruder_tab(self):
        """创建Intruder标签页"""
        self.intruder = IntruderWidget()
        self.tabs.addTab(self.intruder, "Intruder")
    
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
        
        version = QLabel("版本 v1.0.3")
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
            "• 异步扫描引擎 (基于httpx)<br>"
            "• 请求/响应实时查看 (Burp风格，带语法高亮)<br>"
            "• Repeater重放功能<br>"
            "• Intruder爆破功能 (Sniper/Battering Ram/Pitchfork/Cluster Bomb)<br>"
            "• 100+种绕过技术测试<br>"
            "• 23+种WebShell生成<br>"
            "• 8种Polyglot文件<br>"
            "• 多线程并发扫描<br>"
            "• 详细结果报告"
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
        
        layout.addWidget(container)
        
        self.tabs.addTab(about_tab, "关于")
    
    def _create_status_bar(self):
        """创建状态栏"""
        self.status_bar = self.statusBar()
        self.status_bar.showMessage("就绪")
        
        self.stats_label = QLabel("")
        self.status_bar.addPermanentWidget(self.stats_label)
    
    def _log(self, message):
        """添加日志"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.append(f"[{timestamp}] {message}")
    
    def _start_scan(self):
        """开始扫描"""
        url = self.url_input.text().strip()
        
        if not url:
            self._log("错误: 请输入目标URL")
            return
        
        # 收集配置
        proxy = None
        if self.use_proxy_cb.isChecked():
            proxy = self.proxy_input.text().strip()
        
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
        
        # 启动工作线程
        self.worker = AsyncScannerWorker(
            target_url=url,
            file_param=self.param_input.text().strip() or "file",
            upload_dir=self.upload_dir_input.text().strip() or None,
            proxies=proxy_dict,
            headers=headers,
            cookies=self.cookie_input.text().strip() or None
        )
        self.worker.progress.connect(self._log)
        self.worker.finding_found.connect(self._on_finding)
        self.worker.result_found.connect(self._on_result)
        self.worker.traffic_log.connect(self._on_traffic)
        self.worker.progress_update.connect(self._on_progress)
        self.worker.finished.connect(self._on_finished)
        self.worker.start()
    
    def _stop_scan(self):
        """停止扫描"""
        if self.worker:
            self.worker.stop()
            self.worker.wait()
        
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status_bar.showMessage("扫描已停止")
    
    def _on_result(self, result: dict):
        """处理扫描结果 - 实时添加到结果表格"""
        self.results_table.add_result(result)
    
    def _on_finding(self, finding):
        """处理漏洞发现"""
        self.findings_table.add_finding(finding)
    
    def _on_traffic(self, log):
        """处理流量日志"""
        self.traffic_viewer.add_log(log)
    
    def _on_progress(self, percent, message):
        """处理进度更新"""
        self.progress_bar.setValue(percent)
        self.progress_label.setText(message)
        self.status_bar.showMessage(message)
    
    def _on_finished(self, result):
        """扫描完成"""
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        
        # 统计
        result_count = len(self.results_table.results)
        vuln_count = len(result.findings)
        success_count = sum(1 for r in self.results_table.results if r.get('is_success'))
        
        self.stats_label.setText(f"结果: {result_count} | 成功: {success_count} | 漏洞: {vuln_count}")
        self.status_bar.showMessage(f"扫描完成 - 共测试 {result_count} 个payload，成功 {success_count} 个，发现 {vuln_count} 个漏洞")
        
        self._log(f"扫描完成！共测试 {result_count} 个payload，成功 {success_count} 个，发现 {vuln_count} 个漏洞")
    
    def _on_result_selected(self, item):
        """结果选择事件"""
        row = item.row()
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
        """漏洞选择事件"""
        row = item.row()
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
            
            self.polyglot_info.setText(f"{info['name']}: {info['description']}")
            
            if isinstance(self.polyglot_data, bytes):
                hex_preview = self.polyglot_data[:256].hex(' ')
                formatted = ''
                for i in range(0, len(hex_preview), 48):
                    line = hex_preview[i:i+48]
                    formatted += f"{i:04x}: {line}\n"
                self.polyglot_preview.setText(formatted)
    
    def _save_polyglot(self):
        """保存Polyglot"""
        if self.polyglot_data is None:
            self._log("警告: 请先生成polyglot")
            return
        
        filename, _ = QFileDialog.getSaveFileName(
            self, "保存文件", f"polyglot{self.polyglot_ext or '.bin'}", "所有文件 (*.*)"
        )
        if filename:
            mode = 'wb' if isinstance(self.polyglot_data, bytes) else 'w'
            encoding = None if isinstance(self.polyglot_data, bytes) else 'utf-8'
            with open(filename, mode, encoding=encoding) as f:
                f.write(self.polyglot_data)
            self._log(f"文件已保存: {filename}")


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
