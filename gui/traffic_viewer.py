#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
流量查看器 - 类似Burp的请求/响应查看
支持分割器调整大小，完整内容显示，语法高亮
"""

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, 
    QTableWidgetItem, QSplitter, QLabel, 
    QHeaderView, QPushButton, QMenu, QPlainTextEdit, QApplication, QTabWidget
)
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor, QFont, QAction, QTextCursor

from .themes.dark_theme import COLORS
from .syntax_highlighter import HTTPHighlighter

# 成功状态背景色常量
SUCCESS_BG_COLOR = "#1a3d1a"  # 深绿色背景


class CodeEditor(QPlainTextEdit):
    """带语法高亮的代码编辑器"""
    
    def __init__(self, parent=None, is_request=True):
        super().__init__(parent)
        self.is_request = is_request
        
        # 设置字体
        self.setFont(QFont("Consolas", 10))
        
        # 设置样式
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
        self.highlighter = HTTPHighlighter(self.document(), is_request)
    
    def setPlainText(self, text):
        """设置文本并滚动到顶部"""
        super().setPlainText(text)
        self.moveCursor(QTextCursor.Start)


class TrafficViewer(QWidget):
    """流量查看器 - 显示请求/响应历史，支持发送到Repeater和Intruder"""
    
    # 信号
    send_to_repeater = Signal(dict)  # 发送到Repeater
    send_to_intruder = Signal(dict)  # 发送到Intruder
    
    def __init__(self):
        super().__init__()
        self.logs = []
        self.current_log = None
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)
        
        # 使用水平分割器 - 左侧请求列表，右侧详情
        main_splitter = QSplitter(Qt.Horizontal)
        
        # 左侧: 请求列表
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(5)
        
        # 标题和按钮
        header_layout = QHBoxLayout()
        header_label = QLabel("请求历史")
        header_label.setStyleSheet(f"font-weight: bold; color: {COLORS['accent']};")
        header_layout.addWidget(header_label)
        
        # 【新增】跳转到成功项按钮
        jump_success_btn = QPushButton("跳转到成功项")
        jump_success_btn.setFixedWidth(100)
        jump_success_btn.setToolTip("自动跳转到下一个成功的请求")
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
        jump_success_btn.clicked.connect(self._jump_to_success)
        header_layout.addWidget(jump_success_btn)
        
        clear_btn = QPushButton("清除")
        clear_btn.setFixedWidth(80)
        clear_btn.clicked.connect(self.clear_logs)
        header_layout.addWidget(clear_btn)
        
        left_layout.addLayout(header_layout)
        
        # 请求列表表格
        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(["ID", "时间", "方法", "URL", "状态码"])
        self.table.setColumnWidth(0, 50)
        self.table.setColumnWidth(1, 70)
        self.table.setColumnWidth(2, 60)
        self.table.setColumnWidth(4, 70)
        
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Fixed)
        header.setSectionResizeMode(1, QHeaderView.Fixed)
        header.setSectionResizeMode(2, QHeaderView.Fixed)
        header.setSectionResizeMode(3, QHeaderView.Stretch)
        header.setSectionResizeMode(4, QHeaderView.Fixed)
        
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setSelectionMode(QTableWidget.SingleSelection)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)  # 【修复】禁用编辑
        self.table.itemClicked.connect(self.display_details)
        self.table.setAlternatingRowColors(True)
        
        # 【修复】隐藏垂直行号（避免与ID列重复显示）
        self.table.verticalHeader().setVisible(False)
        
        # 右键菜单
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.show_context_menu)
        
        # 【修复】添加表格样式，移除选中边框
        self.table.setStyleSheet(f"""
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
        
        left_layout.addWidget(self.table)
        
        # 右侧: 请求/响应详情 - 使用垂直分割器
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(5)
        
        # 垂直分割器 - 上半部分请求，下半部分响应
        vertical_splitter = QSplitter(Qt.Vertical)
        
        # 请求详情
        req_widget = QWidget()
        req_layout = QVBoxLayout(req_widget)
        req_layout.setContentsMargins(0, 0, 0, 0)
        req_layout.setSpacing(5)
        
        req_header = QHBoxLayout()
        req_label = QLabel("请求")
        req_label.setStyleSheet(f"font-weight: bold; color: {COLORS['accent']};")
        req_header.addWidget(req_label)
        
        # 发送到Repeater按钮
        self.repeater_btn = QPushButton("发送到 Repeater")
        self.repeater_btn.setFixedWidth(130)
        self.repeater_btn.clicked.connect(self._send_to_repeater)
        self.repeater_btn.setEnabled(False)
        self.repeater_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['accent']};
                color: white;
                border: none;
                padding: 5px 10px;
                border-radius: 4px;
            }}
            QPushButton:hover {{
                background-color: {COLORS['accent_hover']};
            }}
        """)
        req_header.addWidget(self.repeater_btn)
        
        # 发送到Intruder按钮
        self.intruder_btn = QPushButton("发送到 Intruder")
        self.intruder_btn.setFixedWidth(130)
        self.intruder_btn.clicked.connect(self._send_to_intruder)
        self.intruder_btn.setEnabled(False)
        self.intruder_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['warning']};
                color: white;
                border: none;
                padding: 5px 10px;
                border-radius: 4px;
            }}
            QPushButton:hover {{
                background-color: #d4a017;
            }}
        """)
        req_header.addWidget(self.intruder_btn)
        
        req_layout.addLayout(req_header)
        
        # 使用带语法高亮的编辑器
        self.req_text = CodeEditor(is_request=True)
        self.req_text.setReadOnly(True)
        req_layout.addWidget(self.req_text)
        
        vertical_splitter.addWidget(req_widget)
        
        # 响应详情
        res_widget = QWidget()
        res_layout = QVBoxLayout(res_widget)
        res_layout.setContentsMargins(0, 0, 0, 0)
        res_layout.setSpacing(5)
        
        res_header = QHBoxLayout()
        res_label = QLabel("响应")
        res_label.setStyleSheet(f"font-weight: bold; color: {COLORS['accent']};")
        res_header.addWidget(res_label)
        
        # 状态码显示
        self.status_label = QLabel("")
        self.status_label.setStyleSheet(f"color: {COLORS['accent']}; font-weight: bold;")
        res_header.addWidget(self.status_label)
        res_header.addStretch()
        
        res_layout.addLayout(res_header)
        
        # 使用 ResponseViewerWidget 替代 CodeEditor
        from .response_viewer import ResponseViewerWidget
        self.res_viewer = ResponseViewerWidget()
        res_layout.addWidget(self.res_viewer)
        
        vertical_splitter.addWidget(res_widget)
        
        # 设置垂直分割器比例
        vertical_splitter.setSizes([400, 400])
        
        right_layout.addWidget(vertical_splitter)
        
        # 添加到水平分割器
        main_splitter.addWidget(left_widget)
        main_splitter.addWidget(right_widget)
        main_splitter.setSizes([500, 900])
        main_splitter.setStretchFactor(0, 1)
        main_splitter.setStretchFactor(1, 2)
        
        layout.addWidget(main_splitter)
    
    def show_context_menu(self, position):
        """显示右键菜单"""
        menu = QMenu(self)
        
        send_repeater_action = QAction("发送到 Repeater", self)
        send_repeater_action.triggered.connect(self._send_to_repeater)
        menu.addAction(send_repeater_action)
        
        send_intruder_action = QAction("发送到 Intruder", self)
        send_intruder_action.triggered.connect(self._send_to_intruder)
        menu.addAction(send_intruder_action)
        
        menu.addSeparator()
        
        copy_url_action = QAction("复制 URL", self)
        copy_url_action.triggered.connect(self._copy_url)
        menu.addAction(copy_url_action)
        
        menu.exec(self.table.viewport().mapToGlobal(position))
    
    def _send_to_repeater(self):
        """发送到Repeater"""
        if self.current_log:
            # 使用 to_dict 方法获取完整请求数据
            request_data = self.current_log.to_dict()
            # 确保有 request_body 字段
            if 'request_body' not in request_data:
                request_data['request_body'] = getattr(self.current_log, 'request_body', '')
            self.send_to_repeater.emit(request_data)
    
    def _send_to_intruder(self):
        """发送到Intruder"""
        if self.current_log:
            # 使用 to_dict 方法获取完整请求数据
            request_data = self.current_log.to_dict()
            # 确保有 request_body 字段
            if 'request_body' not in request_data:
                request_data['request_body'] = getattr(self.current_log, 'request_body', '')
            self.send_to_intruder.emit(request_data)
    
    def _copy_url(self):
        """复制URL"""
        if self.current_log:
            clipboard = QApplication.clipboard()
            clipboard.setText(self.current_log.url)
    
    def clear_logs(self):
        """清除所有日志"""
        self.logs = []
        self.table.setRowCount(0)
        self.req_text.clear()
        self.res_viewer.clear()
        self.current_log = None
        self.repeater_btn.setEnabled(False)
        self.intruder_btn.setEnabled(False)
        self.status_label.setText("")
    
    def add_log(self, log):
        """添加流量日志"""
        self.logs.append(log)
        row = self.table.rowCount()
        self.table.insertRow(row)
        
        # 【修复】提前获取状态，用于后续颜色设置
        has_success_analysis = getattr(log, 'is_success', False)
        
        # ID - 使用唯一的ID而不是行号
        id_item = QTableWidgetItem(str(log.id))
        id_item.setData(Qt.UserRole, log)  # 存储整个log对象
        # 时间
        time_item = QTableWidgetItem(log.timestamp)
        # 方法
        method_item = QTableWidgetItem(log.method)
        # URL - 【修复】根据 is_success 状态设置醒目前景色
        url_item = QTableWidgetItem(log.url)
        url_item.setToolTip(log.url)
        if has_success_analysis:
            url_item.setForeground(QColor("#00ff00"))  # 成功 - 亮绿色
        # 状态码
        status_item = QTableWidgetItem(str(log.status_code))
        
        # 根据状态码和成功状态设置颜色
        if 200 <= log.status_code < 300:
            status_item.setForeground(QColor(COLORS['success']))
        elif 300 <= log.status_code < 400:
            status_item.setForeground(QColor(COLORS['warning']))
        elif 400 <= log.status_code < 500:
            status_item.setForeground(QColor(COLORS['danger']))
        elif 500 <= log.status_code:
            status_item.setForeground(QColor("#ff6b6b"))
        
        # 【修复】先添加所有 item，再设置背景色（参考 ResultsTable 的修复）
        self.table.setItem(row, 0, id_item)
        self.table.setItem(row, 1, time_item)
        self.table.setItem(row, 2, method_item)
        self.table.setItem(row, 3, url_item)
        self.table.setItem(row, 4, status_item)
        
        # 【修复】根据成功状态设置整行背景色
        if has_success_analysis:
            bg_color = QColor(SUCCESS_BG_COLOR)
            for col in range(self.table.columnCount()):
                self.table.item(row, col).setBackground(bg_color)
        
        # 滚动到最新行
        self.table.scrollToBottom()
    
    def update_log_success(self, log_id: int, is_success: bool):
        """更新指定日志的成功状态和颜色（异步分析后调用）"""
        # 找到对应的行
        for row in range(self.table.rowCount()):
            id_item = self.table.item(row, 0)
            if id_item and int(id_item.text()) == log_id:
                # 更新日志对象的 is_success 属性
                if row < len(self.logs):
                    self.logs[row].is_success = is_success
                
                # 更新颜色
                if is_success:
                    bg_color = QColor(SUCCESS_BG_COLOR)
                    fg_color = QColor("#00ff00")  # 亮绿色
                    for col in range(self.table.columnCount()):
                        item = self.table.item(row, col)
                        if item:
                            item.setBackground(bg_color)
                            # URL列（第3列）单独设置前景色
                            if col == 3:
                                item.setForeground(fg_color)
                break
    
    def display_details(self, item):
        """显示选中请求的详情"""
        row = item.row()
        if row < len(self.logs):
            log = self.logs[row]
            self.current_log = log
            self.repeater_btn.setEnabled(True)
            self.intruder_btn.setEnabled(True)
            
            # 格式化请求 - 显示完整内容
            req_str = ""
            if not str(log.request_headers).strip().startswith(log.method):
                req_str += f"{log.method} {log.url} HTTP/1.1\n"
            req_str += f"{log.request_headers}\n\n"
            req_str += f"{log.request_body}"
            self.req_text.setPlainText(req_str)
            
            # 构建响应数据字典
            response_data = {
                'status_code': log.status_code,
                'headers': log.response_headers,
                'body': log.response_body,
                'body_bytes': log.response_body.encode('utf-8', errors='replace') if isinstance(log.response_body, str) else b'',
                'url': log.url
            }
            self.res_viewer.set_response_from_dict(response_data)
            
            # 更新状态码显示
            status_text = f"状态码: {log.status_code}"
            if 200 <= log.status_code < 300:
                status_text += " OK"
                color = COLORS['success']
            elif 300 <= log.status_code < 400:
                status_text += " Redirect"
                color = COLORS['warning']
            elif 400 <= log.status_code < 500:
                status_text += " Client Error"
                color = COLORS['danger']
            elif 500 <= log.status_code:
                status_text += " Server Error"
                color = "#ff6b6b"
            else:
                color = COLORS['text_secondary']
            
            self.status_label.setText(status_text)
            self.status_label.setStyleSheet(f"color: {color}; font-weight: bold;")
    
    def jump_to_log(self, log_id: int):
        """【新增】跳转到指定ID的流量日志"""
        for row in range(self.table.rowCount()):
            id_item = self.table.item(row, 0)
            if id_item and int(id_item.text()) == log_id:
                # 选中该行
                self.table.selectRow(row)
                # 滚动到该行
                self.table.scrollToItem(id_item, QTableWidget.PositionAtCenter)
                # 显示详情
                self.display_details(id_item)
                return True
        return False
    
    def _jump_to_success(self):
        """【新增】跳转到下一个成功的请求"""
        if not self.logs:
            return
        
        # 获取当前选中的行
        current_row = -1
        selected_items = self.table.selectedItems()
        if selected_items:
            current_row = selected_items[0].row()
        
        # 查找下一个成功的请求
        start_row = current_row + 1 if current_row >= 0 else 0
        
        # 先查找当前位置之后的
        for row in range(start_row, len(self.logs)):
            log = self.logs[row]
            if getattr(log, 'is_success', False):
                self._select_and_display(row)
                return
        
        # 如果没找到，从头开始查找（循环）
        if current_row >= 0:
            for row in range(0, min(start_row, len(self.logs))):
                log = self.logs[row]
                if getattr(log, 'is_success', False):
                    self._select_and_display(row)
                    return
    
    def _select_and_display(self, row: int):
        """【新增】选中并显示指定行的请求详情"""
        self.table.selectRow(row)
        id_item = self.table.item(row, 0)
        if id_item:
            self.table.scrollToItem(id_item, QTableWidget.PositionAtCenter)
            self.display_details(id_item)
