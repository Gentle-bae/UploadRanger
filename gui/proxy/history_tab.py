#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ProxyHistoryTab - 流量历史面板"""

import os
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTextEdit, QLineEdit,
    QPushButton, QComboBox, QLabel, QTableWidget, QTableWidgetItem,
    QHeaderView, QSplitter, QGroupBox, QCheckBox, QPlainTextEdit,
    QMenu, QDialog, QDialogButtonBox, QTextEdit as QDialogTextEdit
)
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor, QFont

from gui.themes.dark_theme import COLORS
from gui.syntax_highlighter import HTTPHighlighter
from core.config_manager import ConfigManager
from .models import InterceptedFlow
from .proxy_thread import ProxyThread

class ProxyHistoryTab(QWidget):
    """代理历史标签页"""
    
    send_to_repeater = Signal(object)
    send_to_intruder = Signal(object)
    
    def __init__(self, proxy_thread: 'ProxyThread' = None, config_manager: ConfigManager = None):
        super().__init__()
        self.proxy_thread = proxy_thread
        self.config_manager = config_manager
        self.history = []
        
        # 【修复】初始化过滤规则
        self.filter_rules = ""
        
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)
        
        # 工具栏
        toolbar = QHBoxLayout()
        
        clear_btn = QPushButton("清空历史")
        clear_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['bg_tertiary']};
                color: {COLORS['text_primary']};
                border: 1px solid {COLORS['border']};
                padding: 5px 15px;
                border-radius: 4px;
            }}
            QPushButton:hover {{
                background-color: {COLORS['border']};
            }}
        """)
        clear_btn.clicked.connect(self.clear_history)
        toolbar.addWidget(clear_btn)
        
        # 【修复】简化的过滤控制区域 - 删除复选框，只保留按钮和统计
        filter_control_layout = QHBoxLayout()
        filter_control_layout.setSpacing(10)
        
        # 【修复】配置过滤按钮 - 点击弹出对话框
        self.filter_config_btn = QPushButton("配置过滤规则...")
        self.filter_config_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['bg_tertiary']};
                color: {COLORS['text_primary']};
                border: 1px solid {COLORS['border']};
                padding: 5px 15px;
                border-radius: 4px;
            }}
            QPushButton:hover {{
                background-color: {COLORS['border']};
            }}
        """)
        self.filter_config_btn.clicked.connect(self._open_filter_dialog)
        filter_control_layout.addWidget(self.filter_config_btn)
        
        # 过滤统计标签
        self.filter_stats_label = QLabel("已显示 0 / 总计 0 条")
        self.filter_stats_label.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 11px;")
        filter_control_layout.addWidget(self.filter_stats_label)
        
        filter_control_layout.addStretch()
        
        toolbar.addLayout(filter_control_layout)
        
        toolbar.addStretch()
        
        to_repeater_btn = QPushButton("发送到 Repeater")
        to_repeater_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['accent']};
                color: white;
                border: none;
                padding: 5px 15px;
                border-radius: 4px;
            }}
            QPushButton:hover {{
                background-color: {COLORS['accent_hover']};
            }}
        """)
        to_repeater_btn.clicked.connect(self._send_to_repeater)
        toolbar.addWidget(to_repeater_btn)
        
        to_intruder_btn = QPushButton("发送到 Intruder")
        to_intruder_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['warning']};
                color: white;
                border: none;
                padding: 5px 15px;
                border-radius: 4px;
            }}
            QPushButton:hover {{
                background-color: #d97706;
            }}
        """)
        to_intruder_btn.clicked.connect(self._send_to_intruder)
        toolbar.addWidget(to_intruder_btn)
        
        layout.addLayout(toolbar)
        
        # 历史列表
        self.history_table = QTableWidget()
        self.history_table.setColumnCount(6)
        self.history_table.setHorizontalHeaderLabels(["ID", "时间", "方法", "URL", "状态码", "拦截"])
        self.history_table.setColumnWidth(0, 50)
        self.history_table.setColumnWidth(1, 70)
        self.history_table.setColumnWidth(2, 60)
        self.history_table.setColumnWidth(4, 70)
        self.history_table.setColumnWidth(5, 50)
        
        header = self.history_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Fixed)
        header.setSectionResizeMode(1, QHeaderView.Fixed)
        header.setSectionResizeMode(2, QHeaderView.Fixed)
        header.setSectionResizeMode(3, QHeaderView.Stretch)
        header.setSectionResizeMode(4, QHeaderView.Fixed)
        header.setSectionResizeMode(5, QHeaderView.Fixed)
        
        self.history_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.history_table.setAlternatingRowColors(True)
        self.history_table.setEditTriggers(QTableWidget.NoEditTriggers) 
        self.history_table.itemClicked.connect(self._on_item_selected)
        # 启用右键菜单
        self.history_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.history_table.customContextMenuRequested.connect(self._on_context_menu)
        
        # 【修复】添加行高和选中样式优化 - 移除选中边框避免覆盖URL
        self.history_table.verticalHeader().setDefaultSectionSize(28)
        self.history_table.setStyleSheet(f"""
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
            QTableWidget::item:focus {{
                border: none;
                outline: none;
            }}
            QTableWidget:focus {{
                border: 1px solid {COLORS['accent']};
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
        
        layout.addWidget(self.history_table)
        
        # 详情区域
        splitter = QSplitter(Qt.Vertical)
        splitter.setHandleWidth(6)
        splitter.setStyleSheet(f"""
            QSplitter::handle {{
                background-color: {COLORS['border']};
            }}
            QSplitter::handle:hover {{
                background-color: {COLORS['accent']};
            }}
        """)
        
        # 请求详情
        req_group = QGroupBox("请求")
        req_group.setStyleSheet(f"""
            QGroupBox {{
                font-weight: bold;
                color: {COLORS['accent']};
                border: 1px solid {COLORS['border']};
                border-radius: 6px;
                margin-top: 12px;
                padding-top: 10px;
            }}
            QGroupBox::title {{
                subcontrol-origin: margin;
                left: 12px;
                padding: 0 8px;
            }}
        """)
        req_layout = QVBoxLayout(req_group)
        req_layout.setContentsMargins(5, 5, 5, 5)
        
        self.req_detail = QPlainTextEdit()
        self.req_detail.setReadOnly(True)
        self.req_detail.setFont(QFont("Consolas", 9))
        self.highlighter_req = HTTPHighlighter(self.req_detail.document(), is_request=True)
        req_layout.addWidget(self.req_detail)
        
        splitter.addWidget(req_group)
        
        # 响应详情
        res_group = QGroupBox("响应")
        res_group.setStyleSheet(f"""
            QGroupBox {{
                font-weight: bold;
                color: {COLORS['accent']};
                border: 1px solid {COLORS['border']};
                border-radius: 6px;
                margin-top: 12px;
                padding-top: 10px;
            }}
            QGroupBox::title {{
                subcontrol-origin: margin;
                left: 12px;
                padding: 0 8px;
            }}
        """)
        res_layout = QVBoxLayout(res_group)
        res_layout.setContentsMargins(5, 5, 5, 5)
        
        self.res_detail = QPlainTextEdit()
        self.res_detail.setReadOnly(True)
        self.res_detail.setFont(QFont("Consolas", 9))
        self.highlighter_res = HTTPHighlighter(self.res_detail.document(), is_request=False)
        res_layout.addWidget(self.res_detail)
        
        splitter.addWidget(res_group)
        
        splitter.setSizes([300, 300])
        
        layout.addWidget(splitter)
    
    def add_request(self, intercepted: InterceptedFlow):
        """【修复】添加请求到历史 - 自动应用过滤规则"""
        self.history.append(intercepted)
        
        row = self.history_table.rowCount()
        self.history_table.insertRow(row)
        
        id_item = QTableWidgetItem(str(intercepted.id))
        id_item.setData(Qt.UserRole, intercepted)
        self.history_table.setItem(row, 0, id_item)
        
        self.history_table.setItem(row, 1, QTableWidgetItem(intercepted.timestamp))
        self.history_table.setItem(row, 2, QTableWidgetItem(intercepted.method))
        
        url_item = QTableWidgetItem(intercepted.url[:80])
        url_item.setToolTip(intercepted.url)
        self.history_table.setItem(row, 3, url_item)
        
        status_item = QTableWidgetItem(str(intercepted.status_code))
        if intercepted.status_code != '-':
            try:
                code = int(intercepted.status_code)
                if 200 <= code < 300:
                    status_item.setForeground(QColor(COLORS['success']))
                    # 【新增】2xx响应添加绿色背景
                    for col in range(self.history_table.columnCount()):
                        cell_item = self.history_table.item(row, col)
                        if cell_item:
                            cell_item.setBackground(QColor("#1a3d1a"))
                elif 300 <= code < 400:
                    status_item.setForeground(QColor(COLORS['warning']))
                elif code >= 400:
                    status_item.setForeground(QColor(COLORS['danger']))
            except:
                pass
        self.history_table.setItem(row, 4, status_item)
        
        intercept_item = QTableWidgetItem("是" if intercepted.intercepted else "否")
        self.history_table.setItem(row, 5, intercept_item)
        
        self.history_table.scrollToBottom()
        
        # 【修复】自动对新行应用过滤规则
        self._apply_filter_to_row(row, intercepted)
        
        # 更新过滤统计
        self._update_filter_stats()
    
    def _apply_filter_to_row(self, row: int, intercepted: InterceptedFlow):
        """【新增】对指定行应用过滤规则"""
        filter_text = getattr(self, 'filter_rules', '').strip()
        if not filter_text:
            return
        
        # 解析过滤规则
        user_excluded_domains = []
        user_excluded_paths = []
        user_excluded_methods = []
        user_excluded_body = []
        
        lines = filter_text.split('\n')
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#') or line.startswith('//'):
                continue
            
            line_lower = line.lower()
            
            if line_lower.startswith('domain:'):
                val = line.split(':', 1)[-1].strip().strip('"\'')
                if val:
                    user_excluded_domains.append(val.lower())
            elif line_lower.startswith('path:'):
                val = line.split(':', 1)[-1].strip().strip('"\'')
                if val:
                    user_excluded_paths.append(val.lower())
            elif line_lower.startswith('method:'):
                val = line.split(':', 1)[-1].strip().strip('"\'')
                if val:
                    user_excluded_methods.append(val.upper())
            elif line_lower.startswith('body:'):
                val = line.split(':', 1)[-1].strip().strip('"\'')
                if val:
                    user_excluded_body.append(val.lower())
            else:
                if line.startswith('.'):
                    user_excluded_paths.append(line.lower())
                elif line.startswith('/'):
                    user_excluded_paths.append(line.lower())
                elif line.upper() in ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'HEAD', 'PATCH']:
                    user_excluded_methods.append(line.upper())
                elif '.' in line:
                    user_excluded_domains.append(line.lower())
                else:
                    user_excluded_body.append(line.lower())
        
        # 检查当前行是否应该隐藏
        url = intercepted.url.lower()
        method = intercepted.method.upper()
        host = intercepted.host.lower()
        path = url.split('?')[0] if '?' in url else url
        body = intercepted.content.decode('utf-8', errors='ignore').lower() if intercepted.content else ''
        
        should_hide = False
        
        for domain in user_excluded_domains:
            if domain in host:
                should_hide = True
                break
        
        if not should_hide:
            for p in user_excluded_paths:
                if p in path or p in url:
                    should_hide = True
                    break
        
        if not should_hide:
            for m in user_excluded_methods:
                if m == method:
                    should_hide = True
                    break
        
        if not should_hide and body:
            for b in user_excluded_body:
                if b in body:
                    should_hide = True
                    break
        
        self.history_table.setRowHidden(row, should_hide)
    
    def update_request(self, intercepted: InterceptedFlow):
        """更新请求状态 - 修复响应显示问题"""
        for row in range(self.history_table.rowCount()):
            id_item = self.history_table.item(row, 0)
            if id_item and str(id_item.text()) == str(intercepted.id):
                # 更新状态码
                status_code = intercepted.status_code
                status_item = QTableWidgetItem(str(status_code))
                try:
                    if status_code != '-' and status_code != '无响应':
                        code = int(status_code)
                        if 200 <= code < 300:
                            status_item.setForeground(QColor(COLORS['success']))
                        elif 300 <= code < 400:
                            status_item.setForeground(QColor(COLORS['warning']))
                        elif code >= 400:
                            status_item.setForeground(QColor(COLORS['danger']))
                except:
                    pass
                self.history_table.setItem(row, 4, status_item)
                # 【关键修复】更新存储的数据，包含响应信息
                id_item.setData(Qt.UserRole, intercepted)
                # 如果当前选中的是这一行，更新详情显示
                if self.history_table.currentRow() == row:
                    self._show_request_detail(intercepted)
                break
    
    def clear_history(self):
        """【修复】清除历史 - 添加统计更新"""
        self.history.clear()
        self.history_table.setRowCount(0)
        self.req_detail.clear()
        self.res_detail.clear()
        # 【修复】更新统计标签
        self._update_filter_stats()
    
    def _on_item_selected(self, item):
        """选中历史项"""
        row = item.row()
        if row < len(self.history):
            req = self.history[row]
            self._show_request_detail(req)
    
    def _show_request_detail(self, req: InterceptedFlow):
        """显示请求详情"""
        req_text = f"{req.method} {req.url} HTTP/1.1\n"
        for k, v in req.headers.items():
            req_text += f"{k}: {v}\n"
        if req.content:
            req_text += "\n"
            try:
                req_text += req.content.decode('utf-8', errors='ignore')
            except:
                req_text += str(req.content)
        
        self.req_detail.setPlainText(req_text)
        
        if req.response_content:
            res_text = f"HTTP/1.1 {req.status_code}\n"
            for k, v in req.response_headers.items():
                res_text += f"{k}: {v}\n"
            res_text += "\n"
            try:
                res_text += req.response_content.decode('utf-8', errors='ignore')
            except:
                res_text += str(req.response_content)
            self.res_detail.setPlainText(res_text)
        else:
            self.res_detail.setPlainText("(等待响应...)")
    
    def _on_context_menu(self, pos):
        """右键菜单"""
        row = self.history_table.indexAt(pos).row()
        if row >= 0:
            self.history_table.selectRow(row)
        
        menu = QMenu(self)
        
        send_rep_action = menu.addAction("发送到 Repeater")
        send_int_action = menu.addAction("发送到 Intruder")
        menu.addSeparator()
        clear_action = menu.addAction("清空历史记录")
        send_rep_action.setEnabled(row >= 0)
        send_int_action.setEnabled(row >= 0)
        
        action = menu.exec(self.history_table.mapToGlobal(pos))
        
        if action == send_rep_action:
            self._send_to_repeater()
        elif action == send_int_action:
            self._send_to_intruder()
        elif action == clear_action:
            self.clear_history()
    
    def _send_to_repeater(self):
        """发送到Repeater"""
        row = self.history_table.currentRow()
        if row >= 0 and row < len(self.history):
            req = self.history[row]
            self.send_to_repeater.emit(req.to_dict())
    
    def _send_to_intruder(self):
        """发送到Intruder"""
        row = self.history_table.currentRow()
        if row >= 0 and row < len(self.history):
            req = self.history[row]
            self.send_to_intruder.emit(req.to_dict())
    
    def _open_filter_dialog(self):
        """【新增】打开过滤配置对话框"""
        dialog = QDialog(self)
        dialog.setWindowTitle("配置过滤规则")
        dialog.setMinimumWidth(450)
        dialog.setMinimumHeight(400)
        
        layout = QVBoxLayout(dialog)
        layout.setSpacing(15)
        
        # 说明标签
        help_label = QLabel("每行一个排除条件，支持以下格式:\n"
                           "• 域名: freebuf.com, jd.com\n"
                           "• 路径: .css, .js, .png, /api/\n"
                           "• 方法: GET, POST\n"
                           "• Body内容: 任意字符串")
        help_label.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 12px;")
        layout.addWidget(help_label)
        
        # 过滤规则输入框
        filter_edit = QDialogTextEdit()
        filter_edit.setPlainText(self.filter_rules)
        filter_edit.setPlaceholderText("# 每行一个排除条件\n"
                                       "# 域名排除\n"
                                       "freebuf.com\n"
                                       "jd.com\n\n"
                                       "# 路径排除\n"
                                       ".css\n"
                                       ".js\n"
                                       ".png")
        filter_edit.setStyleSheet(f"""
            QTextEdit {{
                background-color: {COLORS['bg_secondary']};
                color: {COLORS['text_primary']};
                border: 1px solid {COLORS['border']};
                padding: 10px;
                border-radius: 4px;
                font-family: Consolas, monospace;
                font-size: 12px;
            }}
        """)
        layout.addWidget(filter_edit)
        
        # 按钮
        btn_box = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        btn_box.accepted.connect(dialog.accept)
        btn_box.rejected.connect(dialog.reject)
        
        # 样式
        btn_box.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['accent']};
                color: white;
                border: none;
                padding: 8px 20px;
                border-radius: 4px;
                min-width: 80px;
            }}
            QPushButton:hover {{
                background-color: {COLORS['accent_hover']};
            }}
        """)
        layout.addWidget(btn_box)
        
        # 应用样式
        dialog.setStyleSheet(f"""
            QDialog {{
                background-color: {COLORS['bg_primary']};
            }}
        """)
        
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self.filter_rules = filter_edit.toPlainText()
            self._do_apply_filter()
            self._save_filter_config()
    
    def _save_filter_config(self):
        """【修复】保存过滤配置"""
        if self.config_manager:
            self.config_manager.set_filter_config(
                True,  # 过滤始终启用
                getattr(self, 'filter_rules', '')
            )
            self.config_manager.save()
    
    def _apply_filter(self):
        """【修复】应用过滤 - 直接执行，不使用防抖"""
        self._do_apply_filter()
    
    def _do_apply_filter(self):
        """【修复】实际执行过滤逻辑 - 简化处理避免卡顿"""
        filter_text = getattr(self, 'filter_rules', '').strip()
        
        # 如果没有过滤规则，显示所有行
        if not filter_text:
            for row in range(self.history_table.rowCount()):
                self.history_table.setRowHidden(row, False)
            # 更新统计
            self._update_filter_stats()
            return
        
        # 解析用户自定义过滤规则
        user_excluded_domains = []
        user_excluded_paths = []
        user_excluded_methods = []
        user_excluded_body = []
        
        lines = filter_text.split('\n')
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#') or line.startswith('//'):
                continue
            
            # 【修复】优化规则解析逻辑
            line_lower = line.lower()
            
            # 域名排除 - 包含.且不以/开头，或者是显式的domain:xxx
            if line_lower.startswith('domain:'):
                val = line.split(':', 1)[-1].strip().strip('"\'')
                if val:
                    user_excluded_domains.append(val.lower())
            # 路径排除 - 以.或/开头，或者是显式的path:xxx
            elif line_lower.startswith('path:'):
                val = line.split(':', 1)[-1].strip().strip('"\'')
                if val:
                    user_excluded_paths.append(val.lower())
            # 方法排除
            elif line_lower.startswith('method:'):
                val = line.split(':', 1)[-1].strip().strip('"\'')
                if val:
                    user_excluded_methods.append(val.upper())
            # Body排除
            elif line_lower.startswith('body:'):
                val = line.split(':', 1)[-1].strip().strip('"\'')
                if val:
                    user_excluded_body.append(val.lower())
            # 自动判断
            else:
                # 以.开头的是路径/后缀
                if line.startswith('.'):
                    user_excluded_paths.append(line.lower())
                # 以/开头的是路径
                elif line.startswith('/'):
                    user_excluded_paths.append(line.lower())
                # 大写的方法是HTTP方法
                elif line.upper() in ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'HEAD', 'PATCH']:
                    user_excluded_methods.append(line.upper())
                # 包含.的是域名
                elif '.' in line:
                    user_excluded_domains.append(line.lower())
                # 其他作为body排除
                else:
                    user_excluded_body.append(line.lower())
        
        for row in range(self.history_table.rowCount()):
            id_item = self.history_table.item(row, 0)
            if not id_item:
                continue
            
            intercepted = id_item.data(Qt.UserRole)
            if not intercepted:
                continue
            
            url = intercepted.url.lower()
            method = intercepted.method.upper()
            host = intercepted.host.lower()
            path = url.split('?')[0] if '?' in url else url
            body = intercepted.content.decode('utf-8', errors='ignore').lower() if intercepted.content else ''
            
            should_hide = False
            
            # 应用用户自定义域名排除
            for domain in user_excluded_domains:
                if domain in host:
                    should_hide = True
                    break
            
            # 应用用户自定义路径排除
            if not should_hide:
                for p in user_excluded_paths:
                    if p in path or p in url:
                        should_hide = True
                        break
            
            # 应用用户自定义方法排除
            if not should_hide:
                for m in user_excluded_methods:
                    if m == method:
                        should_hide = True
                        break
            
            # 应用用户自定义Body排除
            if not should_hide and body:
                for b in user_excluded_body:
                    if b in body:
                        should_hide = True
                        break
            
            # 设置行隐藏/显示
            self.history_table.setRowHidden(row, should_hide)
        
        # 更新过滤统计
        self._update_filter_stats()
        
        # 保存配置
        self._save_filter_config()
    
    def _update_filter_stats(self):
        """【修复】更新过滤统计信息"""
        total = self.history_table.rowCount()
        visible = 0
        for row in range(total):
            if not self.history_table.isRowHidden(row):
                visible += 1
        
        self.filter_stats_label.setText(f"已显示 {visible} / 总计 {total} 条")
        
        # 【修复】根据是否有过滤规则和过滤效果调整颜色
        has_filters = bool(getattr(self, 'filter_rules', '').strip())
        if has_filters and visible < total:
            self.filter_stats_label.setStyleSheet(f"color: {COLORS['accent']}; font-size: 11px;")
        else:
            self.filter_stats_label.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 11px;")
    
    def load_filter_config(self):
        """【修复】加载过滤配置"""
        if not self.config_manager:
            return
        
        filter_config = self.config_manager.get_filter_config()
        self.filter_rules = filter_config.get('rules', '')
        
        # 应用过滤
        self._do_apply_filter()


