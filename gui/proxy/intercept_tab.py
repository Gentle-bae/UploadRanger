#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ProxyInterceptTab - 拦截面板"""

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTextEdit,
    QPushButton, QLabel, QTableWidget, QTableWidgetItem,
    QHeaderView, QSplitter, QGroupBox, QCheckBox, QPlainTextEdit,
    QMenu
)
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor, QFont

from gui.themes.dark_theme import COLORS
from gui.syntax_highlighter import HTTPHighlighter
from .models import InterceptedFlow
from .proxy_thread import ProxyThread

class ProxyInterceptTab(QWidget):
    """代理拦截标签页"""
    
    send_to_repeater = Signal(object)
    send_to_intruder = Signal(object)
    
    def __init__(self, proxy_thread: 'ProxyThread' = None):
        super().__init__()
        self.proxy_thread = proxy_thread
        self.intercepted_list = []
        self.current_flow_id = None
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)
        
        # 拦截控制栏
        control_layout = QHBoxLayout()
        
        self.forward_btn = QPushButton("放行 (Forward)")
        self.forward_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['success']};
                color: white;
                border: none;
                padding: 8px 20px;
                border-radius: 4px;
                font-weight: bold;
            }}
            QPushButton:hover {{
                background-color: #059669;
            }}
            QPushButton:disabled {{
                background-color: {COLORS['bg_tertiary']};
                color: {COLORS['text_secondary']};
            }}
        """)
        self.forward_btn.setEnabled(False)
        self.forward_btn.clicked.connect(self._forward)
        control_layout.addWidget(self.forward_btn)
        
        self.drop_btn = QPushButton("丢弃 (Drop)")
        self.drop_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['danger']};
                color: white;
                border: none;
                padding: 8px 20px;
                border-radius: 4px;
                font-weight: bold;
            }}
            QPushButton:hover {{
                background-color: #dc2626;
            }}
            QPushButton:disabled {{
                background-color: {COLORS['bg_tertiary']};
                color: {COLORS['text_secondary']};
            }}
        """)
        self.drop_btn.setEnabled(False)
        self.drop_btn.clicked.connect(self._drop)
        control_layout.addWidget(self.drop_btn)
        
        # 【新增】放行全部按钮
        self.forward_all_btn = QPushButton("放行全部")
        self.forward_all_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['info']};
                color: white;
                border: none;
                padding: 8px 20px;
                border-radius: 4px;
                font-weight: bold;
            }}
            QPushButton:hover {{
                background-color: #0284c7;
            }}
            QPushButton:disabled {{
                background-color: {COLORS['bg_tertiary']};
                color: {COLORS['text_secondary']};
            }}
        """)
        self.forward_all_btn.setEnabled(False)
        self.forward_all_btn.clicked.connect(self._forward_all)
        control_layout.addWidget(self.forward_all_btn)
        
        control_layout.addStretch()
        
        # 【新增】发送到模块按钮
        send_layout = QHBoxLayout()
        send_layout.setSpacing(8)
        
        to_repeater_btn = QPushButton("发送到 Repeater")
        to_repeater_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['accent']};
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
            }}
            QPushButton:hover {{
                background-color: {COLORS['accent_hover']};
            }}
        """)
        to_repeater_btn.clicked.connect(self._send_to_repeater)
        send_layout.addWidget(to_repeater_btn)
        
        to_intruder_btn = QPushButton("发送到 Intruder")
        to_intruder_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['warning']};
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
            }}
            QPushButton:hover {{
                background-color: #d97706;
            }}
        """)
        to_intruder_btn.clicked.connect(self._send_to_intruder)
        send_layout.addWidget(to_intruder_btn)
        
        control_layout.addLayout(send_layout)
        
        layout.addLayout(control_layout)
        
        # 分割器
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
        
        # 拦截列表
        list_widget = QWidget()
        list_layout = QVBoxLayout(list_widget)
        list_layout.setContentsMargins(0, 0, 0, 0)
        
        list_label = QLabel("拦截列表")
        list_label.setStyleSheet(f"font-weight: bold; color: {COLORS['accent']}; font-size: 14px;")
        list_layout.addWidget(list_label)
        
        self.intercept_table = QTableWidget()
        self.intercept_table.setColumnCount(4)
        self.intercept_table.setHorizontalHeaderLabels(["ID", "时间", "方法", "URL"])
        self.intercept_table.setColumnWidth(0, 50)
        self.intercept_table.setColumnWidth(1, 70)
        self.intercept_table.setColumnWidth(2, 60)
        
        header = self.intercept_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Fixed)
        header.setSectionResizeMode(1, QHeaderView.Fixed)
        header.setSectionResizeMode(2, QHeaderView.Fixed)
        header.setSectionResizeMode(3, QHeaderView.Stretch)
        
        self.intercept_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.intercept_table.setAlternatingRowColors(True)
        self.intercept_table.setEditTriggers(QTableWidget.NoEditTriggers)  # 【修复】禁用编辑，防止双击进入编辑模式
        self.intercept_table.itemClicked.connect(self._on_item_selected)
        # 启用右键菜单
        self.intercept_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.intercept_table.customContextMenuRequested.connect(self._on_context_menu)
        
        # 【修复】添加行高和选中样式优化 - 移除选中边框避免覆盖URL
        self.intercept_table.verticalHeader().setDefaultSectionSize(28)
        self.intercept_table.setStyleSheet(f"""
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
        
        list_layout.addWidget(self.intercept_table)
        
        splitter.addWidget(list_widget)
        
        # 请求详情（可编辑）
        detail_widget = QWidget()
        detail_layout = QVBoxLayout(detail_widget)
        detail_layout.setContentsMargins(0, 0, 0, 0)
        
        detail_label = QLabel("请求详情 (可编辑后放行)")
        detail_label.setStyleSheet(f"font-weight: bold; color: {COLORS['accent']}; font-size: 14px;")
        detail_layout.addWidget(detail_label)
        
        self.request_edit = QPlainTextEdit()
        self.request_edit.setFont(QFont("Consolas", 10))
        self.highlighter = HTTPHighlighter(self.request_edit.document(), is_request=True)
        detail_layout.addWidget(self.request_edit)
        
        splitter.addWidget(detail_widget)
        
        splitter.setSizes([200, 400])
        
        layout.addWidget(splitter)
    
    def add_intercepted(self, intercepted: InterceptedFlow):
        """添加拦截请求"""
        self.intercepted_list.append(intercepted)
        
        row = self.intercept_table.rowCount()
        self.intercept_table.insertRow(row)
        
        id_item = QTableWidgetItem(str(intercepted.id))
        id_item.setData(Qt.UserRole, intercepted)
        self.intercept_table.setItem(row, 0, id_item)
        
        self.intercept_table.setItem(row, 1, QTableWidgetItem(intercepted.timestamp))
        self.intercept_table.setItem(row, 2, QTableWidgetItem(intercepted.method))
        
        url_item = QTableWidgetItem(intercepted.url[:80])
        url_item.setToolTip(intercepted.url)
        self.intercept_table.setItem(row, 3, url_item)
        
        # 自动选中
        self.intercept_table.selectRow(row)
        self._on_item_selected(self.intercept_table.item(row, 0))
        
        # 【新增】启用放行全部按钮
        self.forward_all_btn.setEnabled(True)
    
    def _on_item_selected(self, item):
        """选中拦截项"""
        row = item.row()
        if row < len(self.intercepted_list):
            intercepted = self.intercepted_list[row]
            self.current_flow_id = intercepted.id
            
            req_text = f"{intercepted.method} {intercepted.url} HTTP/1.1\n"
            for k, v in intercepted.headers.items():
                req_text += f"{k}: {v}\n"
            if intercepted.content:
                req_text += "\n"
                try:
                    req_text += intercepted.content.decode('utf-8', errors='ignore')
                except:
                    req_text += str(intercepted.content)
            
            self.request_edit.setPlainText(req_text)
            
            if not intercepted.released:
                self.forward_btn.setEnabled(True)
                self.drop_btn.setEnabled(True)
            else:
                self.forward_btn.setEnabled(False)
                self.drop_btn.setEnabled(False)
    
    def _on_context_menu(self, pos):
        """右键菜单"""
        row = self.intercept_table.indexAt(pos).row()
        if row >= 0:
            self.intercept_table.selectRow(row)
            item = self.intercept_table.item(row, 0)
            if item:
                self._on_item_selected(item)
        
        menu = QMenu(self)
        
        send_rep_action = menu.addAction("发送到 Repeater")
        send_int_action = menu.addAction("发送到 Intruder")
        menu.addSeparator()
        forward_action = menu.addAction("放行 (Forward)")
        drop_action = menu.addAction("丢弃 (Drop)")
        send_rep_action.setEnabled(row >= 0)
        send_int_action.setEnabled(row >= 0)
        forward_action.setEnabled(row >= 0)
        drop_action.setEnabled(row >= 0)
        
        action = menu.exec(self.intercept_table.mapToGlobal(pos))
        
        if action == send_rep_action:
            self._send_to_repeater()
        elif action == send_int_action:
            self._send_to_intruder()
        elif action == forward_action:
            self._forward()
        elif action == drop_action:
            self._drop()
    
    def _send_to_repeater(self):
        """发送到 Repeater"""
        row = self.intercept_table.currentRow()
        if row >= 0 and row < len(self.intercepted_list):
            req = self.intercepted_list[row]
            self.send_to_repeater.emit(req.to_dict())
    
    def _send_to_intruder(self):
        """发送到 Intruder"""
        row = self.intercept_table.currentRow()
        if row >= 0 and row < len(self.intercepted_list):
            req = self.intercepted_list[row]
            self.send_to_intruder.emit(req.to_dict())
    
    def _forward(self):
        """放行请求 - 【修复】自动选择下一个请求"""
        if self.current_flow_id and self.proxy_thread:
            modified_text = self.request_edit.toPlainText()
            
            try:
                lines = modified_text.split('\n')
                body_start = 0
                for i, line in enumerate(lines[1:], 1):
                    if line.strip() == '':
                        body_start = i + 1
                        break
                
                body = '\n'.join(lines[body_start:]) if body_start > 0 else ''
                modified_content = body.encode('utf-8') if body else None
            except:
                modified_content = None
            
            self.proxy_thread.forward_request(self.current_flow_id, modified_content)
            
            # 从列表中移除并获取当前行号
            removed_row = -1
            for i, intercepted in enumerate(self.intercepted_list):
                if intercepted.id == self.current_flow_id:
                    intercepted.released = True
                    removed_row = i
                    self.intercept_table.removeRow(i)
                    self.intercepted_list.pop(i)
                    break
            
            # 【关键修复】自动选择下一个请求
            if self.intercepted_list:
                # 选择下一个请求（如果存在）
                next_row = min(removed_row, len(self.intercepted_list) - 1)
                if next_row >= 0:
                    self.intercept_table.selectRow(next_row)
                    self._on_item_selected(self.intercept_table.item(next_row, 0))
            else:
                # 没有更多请求，清空编辑区
                self.request_edit.clear()
                self.current_flow_id = None
                self.forward_btn.setEnabled(False)
                self.drop_btn.setEnabled(False)
                self.forward_all_btn.setEnabled(False)
    
    def _drop(self):
        """丢弃请求 - 【修复】自动选择下一个请求"""
        if self.current_flow_id and self.proxy_thread:
            self.proxy_thread.drop_request(self.current_flow_id)
            
            # 从列表中移除并获取当前行号
            removed_row = -1
            for i, intercepted in enumerate(self.intercepted_list):
                if intercepted.id == self.current_flow_id:
                    intercepted.dropped = True
                    intercepted.released = True
                    removed_row = i
                    self.intercept_table.removeRow(i)
                    self.intercepted_list.pop(i)
                    break
            
            # 【关键修复】自动选择下一个请求
            if self.intercepted_list:
                # 选择下一个请求（如果存在）
                next_row = min(removed_row, len(self.intercepted_list) - 1)
                if next_row >= 0:
                    self.intercept_table.selectRow(next_row)
                    self._on_item_selected(self.intercept_table.item(next_row, 0))
            else:
                # 没有更多请求，清空编辑区
                self.request_edit.clear()
                self.current_flow_id = None
                self.forward_btn.setEnabled(False)
                self.drop_btn.setEnabled(False)
                self.forward_all_btn.setEnabled(False)
    
    def _forward_all(self):
        """【优化】放行所有拦截的请求 - 使用批量异步处理"""
        if not self.proxy_thread:
            return
        
        # 复制列表避免遍历时修改
        flows_to_forward = [f for f in self.intercepted_list if not f.released]
        
        if not flows_to_forward:
            return
        
        # 【关键修复】批量放行所有请求，立即设置 released 标志
        for intercepted in flows_to_forward:
            intercepted.released = True  # 立即标记为已释放，避免重复处理
            # 使用原始内容直接放行
            self.proxy_thread.forward_request(intercepted.id, None)
        
        # 【关键修复】延迟清理表格，给异步事件一些时间处理
        from PySide6.QtCore import QTimer
        QTimer.singleShot(100, self._clean_forwarded_flows)
    
    def _clean_forwarded_flows(self):
        """【修复】清理已放行的流量 - 正确获取对象并比较ID"""
        # 获取所有已释放的流量ID集合
        released_ids = {f.id for f in self.intercepted_list if f.released}
        
        if not released_ids:
            return
        
        # 从后向前删除，避免索引错乱
        rows_to_remove = []
        for row in range(self.intercept_table.rowCount() - 1, -1, -1):
            item = self.intercept_table.item(row, 0)
            if item:
                # 【修复】Qt.UserRole 存储的是 InterceptedFlow 对象，不是ID字符串
                flow_obj = item.data(Qt.UserRole)
                if flow_obj and hasattr(flow_obj, 'id') and flow_obj.id in released_ids:
                    rows_to_remove.append(row)
        
        # 删除标记的行
        for row in rows_to_remove:
            self.intercept_table.removeRow(row)
        
        # 【修复】更新列表 - 只保留未释放的
        self.intercepted_list = [f for f in self.intercepted_list if not f.released]
        
        # 清空编辑区
        self.request_edit.clear()
        self.current_flow_id = None
        self.forward_btn.setEnabled(False)
        self.drop_btn.setEnabled(False)
        
        # 【修复】只有当还有未释放的请求时才禁用放行全部按钮
        has_unreleased = any(not f.released for f in self.intercepted_list)
        self.forward_all_btn.setEnabled(has_unreleased)
    
    def clear_intercepted(self):
        """【新增】清空所有拦截的请求"""
        # 丢弃所有未释放的请求
        for intercepted in self.intercepted_list:
            if not intercepted.released and self.proxy_thread:
                self.proxy_thread.drop_request(intercepted.id)
        
        # 清空列表和表格
        self.intercepted_list.clear()
        self.intercept_table.setRowCount(0)
        self.request_edit.clear()
        self.current_flow_id = None
        self.forward_btn.setEnabled(False)
        self.drop_btn.setEnabled(False)
        self.forward_all_btn.setEnabled(False)


