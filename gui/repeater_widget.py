#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Repeater module (minimal, ASCII-only)."""

import asyncio
import httpx
from PySide6.QtCore import Qt, Signal, QThread
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QComboBox,
    QPushButton, QSplitter, QGroupBox, QPlainTextEdit
)

from .themes.dark_theme import COLORS
from .syntax_highlighter import HTTPHighlighter
from .response_viewer import ResponseViewerWidget


class RepeaterWorker(QThread):
    finished = Signal(dict)
    error = Signal(str)

    def __init__(self, request_data: dict):
        super().__init__()
        self.request_data = request_data
        self._loop = None

    def run(self):
        try:
            self._loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self._loop)
            result = self._loop.run_until_complete(self._send_request())
            self.finished.emit(result)
        except Exception as e:
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

        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url

        headers.pop('Content-Length', None)
        headers.pop('content-length', None)

        async with httpx.AsyncClient(verify=False, timeout=30, follow_redirects=True) as client:
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
        self._build_ui()

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

        layout.addLayout(control_layout)

        splitter = QSplitter(Qt.Vertical)

        req_group = QGroupBox("Request")
        req_layout = QVBoxLayout(req_group)
        self.req_edit = QPlainTextEdit()
        self.req_edit.setFont(QFont("Consolas", 10))
        self.highlighter_req = HTTPHighlighter(self.req_edit.document(), is_request=True)
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
        req_text = f"{method} {url} HTTP/1.1\n{headers}\n\n{body}"
        self.req_edit.setPlainText(req_text)
        self.res_display.clear()
        self.res_status_label.setText("")

    def _parse_request(self, req_text: str):
        lines = req_text.strip().split('\n')
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
        body = '\n'.join(lines[body_start:]) if body_start > 0 else ''
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

        self.send_btn.setEnabled(False)
        self.send_btn.setText("Sending...")

        self.worker = RepeaterWorker({
            'url': url,
            'method': method,
            'headers': headers,
            'body': body,
        })
        self.worker.finished.connect(self._on_request_finished)
        self.worker.error.connect(self._on_request_error)
        self.worker.start()

    def _on_request_finished(self, result: dict):
        self.send_btn.setEnabled(True)
        self.send_btn.setText("Send")

        status_code = result.get('status_code', 0)
        headers = result.get('headers', '')

        content_type = 'text/plain'
        for line in headers.split('\n'):
            if line.lower().startswith('content-type:'):
                content_type = line.split(':', 1)[1].strip()
                break

        self._update_status_label(status_code)
        self.res_display.set_response_from_dict(result)

    def _on_request_error(self, error_msg: str):
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


class RepeaterWidget(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        self.tab = RepeaterTab("Repeater")
        layout.addWidget(self.tab)

    def load_request(self, request_data: dict):
        self.tab.load_request(request_data)
