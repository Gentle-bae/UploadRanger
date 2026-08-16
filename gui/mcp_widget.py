#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""MCP Server 控制面板：默认关闭，使用独立 QProcess 管理 stdio 服务。"""
import os
import sys
import subprocess
import json
import socket
from pathlib import Path
from datetime import datetime
from PySide6.QtCore import QProcess, Qt, QTimer, QSettings
from PySide6.QtWidgets import QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QCheckBox, QPlainTextEdit, QGroupBox, QComboBox, QSpinBox

PROJECT_ROOT = Path(__file__).resolve().parents[1]
MCP_LOG_FILE = PROJECT_ROOT / ".uploadranger_mcp.log"
MCP_PID_FILE = PROJECT_ROOT / ".uploadranger_mcp.pid"
_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

class MCPPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.process = QProcess(self)
        self.process.setProcessChannelMode(QProcess.ProcessChannelMode.SeparateChannels)
        self.process.readyReadStandardError.connect(self._read_stderr)
        self.process.finished.connect(self._finished)
        self.process.errorOccurred.connect(self._error)
        self._startup_timer = QTimer(self)
        self._startup_timer.setSingleShot(True)
        self._startup_timer.timeout.connect(self._startup_timeout)
        self._log_timer = QTimer(self)
        self._log_timer.setInterval(700)
        self._log_timer.timeout.connect(self._poll_mcp_log)
        self._log_offset = 0
        self._stderr_buffer = b""
        self._seen_log_lines = set()
        self._external_server = False
        self._shutdown_done = False
        app = QApplication.instance()
        if app is not None:
            app.aboutToQuit.connect(self.shutdown)
        self.settings = QSettings("UploadRanger", "UploadRanger")
        root = QVBoxLayout(self)
        group = QGroupBox("MCP Server")
        row = QHBoxLayout(group)
        self.enabled = QCheckBox("启用 MCP 服务")
        self.enabled.toggled.connect(self._toggle_enabled)
        row.addWidget(self.enabled)
        self.start_btn = QPushButton("启动"); self.start_btn.clicked.connect(self.start_server); row.addWidget(self.start_btn)
        self.stop_btn = QPushButton("停止"); self.stop_btn.setEnabled(False); self.stop_btn.clicked.connect(self.stop_server); row.addWidget(self.stop_btn)
        self.transport_combo = QComboBox(); self.transport_combo.addItem("stdio", "stdio"); self.transport_combo.addItem("SSE", "sse"); row.addWidget(self.transport_combo)
        self.port_spin = QSpinBox(); self.port_spin.setRange(1024, 65535); self.port_spin.setValue(4554); row.addWidget(self.port_spin)
        self.transport_combo.currentIndexChanged.connect(self._refresh_config)
        self.port_spin.valueChanged.connect(self._refresh_config)
        saved_transport = self.settings.value("mcp/transport", "stdio")
        self.transport_combo.setCurrentIndex(max(0, self.transport_combo.findData(saved_transport)))
        self.port_spin.setValue(int(self.settings.value("mcp/port", 4554)))
        self.status = QLabel("状态：未运行"); row.addWidget(self.status); row.addStretch()
        root.addWidget(group)
        config_group = QGroupBox("MCP 客户端配置 JSON")
        config_layout = QVBoxLayout(config_group)
        config_layout.addWidget(QLabel("当前传输方式的 MCP JSON 配置（切换 stdio/SSE 后自动更新）："))
        self.config_editor = QPlainTextEdit()
        self.config_editor.setReadOnly(True)
        self.config_editor.setMinimumHeight(130)
        self.config_editor.setPlainText(self._default_config())
        config_layout.addWidget(self.config_editor)
        config_buttons = QHBoxLayout()
        copy_btn = QPushButton("复制 JSON")
        copy_btn.clicked.connect(self._copy_config)
        config_buttons.addWidget(copy_btn)
        config_buttons.addStretch()
        config_layout.addLayout(config_buttons)
        root.addWidget(config_group)
        self.transport_hint = QLabel()
        self.transport_hint.setWordWrap(True)
        root.addWidget(self.transport_hint)
        log_row = QHBoxLayout(); log_row.addWidget(QLabel("调用/状态日志")); clear = QPushButton("清除日志"); clear.clicked.connect(self._clear_logs); log_row.addWidget(clear); log_row.addStretch(); root.addLayout(log_row)
        self.log = QPlainTextEdit(); self.log.setReadOnly(True); root.addWidget(self.log, 1)
        self._log_timer.start()
        self._toggle_enabled(False)
        self._update_transport_hint()

    def _default_config(self):
        if self.transport_combo.currentData() == "sse":
            data = {"mcpServers": {"uploadranger": {"url": f"http://127.0.0.1:{self.port_spin.value()}/sse"}}}
        else:
            if getattr(sys, "frozen", False):
                data = {"mcpServers": {"uploadranger": {"command": sys.executable, "args": ["--mcp-server", "--transport", "stdio"]}}}
            else:
                data = {"mcpServers": {"uploadranger": {"command": sys.executable, "args": ["-m", "core.mcp.server", "--transport", "stdio"], "cwd": str(PROJECT_ROOT)}}}
        return json.dumps(data, ensure_ascii=False, indent=2)

    def _copy_config(self):
        from PySide6.QtWidgets import QApplication
        QApplication.clipboard().setText(self.config_editor.toPlainText())
        self._write_log("MCP JSON 配置已复制")

    def _refresh_config(self):
        if hasattr(self, "config_editor"):
            self.config_editor.setPlainText(self._default_config())
            self._update_transport_hint()

    def _update_transport_hint(self):
        if not hasattr(self, "transport_hint"):
            return
        if self.transport_combo.currentData() == "sse":
            self.transport_hint.setText(f"SSE 服务地址：http://127.0.0.1:{self.port_spin.value()}/sse")
        else:
            self.transport_hint.setText(f"stdio 本地进程：使用当前 Python 解释器启动，项目目录自动解析为：{PROJECT_ROOT}")

    def _write_log(self, msg):
        text = str(msg)
        key = self._log_key(text)
        if key and key in self._seen_log_lines:
            return
        if key:
            self._seen_log_lines.add(key)
            if len(self._seen_log_lines) > 5000:
                self._seen_log_lines = set(list(self._seen_log_lines)[-2500:])
        self.log.appendPlainText(f"[{datetime.now():%H:%M:%S}] {text}")

    def _poll_mcp_log(self):
        """读取由独立 MCP 客户端/stdio 进程写入的共享日志。"""
        try:
            if not MCP_LOG_FILE.exists():
                return
            with MCP_LOG_FILE.open("r", encoding="utf-8", errors="replace") as fh:
                fh.seek(self._log_offset)
                chunk = fh.read()
                self._log_offset = fh.tell()
            if chunk:
                for line in chunk.splitlines():
                    if line.strip():
                        self._append_external_log(line)
        except OSError:
            pass

    def _clear_logs(self):
        """同时清理当前视图、持久化日志和轮询偏移，避免下次启动恢复旧日志。"""
        self.log.clear()
        self._seen_log_lines.clear()
        try:
            MCP_LOG_FILE.write_text("", encoding="utf-8")
            self._log_offset = 0
        except OSError as exc:
            self._write_log(f"清除持久化 MCP 日志失败：{exc}")
        else:
            self._write_log("MCP 日志已清除（当前视图与持久化文件）")

    def _append_external_log(self, line: str):
        key = self._log_key(line)
        if not key or key in self._seen_log_lines:
            return
        self._seen_log_lines.add(key)
        self.log.appendPlainText(line)

    @staticmethod
    def _log_key(text: str) -> str:
        value = str(text).strip()
        # stderr 与文件日志格式不同，但核心 [MCP][scan_id] 消息相同。
        if "[MCP][" in value:
            value = value[value.find("[MCP]["):]
        if "] " in value:
            value = value.split("] ", 1)[-1]
        return value
    def _toggle_enabled(self, value):
        self.start_btn.setEnabled(value and self.process.state() == QProcess.ProcessState.NotRunning)
        if not value and self.process.state() != QProcess.ProcessState.NotRunning: self.stop_server()
    def start_server(self):
        if not self.enabled.isChecked() or self.process.state() != QProcess.ProcessState.NotRunning: return
        transport = self.transport_combo.currentData()
        if transport != "stdio":
            port = self.port_spin.value()
            if not self._port_available(port):
                pid = self._port_owner_pid(port)
                owner = f"PID {pid}" if pid else "未知进程"
                self.status.setText(f"状态：端口 {port} 已占用")
                self._write_log(f"启动取消：127.0.0.1:{port} 已被 {owner} 占用（WinError 10048）。请更换端口或停止已有 MCP Server。")
                return
        self.settings.setValue("mcp/transport", self.transport_combo.currentData())
        self.settings.setValue("mcp/port", self.port_spin.value())
        self._write_log("正在启动 MCP Server…"); self.status.setText("状态：启动中")
        self.process.setWorkingDirectory(str(PROJECT_ROOT))
        if getattr(sys, "frozen", False):
            command = sys.executable
            args = ["--mcp-server", "--transport", self.transport_combo.currentData()]
        else:
            command = sys.executable
            args = ["-m", "core.mcp.server", "--transport", self.transport_combo.currentData()]
        if self.transport_combo.currentData() != "stdio": args += ["--port", str(self.port_spin.value())]
        self.process.start(command, args); self.start_btn.setEnabled(False); self.stop_btn.setEnabled(True)
        # 记录本次 GUI 启动的子进程，关闭窗口/应用退出时可精确回收。
        QTimer.singleShot(150, self._write_pid_file)
        self._startup_timer.start(3000)

    def _write_pid_file(self):
        try:
            pid = int(self.process.processId())
            if pid:
                MCP_PID_FILE.write_text(str(pid), encoding="ascii")
        except (OSError, ValueError):
            pass

    @staticmethod
    def _port_available(port: int) -> bool:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.settimeout(0.25)
            return sock.connect_ex(("127.0.0.1", int(port))) != 0
        finally:
            sock.close()

    @staticmethod
    def _port_owner_pid(port: int):
        try:
            output = subprocess.run(
                ["powershell.exe", "-NoProfile", "-Command", f"(Get-NetTCPConnection -LocalPort {int(port)} -ErrorAction SilentlyContinue).OwningProcess"],
                capture_output=True, text=True, check=False, creationflags=_NO_WINDOW,
            ).stdout
            values = [line.strip() for line in output.splitlines() if line.strip().isdigit()]
            return values[0] if values else None
        except Exception:
            return None
    def stop_server(self):
        if self._shutdown_done and self.process.state() == QProcess.ProcessState.NotRunning:
            return
        pid = int(self.process.processId() or 0)
        if not pid and MCP_PID_FILE.exists():
            try:
                pid = int(MCP_PID_FILE.read_text(encoding="ascii").strip())
            except (OSError, ValueError):
                pid = 0
        if self.process.state() == QProcess.ProcessState.NotRunning:
            self._remove_pid_file(pid)
            return
        self._write_log("正在停止 MCP Server…")
        self._startup_timer.stop()
        # stdio 服务需要先关闭 stdin，否则事件循环可能继续等待协议输入。
        self.process.closeWriteChannel()
        self.process.terminate()
        if not self.process.waitForFinished(1200):
            self.process.kill()
            self.process.waitForFinished(800)
        # 即使 terminate 返回成功，也再次确认子进程是否残留；Windows 下按进程树回收。
        if pid and self._pid_running(pid):
            subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"], capture_output=True, check=False, creationflags=_NO_WINDOW)
        self._remove_pid_file(pid)
        self._shutdown_done = True

    @staticmethod
    def _pid_running(pid: int) -> bool:
        try:
            return subprocess.run(["tasklist", "/FI", f"PID eq {int(pid)}"], capture_output=True, text=True, check=False, creationflags=_NO_WINDOW).stdout.find(str(pid)) >= 0
        except Exception:
            return False

    @staticmethod
    def _remove_pid_file(pid: int = 0):
        try:
            if MCP_PID_FILE.exists():
                current = MCP_PID_FILE.read_text(encoding="ascii").strip()
                if not pid or current == str(pid):
                    MCP_PID_FILE.unlink()
        except OSError:
            pass
    def _read_stderr(self):
        raw = bytes(self.process.readAllStandardError())
        if not raw:
            return
        self._stderr_buffer += raw
        chunks = self._stderr_buffer.split(b"\n")
        self._stderr_buffer = chunks.pop() or b""
        for raw_line in chunks:
            line = self._decode_log_line(raw_line.rstrip(b"\r"))
            if line.strip():
                self._write_log(line)

    @staticmethod
    def _decode_log_line(raw_line: bytes) -> str:
        """Windows 子进程可能按 UTF-8 或系统代码页输出，按可读性选择解码。"""
        try:
            # MCP/应用日志统一 UTF-8；严格解码可避免把正确 UTF-8 误判成 GBK。
            return raw_line.decode("utf-8")
        except UnicodeDecodeError:
            return raw_line.decode("gb18030", errors="replace")
    def _finished(self, code, _status):
        if self._stderr_buffer:
            tail = self._decode_log_line(self._stderr_buffer)
            self._stderr_buffer = b""
            if tail.strip():
                self._write_log(tail)
        self._stderr_buffer = b""
        self._startup_timer.stop()
        transport = self.transport_combo.currentData()
        self.status.setText(f"状态：已停止（退出码 {code}）")
        self.stop_btn.setEnabled(False)
        self.start_btn.setEnabled(self.enabled.isChecked())
        self._write_log(f"MCP Server（{transport}）已停止，退出码 {code}")
    def _error(self, _error):
        self._startup_timer.stop()
        self.status.setText("状态：启动失败"); self._write_log(f"MCP Server 错误：{self.process.errorString()}"); self.stop_btn.setEnabled(False); self.start_btn.setEnabled(self.enabled.isChecked())
    def shutdown(self):
        if self._shutdown_done:
            return
        self._log_timer.stop()
        self.stop_server()

    def _startup_timeout(self):
        if self.process.state() == QProcess.ProcessState.Running:
            transport = self.transport_combo.currentData()
            if transport == "stdio":
                self.status.setText("状态：进程已启动（等待 MCP 握手）")
                self._write_log("Server 进程已启动；stdio MCP 通道将在首次协议交互时完成握手")
            else:
                self.status.setText(f"状态：SSE 服务运行中（127.0.0.1:{self.port_spin.value()}）")
                self._write_log(f"SSE 服务已启动；等待客户端连接 http://127.0.0.1:{self.port_spin.value()}/sse")
