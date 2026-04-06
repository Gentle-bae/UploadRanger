#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
新手快速向导：填写扫描页常用字段并跳转「扫描」标签。
"""

import ssl
from urllib.request import Request, urlopen
from PySide6.QtWidgets import (
    QWizard,
    QWizardPage,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QFormLayout,
    QPushButton,
    QMessageBox,
)
from PySide6.QtCore import QThread, Signal


class _DiscoverWorker(QThread):
    """后台线程发现上传点"""
    finished = Signal(list)
    error = Signal(str)
    
    def __init__(self, url: str):
        super().__init__()
        self._url = url
    
    def run(self):
        try:
            # 如果 URL 不含协议头，自动补全
            target_url = self._url.strip()
            if not target_url.startswith(('http://', 'https://')):
                target_url = 'http://' + target_url
            
            req = Request(
                target_url,
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
                },
            )
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with urlopen(req, timeout=15, context=ctx) as resp:
                html = resp.read().decode("utf-8", errors="replace")
            
            # 解析表单
            from core.form_parser import FormParser
            items = FormParser.collect_upload_hints(target_url, html)
            self.finished.emit(items)
        except Exception as e:
            self.error.emit(str(e))


class _TargetPage(QWizardPage):
    def __init__(self):
        super().__init__()
        self.setTitle("目标与参数")
        self.setSubTitle("上传接口地址与表单中的文件字段名")
        self._worker = None
        self._discovering = False
        
        form = QFormLayout()
        
        # URL 输入行
        url_layout = QHBoxLayout()
        self._url = QLineEdit()
        self._url.setPlaceholderText("https://example.com/upload")
        url_layout.addWidget(self._url, 1)
        
        # 自动抓取按钮
        self._discover_btn = QPushButton("发现上传点")
        self._discover_btn.setToolTip("自动分析页面表单，获取上传接口和字段名")
        self._discover_btn.clicked.connect(self._on_discover)
        url_layout.addWidget(self._discover_btn)
        
        form.addRow("上传 URL *:", url_layout)
        
        # 文件字段名
        param_layout = QHBoxLayout()
        self._param = QLineEdit("file")
        param_layout.addWidget(self._param, 1)
        
        self._auto_label = QLabel("")
        self._auto_label.setStyleSheet("color: #888; font-size: 10px;")
        param_layout.addWidget(self._auto_label)
        
        form.addRow("文件字段名 *:", param_layout)
        
        self._upload_dir = QLineEdit()
        self._upload_dir.setPlaceholderText("http://example.com/uploads/ （可选，用于二次验证）")
        form.addRow("上传目录 URL:", self._upload_dir)
        
        self.setLayout(form)
        self.registerField("targetUrl*", self._url)
        self.registerField("fileParam*", self._param)
        self.registerField("uploadDir", self._upload_dir)
        self._url.textChanged.connect(lambda _: self._on_url_changed())
    
    def _on_url_changed(self):
        """URL变化时清空自动填充提示"""
        self._auto_label.setText("")
        self.completeChanged.emit()
    
    def _on_discover(self):
        """点击发现上传点"""
        url = self._url.text().strip()
        if not url:
            QMessageBox.warning(self, "提示", "请先填写上传 URL")
            return
        
        self._discover_btn.setEnabled(False)
        self._discover_btn.setText("分析中...")
        self._discovering = True
        
        self._worker = _DiscoverWorker(url)
        self._worker.finished.connect(self._on_discover_ok)
        self._worker.error.connect(self._on_discover_err)
        self._worker.start()
    
    def _on_discover_ok(self, items):
        """发现成功"""
        self._discover_btn.setEnabled(True)
        self._discover_btn.setText("发现上传点")
        self._discovering = False
        
        if not items:
            QMessageBox.information(
                self,
                "发现上传点",
                "未找到上传表单。\n请确认 URL 指向含 <input type=file> 的页面。"
            )
            return
        
        # 自动填充第一个结果
        picked = items[0]
        file_field = picked.get("file_field") or "file"
        self._param.setText(file_field)
        self._auto_label.setText(f"✓ 已自动填充: {file_field}")
        self._log(f"自动检测到字段: {file_field}")
    
    def _on_discover_err(self, msg):
        """发现失败"""
        self._discover_btn.setEnabled(True)
        self._discover_btn.setText("发现上传点")
        self._discovering = False
        QMessageBox.warning(self, "发现失败", f"自动抓取失败:\n{msg}")
        self._log(f"发现失败: {msg}")
    
    def _log(self, msg):
        """记录日志"""
        print(f"[向导] {msg}")
    
    def isComplete(self) -> bool:
        return bool(self._url.text().strip())


class _IntroPage(QWizardPage):
    def __init__(self):
        super().__init__()
        self.setTitle("欢迎使用向导")
        self.setSubTitle("将引导你填写上传测试的最小必填信息")
        lay = QVBoxLayout(self)
        lay.addWidget(
            QLabel(
                "适用场景：已知上传接口 URL，需要快速开始一轮扫描。\n\n"
                "1. 填写目标 URL（上传页面或接口）\n"
                "2. 可点击「发现上传点」自动抓取字段名\n"
                "3. 点击下一步完成配置\n\n"
                "高级选项（Raw 上传、环境指纹、Payload 上限等）请在「扫描」页调整。"
            )
        )
        lay.addStretch()


class _DonePage(QWizardPage):
    def __init__(self):
        super().__init__()
        self.setTitle("完成")
        self.setSubTitle("点击「完成」后，将填入扫描页、切换到「扫描」标签并自动开始一次扫描")
        lay = QVBoxLayout(self)
        lay.addWidget(
            QLabel(
                "提示：\n"
                "• 「Payload 数量」为单次扫描上限，实际请求数不超过内置词库条数；\n"
                "• 开启「环境指纹」后，无效环境策略会被过滤，请求数可能更少。"
            )
        )
        lay.addStretch()


class QuickScanWizard(QWizard):
    """主窗口调用的极简向导。"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("UploadRanger — 快速向导")
        self.setOption(QWizard.WizardOption.NoBackButtonOnStartPage, True)
        self.addPage(_IntroPage())
        self.addPage(_TargetPage())
        self.addPage(_DonePage())
