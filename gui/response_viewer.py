# -*- coding: utf-8 -*-
"""Response viewer: Raw / Pretty / Render / Hex."""

import json
import re
import xml.dom.minidom

try:
    import chardet
    CHARDET_AVAILABLE = True
except Exception:
    chardet = None
    CHARDET_AVAILABLE = False

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QTabWidget, QPlainTextEdit,
    QLabel, QTableWidget, QTableWidgetItem, QHeaderView, QApplication,
    QStyledItemDelegate, QProxyStyle, QStyle, QScrollArea
)
from PySide6.QtGui import QFont, QKeySequence, QPixmap
from PySide6.QtCore import Qt, QUrl

from .syntax_highlighter import HTTPHighlighter
from .themes.dark_theme import COLORS

try:
    from PySide6.QtWebEngineWidgets import QWebEngineView
    from PySide6.QtWebEngineCore import QWebEngineSettings, QWebEnginePage
    WEBENGINE_AVAILABLE = True
except Exception:
    WEBENGINE_AVAILABLE = False
    QWebEngineView = None
    QWebEngineSettings = None
    QWebEnginePage = None


if WEBENGINE_AVAILABLE and QWebEnginePage is not None:
    class _SilentWebPage(QWebEnginePage):
        def javaScriptConsoleMessage(self, level, message, lineNumber, sourceID):
            return
else:
    _SilentWebPage = None


class _HexTable(QTableWidget):
    def keyPressEvent(self, event):
        if event.matches(QKeySequence.Copy):
            self._copy_selection()
            return
        super().keyPressEvent(event)

    def _copy_selection(self):
        # Copy just the active column for all selected rows (easy to use).
        ranges = self.selectedRanges()
        if not ranges:
            return
        current_col = self.currentColumn()
        rows = set()
        for r in ranges:
            for row in range(r.topRow(), r.bottomRow() + 1):
                rows.add(row)
        lines = []
        for row in sorted(rows):
            item = self.item(row, current_col)
            lines.append(item.text() if item else "")
        QApplication.clipboard().setText("\n".join(lines))


class _NoFocusStyle(QProxyStyle):
    def drawPrimitive(self, element, option, painter, widget=None):
        # Suppress focus rectangle drawn by style.
        if element == QStyle.PE_FrameFocusRect:
            return
        super().drawPrimitive(element, option, painter, widget)


class ResponseViewerWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._init_ui()
        self._max_bytes = 2_000_000  # prevent UI freeze on huge responses
        self._max_hex_bytes = 256_000
        # 用于 WebEngineView 刷新时存储待渲染内容
        self._pending_html: str = ""
        self._pending_url = QUrl("about:blank")

    def _detect_encoding(self, body_bytes: bytes, content_type: str = "") -> tuple:
        if not body_bytes:
            return "", "utf-8"

        charset = None
        if content_type:
            ct = content_type.lower()
            if 'charset=' in ct:
                charset = ct.split('charset=')[-1].strip().split(';')[0].strip('"\'')

        if charset:
            try:
                return body_bytes.decode(charset, errors='replace'), charset
            except Exception:
                pass

        if CHARDET_AVAILABLE and chardet is not None:
            try:
                detected = chardet.detect(body_bytes)
                if detected and detected.get('encoding'):
                    enc = detected['encoding']
                    conf = detected.get('confidence', 0)
                    if conf > 0.7:
                        try:
                            return body_bytes.decode(enc, errors='replace'), enc
                        except Exception:
                            pass
            except Exception:
                pass

        for enc in ['utf-8', 'gbk', 'gb2312', 'gb18030', 'big5', 'shift_jis', 'iso-8859-1']:
            try:
                return body_bytes.decode(enc, errors='strict'), enc
            except Exception:
                continue

        return body_bytes.decode('utf-8', errors='replace'), "utf-8"

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        self.tabs = QTabWidget()
        # 【新增】应用暗色主题到 TabWidget
        self.tabs.setStyleSheet(f"""
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
        layout.addWidget(self.tabs)

        self.raw_view = QPlainTextEdit()
        self.raw_view.setReadOnly(True)
        self.raw_view.setFont(QFont("Consolas", 10))
        # 【新增】应用暗色主题到 Raw 视图 - 移除默认颜色以允许高亮器工作
        self.raw_view.setStyleSheet(f"""
            QPlainTextEdit {{
                background-color: {COLORS['bg_secondary']};
                border: 1px solid {COLORS['border']};
                selection-background-color: {COLORS['accent']};
            }}
        """)
        self._raw_hl = HTTPHighlighter(self.raw_view.document(), is_request=False)
        self.tabs.addTab(self.raw_view, "Raw")

        self.pretty_view = QPlainTextEdit()
        self.pretty_view.setReadOnly(True)
        self.pretty_view.setFont(QFont("Consolas", 10))
        # 【新增】应用暗色主题到 Pretty 视图 - 移除默认颜色以允许高亮器工作
        self.pretty_view.setStyleSheet(f"""
            QPlainTextEdit {{
                background-color: {COLORS['bg_secondary']};
                border: 1px solid {COLORS['border']};
                selection-background-color: {COLORS['accent']};
            }}
        """)
        self._pretty_hl = HTTPHighlighter(self.pretty_view.document(), is_request=False)
        self.tabs.addTab(self.pretty_view, "Pretty")

        if WEBENGINE_AVAILABLE and QWebEngineView is not None and QWebEnginePage is not None:
            try:
                self.render_view = QWebEngineView()
                self.render_view.setPage(_SilentWebPage(self.render_view))
                self._secure_webengine(self.render_view)
                # 【修复】WebEngineView 背景设为与工具主题一致的深色背景
                # 这样原始网页如果有自己的暗色背景可以正确显示
                self.render_view.setStyleSheet(f"QWebEngineView {{ background-color: {COLORS['bg_primary']}; }}")
                self.tabs.addTab(self.render_view, "Render")
            except Exception:
                self.render_view = None
                self.render_placeholder = QLabel("WebEngine unavailable")
                self.render_placeholder.setAlignment(Qt.AlignCenter)
                self.render_placeholder.setStyleSheet(f"""
                    QLabel {{
                        background-color: {COLORS['bg_secondary']};
                        color: {COLORS['text_secondary']};
                        padding: 20px;
                    }}
                """)
                self.tabs.addTab(self.render_placeholder, "Render")
        else:
            self.render_view = None
            self.render_placeholder = QLabel("WebEngine unavailable")
            self.render_placeholder.setAlignment(Qt.AlignCenter)
            self.render_placeholder.setStyleSheet(f"""
                QLabel {{
                    background-color: {COLORS['bg_secondary']};
                    color: {COLORS['text_secondary']};
                    padding: 20px;
                }}
            """)
            self.tabs.addTab(self.render_placeholder, "Render")

        # ========== Image 视图 ==========
        # 【隐藏】Image 标签对于文件上传测试通常无用，暂不显示
        self.image_scroll = QScrollArea()
        self.image_scroll.setWidgetResizable(True)
        self.image_label = QLabel()
        self.image_label.setAlignment(Qt.AlignCenter)
        self.image_label.setStyleSheet("QLabel { background-color: #2d2d2d; }")
        self.image_label.setText("非图片响应")
        self.image_label.setMinimumSize(400, 300)
        self.image_scroll.setWidget(self.image_label)
        # 【隐藏】self.tabs.addTab(self.image_scroll, "Image")

        self.hex_table = _HexTable()
        self.hex_table.setColumnCount(3)
        self.hex_table.setHorizontalHeaderLabels(["Offset", "Hex", "ASCII"])
        self.hex_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.hex_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.hex_table.setSelectionMode(QTableWidget.ExtendedSelection)
        self.hex_table.verticalHeader().setVisible(False)
        header = self.hex_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.hex_table.setFont(QFont("Consolas", 10))
        self.hex_table.setStyle(_NoFocusStyle(self.hex_table.style()))
        # 【新增】应用暗色主题到 Hex 表格
        self.hex_table.setStyleSheet(f"""
            QTableWidget {{
                background-color: {COLORS['bg_secondary']};
                color: {COLORS['text_primary']};
                border: 1px solid {COLORS['border']};
                gridline-color: {COLORS['border']};
                selection-background-color: {COLORS['accent']};
            }}
            QTableWidget::item:focus {{
                outline: 0px;
            }}
            QTableWidget::item:selected {{
                background-color: {COLORS['accent']};
                color: white;
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
        self.tabs.addTab(self.hex_table, "Hex")

    def _secure_webengine(self, view: QWebEngineView):
        if view is None:
            return
        settings = view.settings()
        # 【修复】启用 JavaScript 以支持现代网页的 CSS 样式（包括暗色主题）
        # 由于 setHtml() 加载的是内联 HTML，安全性不受影响
        settings.setAttribute(QWebEngineSettings.WebAttribute.JavascriptEnabled, True)
        settings.setAttribute(QWebEngineSettings.WebAttribute.LocalContentCanAccessRemoteUrls, False)
        settings.setAttribute(QWebEngineSettings.WebAttribute.LocalStorageEnabled, False)
        settings.setAttribute(QWebEngineSettings.WebAttribute.LocalContentCanAccessFileUrls, False)
        settings.setDefaultTextEncoding("UTF-8")

    def _is_binary_content(self, content_type: str, body_bytes: bytes) -> bool:
        if content_type:
            ct = content_type.lower()
            text_hints = ['text/', 'json', 'xml', 'javascript', 'x-www-form-urlencoded', 'xhtml', 'svg', 'graphql']
            for th in text_hints:
                if th in ct:
                    return False
            binary_types = ['image/', 'audio/', 'video/', 'font/', 'application/octet-stream', 'application/pdf', 'application/zip']
            for bt in binary_types:
                if bt in ct:
                    return True

        if len(body_bytes) >= 4:
            if body_bytes[:4] == b'\x89PNG':
                return True
            if body_bytes[:2] == b'\xFF\xD8':
                return True
            if body_bytes[:6] in (b'GIF87a', b'GIF89a'):
                return True
            if body_bytes[:2] == b'PK':
                return True

        if len(body_bytes) > 0:
            printable = sum(1 for b in body_bytes[:1000] if 32 <= b <= 126 or b in (9, 10, 13))
            if len(body_bytes) >= 1000 and printable < len(body_bytes[:1000]) * 0.1:
                return True

        return False

    def set_response(self, headers_text: str, body_bytes: bytes, content_type: str = "", base_url: str | None = None):
        if body_bytes is None:
            body_bytes = b""

        is_binary = self._is_binary_content(content_type, body_bytes)
        display_bytes = body_bytes
        truncated = False
        if len(body_bytes) > self._max_bytes:
            display_bytes = body_bytes[: self._max_bytes]
            truncated = True

        body_text, detected_encoding = self._detect_encoding(display_bytes, content_type)

        if is_binary:
            note = f"[binary content - {len(body_bytes)} bytes - {detected_encoding}]"
            if truncated:
                note += f"\n[truncated to {self._max_bytes} bytes for display]"
            full_raw = f"{headers_text}\n\n{note}"
        else:
            full_raw = f"{headers_text}\n\n{body_text}"

        self.raw_view.setPlainText(full_raw)
        # 【新增】强制重新应用语法高亮
        if hasattr(self, '_raw_hl') and self._raw_hl:
            self._raw_hl.rehighlight()

        if not is_binary:
            try:
                pretty = self._format_pretty(body_text, content_type)
            except Exception:
                pretty = body_text
            if truncated:
                pretty = f"[truncated to {self._max_bytes} bytes for display]\n\n{pretty}"
            self.pretty_view.setPlainText(pretty)
            # 【新增】强制重新应用语法高亮
            if hasattr(self, '_pretty_hl') and self._pretty_hl:
                self._pretty_hl.rehighlight()
        else:
            self.pretty_view.setPlainText("[binary content]")

        if WEBENGINE_AVAILABLE and self.render_view and not truncated:
            try:
                # 【修复】更宽泛的HTML检测 - 检查Content-Type或HTML标签特征
                is_html_content = (
                    "html" in content_type.lower() or 
                    "xhtml" in content_type.lower() or
                    "text/plain" in content_type.lower()  # 有些HTML返回text/plain
                )
                
                # 【修复】检测body_text是否包含HTML标签特征
                if not is_html_content and not is_binary:
                    html_tags = ['<html', '<body', '<div', '<script', '<style', '<head', '<p>', '<a ', '<img', '<form']
                    body_lower = body_text[:1000].lower()
                    is_html_content = any(tag in body_lower for tag in html_tags)
                
                if is_html_content and not is_binary:
                    # 确保HTML有基础结构（不覆盖原始样式）
                    html_to_render = self._ensure_html_structure(body_text)
                    url = QUrl(base_url) if base_url else QUrl("about:blank")
                    # 【修复】使用 update() 强制刷新，并存储待渲染内容用于手动刷新
                    self._pending_html = html_to_render
                    self._pending_url = url
                    self.render_view.setHtml(html_to_render, baseUrl=url)
                else:
                    # 非 HTML 内容，显示空白页面
                    self._pending_html = ""
                    self._pending_url = QUrl("about:blank")
                    self.render_view.setHtml("")
            except Exception as e:
                # 渲染错误，显示空白
                print(f"Render error: {e}")
                self.render_view.setHtml("")
        
        # 【修复】如果 WebEngine 不可用但有 HTML 内容，尝试在下次显示时刷新
        elif body_text and not is_binary:
            html_tags = ['<html', '<body', '<div', '<script', '<style', '<head', '<p>', '<a ', '<img', '<form']
            if any(tag in body_text[:1000].lower() for tag in html_tags):
                self._pending_html = self._ensure_html_structure(body_text)
                self._pending_url = QUrl(base_url) if base_url else QUrl("about:blank")

        hex_bytes = display_bytes[: self._max_hex_bytes]
        rows = self._generate_hex_rows(hex_bytes)
        self._fill_hex_table(rows, truncated=(len(display_bytes) > self._max_hex_bytes))

        # ========== 设置 Image 视图 ==========
        self._load_image(display_bytes, content_type, truncated)

    def set_response_from_dict(self, result: dict):
        status_code = result.get('status_code', 0)
        headers = result.get('headers', '')
        body = result.get('body', '')
        body_bytes = result.get('body_bytes', None)
        url = result.get('url', None)
        analysis = result.get('analysis', {})
        if body_bytes is None:
            body_bytes = body.encode('utf-8') if isinstance(body, str) else body

        content_type = 'text/plain'
        for line in headers.split('\n'):
            if line.lower().startswith('content-type:'):
                content_type = line.split(':', 1)[1].strip()
                break

        # 【修复】格式化响应头，使用标准 HTTP 响应格式
        # HTTPHighlighter 可以高亮状态码 \b\d{3}\b
        status_text = self._get_status_text(status_code)
        headers_text = f"HTTP/1.1 {status_code} {status_text}\n{headers}"
        
        # 如果有分析结果，添加到Raw视图顶部
        if analysis:
            analysis_info = self._format_analysis_info(analysis)
            if analysis_info:
                headers_text = f"{analysis_info}\n{'='*60}\n{headers_text}"
        
        self.set_response(headers_text, body_bytes, content_type, base_url=url)
    
    def _get_status_text(self, status_code: int) -> str:
        """获取状态码对应的文本描述"""
        status_map = {
            200: "OK",
            201: "Created",
            204: "No Content",
            301: "Moved Permanently",
            302: "Found",
            304: "Not Modified",
            400: "Bad Request",
            401: "Unauthorized",
            403: "Forbidden",
            404: "Not Found",
            405: "Method Not Allowed",
            413: "Payload Too Large",
            500: "Internal Server Error",
            502: "Bad Gateway",
            503: "Service Unavailable",
        }
        return status_map.get(status_code, "")
    
    def _format_analysis_info(self, analysis: dict) -> str:
        """格式化分析结果信息"""
        lines = []
        
        # 上传状态
        is_success = analysis.get('is_success', False)
        is_failure = analysis.get('is_failure', False)
        if is_success:
            lines.append("[分析结果] 上传成功 ✓")
        elif is_failure:
            lines.append("[分析结果] 上传失败 ✗")
        else:
            lines.append("[分析结果] 状态未知 ?")
        
        # 主要消息
        message = analysis.get('message', '')
        if message:
            lines.append(f"[消息] {message}")
        
        # 上传路径
        uploaded_path = analysis.get('uploaded_path', '')
        if uploaded_path:
            lines.append(f"[上传路径] {uploaded_path}")
        
        # 错误消息
        error_msgs = analysis.get('error_messages', [])
        if error_msgs:
            lines.append(f"[错误提示] {' | '.join(error_msgs[:3])}")
        
        # 成功消息
        success_msgs = analysis.get('success_messages', [])
        if success_msgs:
            lines.append(f"[成功提示] {' | '.join(success_msgs[:3])}")
        
        # 隐藏指示器
        hidden = analysis.get('hidden_indicators', [])
        if hidden:
            lines.append(f"[隐藏提示] {' | '.join(hidden[:2])}")
        
        return '\n'.join(lines) if lines else ''

    def _format_pretty(self, text: str, content_type: str) -> str:
        if 'json' in content_type:
            try:
                return json.dumps(json.loads(text), indent=4, ensure_ascii=False)
            except Exception:
                pass
        if 'xml' in content_type:
            try:
                dom = xml.dom.minidom.parseString(text)
                return dom.toprettyxml(indent='  ')
            except Exception:
                pass
        return text

    def _generate_hex_rows(self, data: bytes, length: int = 16):
        rows = []
        if not data:
            return rows

        for i in range(0, len(data), length):
            chunk = data[i:i + length]
            hex_parts = []
            for j in range(0, length):
                if j < len(chunk):
                    hex_parts.append(f"{chunk[j]:02X}")
                else:
                    hex_parts.append("  ")

            hex_str = ""
            for j, h in enumerate(hex_parts):
                if j == 8:
                    hex_str += " "
                hex_str += h + " "
            hex_str = hex_str.rstrip()

            ascii_str = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
            offset = f"{i:08X}"
            rows.append((offset, hex_str, ascii_str))
        return rows

    def _fill_hex_table(self, rows, truncated: bool):
        self.hex_table.setRowCount(0)
        for offset, hex_str, ascii_str in rows:
            row = self.hex_table.rowCount()
            self.hex_table.insertRow(row)
            self.hex_table.setItem(row, 0, QTableWidgetItem(offset))
            self.hex_table.setItem(row, 1, QTableWidgetItem(hex_str))
            self.hex_table.setItem(row, 2, QTableWidgetItem(ascii_str))

        if truncated:
            row = self.hex_table.rowCount()
            self.hex_table.insertRow(row)
            self.hex_table.setItem(row, 0, QTableWidgetItem(""))
            self.hex_table.setItem(row, 1, QTableWidgetItem(f"[truncated to {self._max_hex_bytes} bytes for display]"))
            self.hex_table.setItem(row, 2, QTableWidgetItem(""))

    def _ensure_html_structure(self, html: str) -> str:
        """确保HTML内容有完整的基础结构，完整保留原始样式"""
        html = html.strip()
        if not html:
            return """<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
</head>
<body></body>
</html>"""
        
        # 如果已经有完整的HTML结构，直接返回（完整保留原始样式）
        if html.lower().startswith('<!doctype'):
            return html
        if html.lower().startswith('<html'):
            # 如果有 <html> 标签但不完整，尝试提取 body 内容并重新包装
            if '</html>' not in html.lower():
                # 尝试提取 body 内容
                body_match = re.search(r'<body[^>]*>(.*?)</body>', html, re.DOTALL | re.IGNORECASE)
                if body_match:
                    body_content = body_match.group(1)
                    return self._ensure_html_structure(body_content)
            return html
        
        # 片段内容，添加最小结构包装（不添加任何额外样式，保持原始内容完整）
        # 确保有 meta charset 以避免乱码
        if 'charset' not in html.lower() and 'content-type' not in html.lower():
            head = '<head><meta charset="UTF-8"></head>'
        else:
            head = '<head></head>'
        
        return f"""<!DOCTYPE html>
<html>
{head}
<body>
{html}
</body>
</html>"""

    def _update_render_view(self):
        """手动刷新 Render 视图 - 用于处理嵌套 Tab 中的 WebEngineView 刷新问题"""
        if not WEBENGINE_AVAILABLE or not self.render_view:
            return
        
        try:
            # 强制刷新 WebEngineView
            if hasattr(self, '_pending_html'):
                html = self._pending_html
                base_url = self._pending_url
                self.render_view.setHtml(html, baseUrl=base_url)
                self._pending_html = None
                self._pending_url = None
        except Exception:
            pass

    def _load_image(self, body_bytes: bytes, content_type: str, truncated: bool = False):
        """加载图片马等 Polyglot 载荷"""
        pixmap = QPixmap()

        # 根据Content-Type判断是否可能是图片
        is_likely_image = False
        if content_type:
            content_type_lower = content_type.lower()
            if content_type_lower.startswith('image/'):
                is_likely_image = True

        # 尝试从字节流加载
        if not truncated and pixmap.loadFromData(body_bytes):
            # 自动适应窗口大小，保持比例
            scaled_pixmap = pixmap.scaled(
                800, 600,
                Qt.KeepAspectRatio,
                Qt.SmoothTransformation
            )
            self.image_label.setPixmap(scaled_pixmap)
            self.image_label.setText("")
            self.image_label.setStyleSheet("QLabel { background-color: #2d2d2d; }")
        else:
            # 检查文件头
            image_formats = [
                (b'\x89PNG\r\n\x1a\n', 'PNG'),
                (b'\xFF\xD8\xFF', 'JPEG'),
                (b'GIF87a', 'GIF'),
                (b'GIF89a', 'GIF'),
                (b'RIFF', 'WEBP'),
                (b'BM', 'BMP'),
                (b'%PDF', 'PDF'),
            ]

            detected_format = None
            for magic, fmt in image_formats:
                if body_bytes.startswith(magic):
                    detected_format = fmt
                    break

            if detected_format:
                info_text = f"检测到 {detected_format} 格式，但无法显示"
                if truncated:
                    info_text += f"\n(内容被截断，仅显示前 {self._max_bytes} bytes)"
                else:
                    info_text += f"\n(大小: {len(body_bytes)} bytes)"
                self.image_label.setText(info_text)
                self.image_label.setStyleSheet("color: #f0ad4e; padding: 20px; text-align: center; background-color: #2d2d2d;")
            elif is_likely_image:
                info_text = f"无法加载图片"
                if truncated:
                    info_text += f"\n(内容被截断，仅显示前 {self._max_bytes} bytes)"
                else:
                    info_text += f"\n(Content-Type: {content_type}, 大小: {len(body_bytes)} bytes)"
                self.image_label.setText(info_text)
                self.image_label.setStyleSheet("color: #f0ad4e; padding: 20px; background-color: #2d2d2d;")
            else:
                self.image_label.setText("非图片响应")
                self.image_label.setStyleSheet("color: #888; background-color: #2d2d2d;")

            self.image_label.setPixmap(QPixmap())

    def clear(self):
        """【修复】安全清空所有视图，避免程序退出时卡住"""
        self.raw_view.clear()
        self.pretty_view.clear()
        
        # 【修复】WebEngine 在程序退出时可能已被销毁，添加异常保护
        if self.render_view and WEBENGINE_AVAILABLE:
            try:
                # 检查 render_view 是否还有有效的底层对象
                if self.render_view.isVisible():
                    self.render_view.setHtml("")
            except Exception:
                # 忽略退出时的异常
                pass
                
        self.hex_table.setRowCount(0)
