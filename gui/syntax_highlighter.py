#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HTTP语法高亮 - 为请求和响应添加颜色渲染
"""

from PySide6.QtCore import Qt, QRegularExpression, QRegularExpressionMatchIterator
from PySide6.QtGui import (
    QColor, QTextCharFormat, QFont, 
    QSyntaxHighlighter
)

try:
    from .themes.dark_theme import COLORS
    DARK_THEME_AVAILABLE = True
except ImportError:
    DARK_THEME_AVAILABLE = False
    COLORS = {}


class HTTPHighlighter(QSyntaxHighlighter):
    """HTTP请求/响应语法高亮器"""
    
    def __init__(self, parent=None, is_request=True):
        super().__init__(parent)
        self.is_request = is_request
        self.highlighting_rules = []
        
        # 定义颜色 - 优先使用暗色主题，否则使用优化后的颜色
        if DARK_THEME_AVAILABLE:
            self.colors = {
                'method': QColor(COLORS['accent']),           # 主色调 - HTTP方法
                'url': QColor(COLORS['warning']),            # 警告色 - URL
                'protocol': QColor("#9b59b6"),               # 紫色 - HTTP协议版本
                'header_name': QColor(COLORS['success']),     # 成功色 - 请求头名
                'header_value': QColor(COLORS['text_primary']),       # 主文本色 - 请求头值
                'status_code': QColor(COLORS['warning']),     # 警告色 - 状态码
                'status_text': QColor(COLORS['text_primary']),        # 主文本色 - 状态文本
                'boundary': QColor(COLORS['accent']),          # 主色调 - boundary
                'filename': QColor("#f39c12"),               # 橙色 - 文件名
                'content_type': QColor(COLORS['warning']),    # 警告色 - Content-Type
                'php_code': QColor(COLORS['danger']),         # 危险色 - PHP代码
                'html_tag': QColor(COLORS['accent']),         # 主色调 - HTML标签
                'html_attr': QColor(COLORS['success']),       # 成功色 - HTML属性
                'html_value': QColor("#f39c12"),             # 橙色 - HTML属性值
                'comment': QColor(COLORS['text_secondary']),          # 次要文本色 - 注释
                'number': QColor("#9b59b6"),                 # 紫色 - 数字
                'string': QColor("#f39c12"),                 # 橙色 - 字符串
            }
        else:
            # 默认优化颜色（更亮的颜色，适合暗色背景）
            self.colors = {
                'method': QColor("#ff6b9d"),      # 亮粉色 - HTTP方法
                'url': QColor("#4ecdc4"),          # 亮青色 - URL
                'protocol': QColor("#a8e6cf"),     # 亮绿色 - HTTP协议版本
                'header_name': QColor("#ffd93d"),  # 亮黄色 - 请求头名
                'header_value': QColor("#ffffff"), # 纯白 - 请求头值
                'status_code': QColor("#ff9f40"),  # 亮橙色 - 状态码
                'status_text': QColor("#ffffff"),  # 纯白 - 状态文本
                'boundary': QColor("#ff6b9d"),     # 亮粉色 - boundary
                'filename': QColor("#ffd93d"),     # 亮黄色 - 文件名
                'content_type': QColor("#4ecdc4"), # 亮青色 - Content-Type
                'php_code': QColor("#ff6b6b"),     # 亮红色 - PHP代码
                'html_tag': QColor("#ff6b9d"),     # 亮粉色 - HTML标签
                'html_attr': QColor("#ffd93d"),    # 亮黄色 - HTML属性
                'html_value': QColor("#ffd93d"),   # 亮黄色 - HTML属性值
                'comment': QColor("#95afc0"),      # 亮灰色 - 注释
                'number': QColor("#a8e6cf"),       # 亮绿色 - 数字
                'string': QColor("#ffd93d"),       # 亮黄色 - 字符串
            }
        
        self._setup_rules()
    
    def _setup_rules(self):
        """设置高亮规则"""
        
        # HTTP方法 (GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS)
        method_format = QTextCharFormat()
        method_format.setForeground(self.colors['method'])
        method_format.setFontWeight(QFont.Bold)
        self.highlighting_rules.append(
            (QRegularExpression(r"\b(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\b"), method_format)
        )
        
        # HTTP协议版本
        protocol_format = QTextCharFormat()
        protocol_format.setForeground(self.colors['protocol'])
        self.highlighting_rules.append(
            (QRegularExpression(r"HTTP/\d\.\d"), protocol_format)
        )
        
        # 状态码 (3位数字)
        status_format = QTextCharFormat()
        status_format.setForeground(self.colors['status_code'])
        status_format.setFontWeight(QFont.Bold)
        self.highlighting_rules.append(
            (QRegularExpression(r"\b\d{3}\b"), status_format)
        )
        
        # 请求头名
        header_name_format = QTextCharFormat()
        header_name_format.setForeground(self.colors['header_name'])
        self.highlighting_rules.append(
            (QRegularExpression(r"^[A-Za-z0-9\-]+(?=:)"), header_name_format)
        )
        
        # Boundary
        boundary_format = QTextCharFormat()
        boundary_format.setForeground(self.colors['boundary'])
        self.highlighting_rules.append(
            (QRegularExpression(r"----[-\w]+"), boundary_format)
        )
        
        # Content-Disposition中的filename
        filename_format = QTextCharFormat()
        filename_format.setForeground(self.colors['filename'])
        self.highlighting_rules.append(
            (QRegularExpression(r'filename="[^"]*"'), filename_format)
        )
        
        # Content-Type
        content_type_format = QTextCharFormat()
        content_type_format.setForeground(self.colors['content_type'])
        self.highlighting_rules.append(
            (QRegularExpression(r"Content-Type:\s*[^;\n]+"), content_type_format)
        )
        
        # PHP代码
        php_format = QTextCharFormat()
        php_format.setForeground(self.colors['php_code'])
        self.highlighting_rules.append(
            (QRegularExpression(r"<\?php.*?\?>"), php_format)
        )
        
        # HTML标签
        html_tag_format = QTextCharFormat()
        html_tag_format.setForeground(self.colors['html_tag'])
        self.highlighting_rules.append(
            (QRegularExpression(r"</?[a-zA-Z][^>]*>"), html_tag_format)
        )
        
        # HTML属性
        html_attr_format = QTextCharFormat()
        html_attr_format.setForeground(self.colors['html_attr'])
        self.highlighting_rules.append(
            (QRegularExpression(r'\s[a-zA-Z\-]+(?==)'), html_attr_format)
        )
        
        # HTML属性值
        html_value_format = QTextCharFormat()
        html_value_format.setForeground(self.colors['html_value'])
        self.highlighting_rules.append(
            (QRegularExpression(r'"[^"]*"'), html_value_format)
        )
        
        # URL (http://...)
        url_format = QTextCharFormat()
        url_format.setForeground(self.colors['url'])
        self.highlighting_rules.append(
            (QRegularExpression(r"https?://[^\s\"<>]+"), url_format)
        )
        
        # 数字
        number_format = QTextCharFormat()
        number_format.setForeground(self.colors['number'])
        self.highlighting_rules.append(
            (QRegularExpression(r"\b\d+\b"), number_format)
        )
        
        # 注释
        comment_format = QTextCharFormat()
        comment_format.setForeground(self.colors['comment'])
        comment_format.setFontItalic(True)
        self.highlighting_rules.append(
            (QRegularExpression(r"#.*$"), comment_format)
        )
    
    def highlightBlock(self, text):
        """高亮文本块"""
        for pattern, format in self.highlighting_rules:
            iterator = pattern.globalMatch(text)
            while iterator.hasNext():
                match = iterator.next()
                self.setFormat(match.capturedStart(), match.capturedLength(), format)


class WebShellHighlighter(QSyntaxHighlighter):
    """WebShell语法高亮器 - 支持PHP, ASP, JSP, Python, Perl"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.highlighting_rules = []
        
        # 定义颜色
        self.colors = {
            'keyword': QColor("#ff79c6"),      # 粉色 - 关键字
            'string': QColor("#f1fa8c"),       # 黄色 - 字符串
            'comment': QColor("#6272a4"),      # 灰色 - 注释
            'number': QColor("#bd93f9"),       # 紫色 - 数字
            'tag': QColor("#ff5555"),          # 红色 - 标签 <?php, <%, %>
            'variable': QColor("#8be9fd"),     # 青色 - 变量
            'function': QColor("#50fa7b"),     # 绿色 - 函数
        }
        
        self._setup_rules()
    
    def _setup_rules(self):
        """设置高亮规则"""
        
        # 1. 关键字 (多语言混合)
        keywords = [
            # PHP
            "echo", "eval", "system", "exec", "passthru", "shell_exec", "assert", 
            "if", "else", "elseif", "while", "for", "foreach", "return", "function", 
            "class", "new", "try", "catch", "die", "exit", "isset", "empty",
            # Python
            "import", "from", "def", "print", "try", "except", "with", "as", 
            "if", "elif", "else", "return", "True", "False", "None",
            # JSP/Java
            "import", "page", "public", "private", "protected", "void", "String", 
            "int", "boolean", "new", "if", "else", "try", "catch", "return",
            # ASP/VBScript
            "Dim", "Set", "If", "Then", "Else", "End", "Function", "Sub", 
            "Response", "Request", "Server", "CreateObject",
            # Perl
            "use", "my", "print", "if", "else", "sub"
        ]
        
        keyword_format = QTextCharFormat()
        keyword_format.setForeground(self.colors['keyword'])
        keyword_format.setFontWeight(QFont.Bold)
        
        for word in keywords:
            pattern = QRegularExpression(r"\b" + word + r"\b")
            pattern.setPatternOptions(QRegularExpression.CaseInsensitiveOption)
            self.highlighting_rules.append((pattern, keyword_format))
            
        # 2. 标签
        tag_format = QTextCharFormat()
        tag_format.setForeground(self.colors['tag'])
        tag_format.setFontWeight(QFont.Bold)
        self.highlighting_rules.append((QRegularExpression(r"<\?php"), tag_format))
        self.highlighting_rules.append((QRegularExpression(r"\?>"), tag_format))
        self.highlighting_rules.append((QRegularExpression(r"<%"), tag_format))
        self.highlighting_rules.append((QRegularExpression(r"%>"), tag_format))
        self.highlighting_rules.append((QRegularExpression(r"<%@"), tag_format))
        
        # 3. 字符串 ("..." 和 '...')
        string_format = QTextCharFormat()
        string_format.setForeground(self.colors['string'])
        self.highlighting_rules.append((QRegularExpression(r"\".*?\""), string_format))
        self.highlighting_rules.append((QRegularExpression(r"'.*?'"), string_format))
        
        # 4. 注释 (#, //, --, /*...*/)
        comment_format = QTextCharFormat()
        comment_format.setForeground(self.colors['comment'])
        comment_format.setFontItalic(True)
        self.highlighting_rules.append((QRegularExpression(r"#[^\n]*"), comment_format))
        self.highlighting_rules.append((QRegularExpression(r"//[^\n]*"), comment_format))
        # ASP注释 '
        self.highlighting_rules.append((QRegularExpression(r"'[^\n]*"), comment_format))
        
        # 5. 变量 ($var, @var)
        variable_format = QTextCharFormat()
        variable_format.setForeground(self.colors['variable'])
        self.highlighting_rules.append((QRegularExpression(r"[\$@%][a-zA-Z_]\w*"), variable_format))
        
        # 6. 函数调用 (func(...))
        function_format = QTextCharFormat()
        function_format.setForeground(self.colors['function'])
        self.highlighting_rules.append((QRegularExpression(r"\b[a-zA-Z_]\w*(?=\()"), function_format))
        
        # 7. 数字
        number_format = QTextCharFormat()
        number_format.setForeground(self.colors['number'])
        self.highlighting_rules.append((QRegularExpression(r"\b\d+\b"), number_format))

    def highlightBlock(self, text):
        """高亮文本块"""
        for pattern, format in self.highlighting_rules:
            iterator = pattern.globalMatch(text)
            while iterator.hasNext():
                match = iterator.next()
                self.setFormat(match.capturedStart(), match.capturedLength(), format)


class JSONHighlighter(QSyntaxHighlighter):
    """JSON语法高亮器"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.highlighting_rules = []
        
        self.colors = {
            'key': QColor("#50fa7b"),      # 绿色 - 键
            'string': QColor("#f1fa8c"),   # 黄色 - 字符串
            'number': QColor("#bd93f9"),   # 紫色 - 数字
            'boolean': QColor("#ff79c6"),  # 粉色 - 布尔值
            'null': QColor("#6272a4"),     # 灰色 - null
        }
        
        self._setup_rules()
    
    def _setup_rules(self):
        """设置高亮规则"""
        
        # JSON键
        key_format = QTextCharFormat()
        key_format.setForeground(self.colors['key'])
        self.highlighting_rules.append(
            (QRegularExpression(r'"[^"]*"(?=\s*:)'), key_format)
        )
        
        # 字符串值
        string_format = QTextCharFormat()
        string_format.setForeground(self.colors['string'])
        self.highlighting_rules.append(
            (QRegularExpression(r':\s*"[^"]*"'), string_format)
        )
        
        # 数字
        number_format = QTextCharFormat()
        number_format.setForeground(self.colors['number'])
        self.highlighting_rules.append(
            (QRegularExpression(r':\s*\-?\d+\.?\d*'), number_format)
        )
        
        # 布尔值
        bool_format = QTextCharFormat()
        bool_format.setForeground(self.colors['boolean'])
        self.highlighting_rules.append(
            (QRegularExpression(r'\b(true|false)\b'), bool_format)
        )
        
        # null
        null_format = QTextCharFormat()
        null_format.setForeground(self.colors['null'])
        self.highlighting_rules.append(
            (QRegularExpression(r'\bnull\b'), null_format)
        )
    
    def highlightBlock(self, text):
        """高亮文本块"""
        for pattern, format in self.highlighting_rules:
            iterator = pattern.globalMatch(text)
            while iterator.hasNext():
                match = iterator.next()
                self.setFormat(match.capturedStart(), match.capturedLength(), format)
