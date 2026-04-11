#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
深色主题样式
"""

from PySide6.QtWidgets import QApplication
from PySide6.QtGui import QPalette, QColor

# 颜色定义
COLORS = {
    'bg_primary': '#1e1e2e',
    'bg_secondary': '#252536',
    'bg_tertiary': '#2d2d44',
    'accent': '#7c3aed',
    'accent_hover': '#8b5cf6',
    'success': '#10b981',
    'warning': '#f59e0b',
    'danger': '#ef4444',
    'info': '#3b82f6',
    'text_primary': '#f1f1f4',
    'text_secondary': '#a0a0b0',
    'border': '#3d3d5c',
}

DARK_STYLESHEET = f"""
/* 全局样式 */
QWidget {{
    background-color: {COLORS['bg_primary']};
    color: {COLORS['text_primary']};
    font-family: "Microsoft YaHei", "WenQuanYi Micro Hei", "Noto Sans CJK SC", "Source Han Sans SC", "SimHei", sans-serif;
    font-size: 13px;
}}

/* 主窗口 */
QMainWindow {{
    background-color: {COLORS['bg_primary']};
}}

/* 标签页 */
QTabWidget::pane {{
    border: 1px solid {COLORS['border']};
    background-color: {COLORS['bg_secondary']};
    border-radius: 4px;
    padding: 0px;
    margin: 0px;
}}

QTabBar::tab {{
    background-color: {COLORS['bg_tertiary']};
    color: {COLORS['text_secondary']};
    padding: 10px 20px;
    margin-right: 2px;
    border-top-left-radius: 4px;
    border-top-right-radius: 4px;
}}

QTabBar::tab:selected {{
    background-color: {COLORS['accent']};
    color: {COLORS['text_primary']};
}}

QTabBar::tab:hover:!selected {{
    background-color: {COLORS['bg_secondary']};
    color: {COLORS['text_primary']};
}}

/* 按钮 */
QPushButton {{
    background-color: {COLORS['accent']};
    color: white;
    border: none;
    padding: 10px 24px;
    border-radius: 6px;
    font-weight: bold;
}}

QPushButton:hover {{
    background-color: {COLORS['accent_hover']};
}}

QPushButton:pressed {{
    background-color: {COLORS['accent']};
}}

QPushButton:disabled {{
    background-color: {COLORS['bg_tertiary']};
    color: {COLORS['text_secondary']};
}}

QPushButton#danger {{
    background-color: {COLORS['danger']};
}}

QPushButton#danger:hover {{
    background-color: #dc2626;
}}

QPushButton#success {{
    background-color: {COLORS['success']};
}}

QPushButton#success:hover {{
    background-color: #059669;
}}

/* 输入框 */
QLineEdit {{
    background-color: {COLORS['bg_secondary']};
    color: {COLORS['text_primary']};
    border: 1px solid {COLORS['border']};
    padding: 8px 12px;
    border-radius: 4px;
}}

QLineEdit:focus {{
    border: 1px solid {COLORS['accent']};
}}

QLineEdit::placeholder {{
    color: {COLORS['text_secondary']};
}}

/* 文本编辑框 */
QTextEdit {{
    background-color: {COLORS['bg_secondary']};
    color: {COLORS['text_primary']};
    border: 1px solid {COLORS['border']};
    border-radius: 4px;
    padding: 8px;
}}

QTextEdit QScrollBar:vertical {{
    background-color: {COLORS['bg_tertiary']};
    width: 12px;
    border-radius: 6px;
}}

QTextEdit QScrollBar::handle:vertical {{
    background-color: {COLORS['accent']};
    border-radius: 6px;
    min-height: 30px;
}}

/* 复选框 - 修复白色问题 */
QCheckBox {{
    color: {COLORS['text_primary']};
    spacing: 8px;
}}

QCheckBox::indicator {{
    width: 18px;
    height: 18px;
    border-radius: 3px;
    border: 2px solid {COLORS['border']};
    background-color: {COLORS['bg_secondary']};
}}

QCheckBox::indicator:checked {{
    background-color: {COLORS['accent']};
    border: 2px solid {COLORS['accent']};
}}

QCheckBox::indicator:hover {{
    border: 2px solid {COLORS['accent_hover']};
}}

/* 单选按钮 - 修复白色问题 */
QRadioButton {{
    color: {COLORS['text_primary']};
    spacing: 8px;
}}

QRadioButton::indicator {{
    width: 18px;
    height: 18px;
    border-radius: 9px;
    border: 2px solid {COLORS['border']};
    background-color: {COLORS['bg_secondary']};
}}

QRadioButton::indicator:checked {{
    background-color: {COLORS['accent']};
    border: 2px solid {COLORS['accent']};
}}

QRadioButton::indicator:hover {{
    border: 2px solid {COLORS['accent_hover']};
}}

/* 下拉框 - 修复白色问题 */
QComboBox {{
    background-color: {COLORS['bg_secondary']};
    color: {COLORS['text_primary']};
    border: 1px solid {COLORS['border']};
    padding: 8px 12px;
    border-radius: 4px;
    min-width: 120px;
}}

QComboBox:hover {{
    border: 1px solid {COLORS['accent']};
}}

QComboBox::drop-down {{
    border: none;
    width: 30px;
}}

QComboBox::down-arrow {{
    image: none;
    border-left: 5px solid transparent;
    border-right: 5px solid transparent;
    border-top: 5px solid {COLORS['text_secondary']};
    width: 0;
    height: 0;
}}

QComboBox QAbstractItemView {{
    background-color: {COLORS['bg_secondary']};
    color: {COLORS['text_primary']};
    border: 1px solid {COLORS['border']};
    selection-background-color: {COLORS['accent']};
    selection-color: white;
}}

/* 表格 */
QTableWidget {{
    background-color: {COLORS['bg_secondary']};
    color: {COLORS['text_primary']};
    border: 1px solid {COLORS['border']};
    gridline-color: {COLORS['border']};
    border-radius: 4px;
}}

QTableWidget::item {{
    padding: 8px;
    border-bottom: 1px solid {COLORS['border']};
}}

QTableWidget::item:selected {{
    background-color: {COLORS['accent']};
    color: white;
}}

QHeaderView::section {{
    background-color: {COLORS['bg_tertiary']};
    color: {COLORS['text_primary']};
    padding: 10px;
    border: none;
    border-right: 1px solid {COLORS['border']};
    font-weight: bold;
}}

QHeaderView::section:hover {{
    background-color: {COLORS['accent']};
}}

/* 滚动条 */
QScrollBar:vertical {{
    background-color: {COLORS['bg_tertiary']};
    width: 12px;
    border-radius: 6px;
}}

QScrollBar::handle:vertical {{
    background-color: {COLORS['accent']};
    border-radius: 6px;
    min-height: 30px;
}}

QScrollBar::handle:vertical:hover {{
    background-color: {COLORS['accent_hover']};
}}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    height: 0px;
}}

QScrollBar:horizontal {{
    background-color: {COLORS['bg_tertiary']};
    height: 12px;
    border-radius: 6px;
}}

QScrollBar::handle:horizontal {{
    background-color: {COLORS['accent']};
    border-radius: 6px;
    min-width: 30px;
}}

QScrollBar::handle:horizontal:hover {{
    background-color: {COLORS['accent_hover']};
}}

/* 进度条 */
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

/* 分组框 */
QGroupBox {{
    background-color: {COLORS['bg_secondary']};
    color: {COLORS['text_primary']};
    border: 1px solid {COLORS['border']};
    border-radius: 6px;
    margin-top: 12px;
    padding-top: 12px;
    font-weight: bold;
}}

QGroupBox::title {{
    subcontrol-origin: margin;
    left: 12px;
    padding: 0 8px;
    color: {COLORS['accent']};
}}

/* 标签 */
QLabel {{
    color: {COLORS['text_primary']};
}}

QLabel#title {{
    font-size: 18px;
    font-weight: bold;
    color: {COLORS['accent']};
}}

QLabel#subtitle {{
    color: {COLORS['text_secondary']};
    font-size: 12px;
}}

/* 状态栏 */
QStatusBar {{
    background-color: {COLORS['bg_tertiary']};
    color: {COLORS['text_primary']};
}}

/* 菜单 */
QMenuBar {{
    background-color: {COLORS['bg_secondary']};
    color: {COLORS['text_primary']};
}}

QMenuBar::item:selected {{
    background-color: {COLORS['accent']};
}}

QMenu {{
    background-color: {COLORS['bg_secondary']};
    color: {COLORS['text_primary']};
    border: 1px solid {COLORS['border']};
}}

QMenu::item:selected {{
    background-color: {COLORS['accent']};
}}

/* 工具提示 - 修复悬浮白色问题 */
QToolTip {{
    background-color: {COLORS['bg_tertiary']};
    color: {COLORS['text_primary']};
    border: 1px solid {COLORS['accent']};
    padding: 6px 10px;
    border-radius: 4px;
}}

/* 分割器 */
QSplitter::handle {{
    background-color: {COLORS['border']};
}}

QSplitter::handle:hover {{
    background-color: {COLORS['accent']};
}}

/* 树形控件 */
QTreeWidget {{
    background-color: {COLORS['bg_secondary']};
    color: {COLORS['text_primary']};
    border: 1px solid {COLORS['border']};
}}

QTreeWidget::item {{
    padding: 6px;
}}

QTreeWidget::item:selected {{
    background-color: {COLORS['accent']};
}}

QTreeWidget::item:hover {{
    background-color: {COLORS['bg_tertiary']};
}}
"""

def apply_dark_theme(app: QApplication):
    """应用深色主题"""
    app.setStyleSheet(DARK_STYLESHEET)
    
    # 设置调色板
    palette = QPalette()
    palette.setColor(QPalette.Window, QColor(COLORS['bg_primary']))
    palette.setColor(QPalette.WindowText, QColor(COLORS['text_primary']))
    palette.setColor(QPalette.Base, QColor(COLORS['bg_secondary']))
    palette.setColor(QPalette.AlternateBase, QColor(COLORS['bg_tertiary']))
    palette.setColor(QPalette.ToolTipBase, QColor(COLORS['bg_tertiary']))
    palette.setColor(QPalette.ToolTipText, QColor(COLORS['text_primary']))
    palette.setColor(QPalette.Text, QColor(COLORS['text_primary']))
    palette.setColor(QPalette.Button, QColor(COLORS['accent']))
    palette.setColor(QPalette.ButtonText, QColor('white'))
    palette.setColor(QPalette.Highlight, QColor(COLORS['accent']))
    palette.setColor(QPalette.HighlightedText, QColor('white'))
    
    app.setPalette(palette)
