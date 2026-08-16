#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
智能分层扫描器 - v1.1.4

核心功能：
1. 扩展名分组：PHP/ASP/JSP三组
2. 分层测试：L1(MIME伪造) > L2(参数污染) > L3(扩展名变异)
3. 智能跳过：同组已成功则跳过后续测试
4. 基线对比：与正常上传响应对比确认成功
"""

from typing import List, Dict, Optional, Set, Tuple, Any
from dataclasses import dataclass


# ============================================================
# 扩展名分组定义
# ============================================================

# PHP组：后端解析机制相同
PHP_EXTENSIONS = {'php', 'php5', 'phtml', 'phar', 'pht', 'php3', 'php4', 'php7', 'phps'}

# ASP/IIS组
ASP_EXTENSIONS = {'asp', 'aspx', 'ashx', 'asmx', 'asax', 'cer', 'cdx', 'asa'}

# JSP/Tomcat组
JSP_EXTENSIONS = {'jsp', 'jspx', 'jsw', 'jsv', 'jspf', 'jspa', 'jhtml'}

# 基准后缀定义（优先级最高）
BASE_EXTENSIONS = {
    'PHP': 'php',
    'ASP': 'asp',  # 注意：ASP组优先asp而不是aspx
    'JSP': 'jsp'
}


def get_extension_group(ext: str) -> str:
    """根据扩展名判断所属组"""
    ext = ext.lower()
    if ext in PHP_EXTENSIONS:
        return 'PHP'
    elif ext in ASP_EXTENSIONS:
        return 'ASP'
    elif ext in JSP_EXTENSIONS:
        return 'JSP'
    return 'PHP'  # 默认归为PHP组


# ============================================================
# 分层定义
# ============================================================

class ScanLayer:
    """扫描层级"""
    # L1: MIME伪造 - 仅改Content-Type，最简单，WAF拦截率低
    L1_MIME = 1
    # L2: 参数污染 - 双filename等
    L2_PARAM = 2
    # L3: 扩展名变异 - 后缀名本身变异（兜底）
    L3_EXT = 3

    @staticmethod
    def get_name(layer: int) -> str:
        names = {1: "MIME伪造", 2: "参数污染", 3: "扩展名变异"}
        return names.get(layer, f"L{layer}")

    @staticmethod
    def get_short_name(layer: int) -> str:
        names = {1: "MIME", 2: "PARAM", 3: "EXT"}
        return names.get(layer, f"L{layer}")


# ============================================================
# 扫描状态管理
# ============================================================

@dataclass
class SkipResult:
    """跳过检测结果"""
    skip: bool = False           # 是否应跳过
    reason: str = ""             # 跳过原因
    inferred_success: bool = False  # 是否推断成功


@dataclass
class LayerTestResult:
    """层级测试结果"""
    layer: int
    group: str
    extension: str
    is_success: bool
    reason: str


class SmartScanState:
    """
    智能扫描状态管理器 - v1.1.4 修复版

    核心改进：
    1. 区分"绕过有效"（双扩展名）和"完全打穿"（纯后缀）
    2. 双扩展名(.jsp.gif等)成功不触发组终止
    3. 只有基准后缀(.jsp/.php/.asp)成功才算"完全打穿"
    """

    # 基准后缀定义
    BASE_EXTENSIONS = {'PHP': 'php', 'ASP': 'asp', 'JSP': 'jsp'}

    # 安全/图片扩展名集合 - 用于检测双扩展名
    DOUBLE_EXT_PATTERNS = ('.gif', '.jpg', '.jpeg', '.png', '.bmp', '.txt', '.html', '.htm', '.svg')

    def __init__(self):
        # 状态结构: {group: {layer: {'tested': bool, 'success': bool, 'ext': str, 'is_double_ext': bool}}}
        self._state: Dict[str, Dict[int, Dict]] = {}
        self._initialize()

    def _initialize(self):
        """初始化所有组的默认状态"""
        for group in ['PHP', 'ASP', 'JSP']:
            self._state[group] = {}
            for layer in [ScanLayer.L1_MIME, ScanLayer.L2_PARAM, ScanLayer.L3_EXT]:
                self._state[group][layer] = {
                    'tested': False,
                    'success': False,
                    'ext': None,
                    'is_double_ext': False
                }

    def reset(self):
        """重置状态"""
        self._initialize()

    @staticmethod
    def _is_double_extension(filename: str) -> bool:
        """
        检测是否为双扩展名（如 shell.jsp.gif）

        判定规则：
        - 文件名末尾包含安全扩展名（.gif, .jpg, .png 等）
        - 且文件名中包含脚本扩展名（.jsp, .php, .asp 等）

        示例：
        - "shell.jsp.gif" → True (双扩展名)
        - "shell.jsp" → False (纯脚本后缀)
        - "test.jpg" → False (普通图片文件)
        """
        if not filename:
            return False

        lower = filename.lower()

        # 检查是否以安全扩展名结尾
        is_safe_ending = any(lower.endswith(p) for p in SmartScanState.DOUBLE_EXT_PATTERNS)

        if not is_safe_ending:
            return False

        # 检查是否同时包含脚本扩展名（排除点号前的部分）
        script_exts = PHP_EXTENSIONS | ASP_EXTENSIONS | JSP_EXTENSIONS
        base_name = lower
        # 移除已知的安全后缀
        for p in SmartScanState.DOUBLE_EXT_PATTERNS:
            if base_name.endswith(p):
                base_name = base_name[:-len(p)]
                break

        # 检查剩余部分是否以脚本扩展名结尾
        has_script_ext = any(base_name.endswith(f'.{ext}') for ext in script_exts)

        return has_script_ext

    def should_skip(self, group: str, layer: int, extension: str = None) -> SkipResult:
        """
        判断是否应该跳过该测试

        规则（v1.1.3 修复）：
        1. 已测试过 → 跳过
        2. 同组基准后缀已成功（且非双扩展名）→ 跳过其他扩展名的同层测试
           - 关键：双扩展名成功不算"打穿"，不会触发跳过
        """
        if group not in self._state:
            return SkipResult(skip=False)

        state = self._state[group].get(layer, {})

        # 规则1: 已测试过
        if state.get('tested'):
            return SkipResult(
                skip=True,
                reason=f"{group}.L{layer} 已测试"
            )

        # 规则2: 同组基准后缀已成功，跳过其他扩展名的同层测试
        # 【v1.1.3修复】排除双扩展名的成功记录
        if extension:
            for l in [ScanLayer.L1_MIME, ScanLayer.L2_PARAM, ScanLayer.L3_EXT]:
                s = self._state[group].get(l, {})
                if s.get('success') and not s.get('is_double_ext'):  # 只看非双扩展名的成功
                    if extension != s.get('ext'):
                        return SkipResult(
                            skip=True,
                            reason=f"同组.{s.get('ext')}已打穿成功，跳过{extension}"
                        )

        return SkipResult(skip=False)

    def update(self, group: str, layer: int, extension: str, is_success: bool, filename: str = None):
        """
        更新测试状态

        Args:
            group: 组别 (PHP/ASP/JSP)
            layer: 层级 (L1_MIME/L2_PARAM/L3_EXT)
            extension: 扩展名 (jsp/php/asp等)
            is_success: 是否成功
            filename: 【v1.1.3新增】完整文件名，用于检测双扩展名
        """
        if group not in self._state:
            self._state[group] = {}

        # 检测是否是双扩展名
        is_double_ext = self._is_double_extension(filename) if filename else False

        self._state[group][layer] = {
            'tested': True,
            'success': is_success,
            'ext': extension if is_success else None,
            'is_double_ext': is_double_ext
        }

    def is_group_compromised(self, group: str) -> bool:
        """
        检查该组是否已被完全打穿（基准后缀成功）

        【v1.1.3修复】双扩展名成功不算"完全打穿"
        - .jsp.gif 成功 → is_group_compromised 返回 False（仅绕过有效）
        - .jsp 成功 → is_group_compromised 返回 True（完全打穿）
        """
        base_ext = self.BASE_EXTENSIONS.get(group)

        for layer in [ScanLayer.L1_MIME, ScanLayer.L2_PARAM, ScanLayer.L3_EXT]:
            state = self._state.get(group, {}).get(layer, {})
            # 必须同时满足：成功 + 非双扩展名 + 基准后缀匹配
            if (state.get('success') and
                not state.get('is_double_ext') and
                state.get('ext') == base_ext):
                return True
        return False

    def has_bypass(self, group: str) -> bool:
        """检查该组是否有任意形式的绕过（包括双扩展名）"""
        for layer in [ScanLayer.L1_MIME, ScanLayer.L2_PARAM, ScanLayer.L3_EXT]:
            state = self._state.get(group, {}).get(layer, {})
            if state.get('success'):
                return True
        return False

    def get_bypass_details(self, group: str) -> list:
        """获取该组的绕过详情"""
        details = []
        for layer in [ScanLayer.L1_MIME, ScanLayer.L2_PARAM, ScanLayer.L3_EXT]:
            state = self._state.get(group, {}).get(layer, {})
            if state.get('success'):
                ext = state.get('ext', '?')
                is_double = state.get('is_double_ext', False)
                tag = "⚠️[绕过]" if is_double else "✓[打穿]"
                layer_name = ScanLayer.get_short_name(layer)
                details.append(f"{tag} {layer_name}(.{ext})")
        return details

    def get_summary(self) -> str:
        """获取状态摘要（增强版，显示绕过/打穿区分）"""
        lines = ["=" * 50, "【扫描状态摘要】", "=" * 50]

        for group in ['PHP', 'ASP', 'JSP']:
            lines.append(f"\n[{group}组]")
            success_info = []

            for layer in [ScanLayer.L1_MIME, ScanLayer.L2_PARAM, ScanLayer.L3_EXT]:
                state = self._state.get(group, {}).get(layer, {})
                if state.get('tested'):
                    status = "[OK]" if state.get('success') else "[X]"
                    ext = state.get('ext', '?')
                    is_double = state.get('is_double_ext', False)
                    layer_name = ScanLayer.get_short_name(layer)
                    # 双扩展名用 + 标记
                    tag = "+" if is_double else ""
                    success_info.append(f"{status}{layer_name}({tag}.{ext})")

            if success_info:
                lines.append(f"  {', '.join(success_info)}")
            else:
                lines.append("  ○ 未测试")

            # 【v1.1.3新增】显示绕过/打穿详情
            bypass_details = self.get_bypass_details(group)
            if bypass_details:
                lines.append(f"    → {', '.join(bypass_details)}")
            elif self.has_bypass(group):
                lines.append("    → 有绕过记录但无详情")

        # 汇总状态
        lines.append("-" * 50)
        compromised_groups = [g for g in ['PHP', 'ASP', 'JSP'] if self.is_group_compromised(g)]
        bypass_only_groups = []
        for g in ['PHP', 'ASP', 'JSP']:
            if g not in compromised_groups and self.has_bypass(g):
                bypass_only_groups.append(g)

        if compromised_groups:
            lines.append(f"✓ 完全打穿: {', '.join(compromised_groups)}")
        if bypass_only_groups:
            lines.append(f"⚠️ 绕过有效(非可执行): {', '.join(bypass_only_groups)}")
        if not compromised_groups and not bypass_only_groups:
            lines.append("○ 无成功记录")

        lines.append("=" * 50)
        return '\n'.join(lines)


# ============================================================
# Payload分类器
# ============================================================

def categorize_payload(payload: Dict) -> Tuple[int, str]:
    """
    将payload分类到对应的层和组

    Returns:
        (layer, group) 元组
    """
    ptype = payload.get('type', '').lower()
    http_mods = payload.get('http_mods', {})
    ext = payload.get('ext', 'php').lower()

    # L1: MIME伪造
    if 'mime' in ptype or payload.get('fake_content_type'):
        layer = ScanLayer.L1_MIME
    # L2: 参数污染
    elif http_mods.get('filename_field') or 'pollution' in ptype or 'field' in ptype:
        layer = ScanLayer.L2_PARAM
    # L3: 扩展名变异（默认）
    else:
        layer = ScanLayer.L3_EXT

    group = get_extension_group(ext)
    return layer, group


def get_probe_payloads(payloads: List[Dict]) -> Dict[Tuple[int, str], Dict]:
    """
    从payload列表中提取每个(层,组)的探测payload

    v1.1.4 修复：
    1. 优先选择基准后缀（php/jsp/asp）而不是变体（php5/jspx等）
    2. 优先选择单扩展名payload（不带双扩展名伪装）
    3. 例如: shell.jsp 优先于 shell.jspx，优先于 shell.gif.jsp
    """

    def get_priority(payload: Dict) -> int:
        """
        计算payload的优先级（数值越小优先级越高）
        
        优先级：
        1. 基准后缀 + 单扩展名（如 shell.php, shell.jsp）
        2. 非基准后缀 + 单扩展名（如 shell.php5, shell.jspx）
        3. 双扩展名（如 shell.gif.php, shell.gif.jsp）
        """
        filename = payload.get('filename', '')
        ext = payload.get('ext', '').lower()
        group = categorize_payload(payload)[1]

        if not ext or not filename:
            return 100  # 无效payload，优先级最低

        # 去掉开头的点
        ext_clean = ext[1:] if ext.startswith('.') else ext

        # 检查是否是双扩展名
        is_double = '.' in (filename.rsplit('.', 1)[0] if '.' in filename else '')

        # 检查是否是基准后缀
        base_ext = BASE_EXTENSIONS.get(group, '')
        is_base = (ext_clean == base_ext)

        if is_double:
            # 双扩展名，优先级最低
            return 30
        elif is_base:
            # 基准后缀，优先级最高
            return 1
        else:
            # 非基准单扩展名（如 php5, jspx），优先级中等
            return 20

    probes = {}

    for p in payloads:
        layer, group = categorize_payload(p)
        key = (layer, group)

        if key not in probes:
            # 第一次遇到，存下来
            probes[key] = p
        else:
            # 已经有探针，比较优先级
            current_priority = get_priority(probes[key])
            new_priority = get_priority(p)
            if new_priority < current_priority:
                # 新payload优先级更高，替换
                probes[key] = p

    return probes


def sort_by_layer(payloads: List[Dict]) -> List[Dict]:
    """
    按层级排序payloads

    顺序：L1 > L2 > L3
    """
    def sort_key(p):
        layer, _ = categorize_payload(p)
        return layer

    return sorted(payloads, key=sort_key)


# 全局实例
scan_state = SmartScanState()
