#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
表单解析器 - 自动识别和解析上传表单
"""

import re
from typing import Any, Dict, List, Set, Tuple

from bs4 import BeautifulSoup
from urllib.parse import urljoin


class FormParser:
    """表单解析器类"""
    
    def __init__(self, http_client):
        self.http_client = http_client
    
    def parse_forms(self, url, html_content=None):
        """解析页面中的所有表单"""
        forms = []
        
        # 获取页面内容
        if html_content is None:
            response = self.http_client.get(url)
            if isinstance(response, dict) and "error" in response:
                return forms
            html_content = response.text
        
        soup = BeautifulSoup(html_content, 'html.parser')
        
        for form in soup.find_all('form'):
            form_info = self._extract_form_info(form, url)
            if form_info:
                forms.append(form_info)
        
        return forms
    
    def _extract_form_info(self, form, base_url):
        """提取表单信息"""
        form_info = {
            "action": "",
            "method": "GET",
            "enctype": "application/x-www-form-urlencoded",
            "fields": [],
            "file_fields": [],
            "other_fields": {},
            "is_upload_form": False
        }
        
        # 获取action
        action = form.get('action', '')
        form_info["action"] = urljoin(base_url, action) if action else base_url
        
        # 获取method
        method = form.get('method', 'GET').upper()
        form_info["method"] = method
        
        # 获取enctype
        enctype = form.get('enctype', 'application/x-www-form-urlencoded')
        form_info["enctype"] = enctype
        
        # 解析所有输入字段
        for input_tag in form.find_all(['input', 'textarea', 'select']):
            field_info = self._extract_field_info(input_tag)
            if field_info:
                form_info["fields"].append(field_info)
                
                # 检查是否是文件上传字段
                if field_info.get("type") == "file":
                    form_info["file_fields"].append(field_info)
                    form_info["is_upload_form"] = True
                else:
                    # 收集其他字段的默认值
                    name = field_info.get("name")
                    value = field_info.get("value", "")
                    if name:
                        form_info["other_fields"][name] = value
        
        return form_info
    
    def _extract_field_info(self, tag):
        """提取字段信息"""
        field_info = {}
        
        tag_name = tag.name.lower()
        
        if tag_name == 'input':
            field_info["type"] = tag.get('type', 'text').lower()
            field_info["name"] = tag.get('name', '')
            field_info["id"] = tag.get('id', '')
            field_info["value"] = tag.get('value', '')
            field_info["placeholder"] = tag.get('placeholder', '')
            field_info["required"] = tag.get('required') is not None
            
            # 获取accept属性（文件类型限制）
            if field_info["type"] == "file":
                field_info["accept"] = tag.get('accept', '')
                
        elif tag_name == 'textarea':
            field_info["type"] = "textarea"
            field_info["name"] = tag.get('name', '')
            field_info["id"] = tag.get('id', '')
            field_info["value"] = tag.get_text()
            
        elif tag_name == 'select':
            field_info["type"] = "select"
            field_info["name"] = tag.get('name', '')
            field_info["id"] = tag.get('id', '')
            # 获取选中的值
            selected = tag.find('option', selected=True)
            field_info["value"] = selected.get('value', '') if selected else ''
        
        return field_info
    
    def find_upload_forms(self, url, html_content=None):
        """专门查找上传表单"""
        all_forms = self.parse_forms(url, html_content)
        upload_forms = [f for f in all_forms if f.get("is_upload_form")]
        return upload_forms
    
    def analyze_upload_restrictions(self, form_info):
        """分析上传限制"""
        restrictions = {
            "file_types": [],
            "max_size": None,
            "client_validation": False,
            "restrictions": []
        }
        
        for file_field in form_info.get("file_fields", []):
            accept = file_field.get("accept", '')
            if accept:
                restrictions["file_types"] = [t.strip() for t in accept.split(',')]
                restrictions["restrictions"].append(f"客户端限制文件类型: {accept}")
        
        # 检查是否有JavaScript验证
        # 这里简化处理，实际应该分析JS代码
        
        return restrictions
    
    def extract_csrf_token(self, html_content):
        """提取CSRF Token"""
        tokens = {}
        
        # 常见的CSRF token字段名
        csrf_names = [
            'csrf_token', 'csrfmiddlewaretoken', '_token', '_csrf',
            'authenticity_token', 'token', 'csrf', 'xsrf_token'
        ]
        
        soup = BeautifulSoup(html_content, 'html.parser')
        
        for name in csrf_names:
            # 从input标签查找
            input_tag = soup.find('input', {'name': name})
            if input_tag:
                tokens[name] = input_tag.get('value', '')
            
            # 从meta标签查找
            meta_tag = soup.find('meta', {'name': name})
            if meta_tag:
                tokens[name] = meta_tag.get('content', '')
        
        return tokens
    
    def get_form_by_index(self, url, index, html_content=None):
        """通过索引获取表单"""
        forms = self.parse_forms(url, html_content)
        if 0 <= index < len(forms):
            return forms[index]
        return None
    
    def get_form_by_id(self, url, form_id, html_content=None):
        """通过ID获取表单"""
        if html_content is None:
            response = self.http_client.get(url)
            if isinstance(response, dict) and "error" in response:
                return None
            html_content = response.text
        
        soup = BeautifulSoup(html_content, 'html.parser')
        form = soup.find('form', {'id': form_id})
        
        if form:
            return self._extract_form_info(form, url)
        return None

    @staticmethod
    def find_upload_api_candidates(html_content: str, base_url: str) -> List[Dict[str, Any]]:
        """
        从内联 <script> 中启发式提取可能是上传接口的 URL（fetch/axios/.post 等）。
        不含完整 JS 语义分析，仅作辅助发现。
        """
        if not html_content or not base_url:
            return []

        soup = BeautifulSoup(html_content, "html.parser")
        chunks: List[str] = []
        for sc in soup.find_all("script"):
            if sc.string:
                chunks.append(sc.string)
        text = "\n".join(chunks)
        if not text.strip():
            return []

        patterns: List[Tuple[str, str]] = [
            (r"fetch\s*\(\s*[`\"']([^`\"']+)[`\"']", "fetch"),
            (r"axios\.(?:post|put)\s*\(\s*[`\"']([^`\"']+)[`\"']", "axios"),
            (r"axios\s*\.\s*request\s*\(\s*\{[^}]*url\s*:\s*[`\"']([^`\"']+)[`\"']", "axios.request"),
            (r"\$\.(?:post|ajax)\s*\(\s*[`\"']([^`\"']+)[`\"']", "jquery"),
            (r"\.post\s*\(\s*[`\"']([^`\"']+)[`\"']", ".post"),
            (r"\.put\s*\(\s*[`\"']([^`\"']+)[`\"']", ".put"),
        ]

        keywords = (
            "upload",
            "file",
            "avatar",
            "image",
            "media",
            "attach",
            "multipart",
            "import",
            "/api/",
        )

        seen: Set[str] = set()
        out: List[Dict[str, Any]] = []

        for pat, src in patterns:
            for m in re.finditer(pat, text, re.I | re.DOTALL):
                path = (m.group(1) or "").strip()
                if not path or len(path) > 800:
                    continue
                if path.startswith("data:") or path.startswith("#"):
                    continue
                low = path.lower()
                if not any(k in low for k in keywords):
                    continue
                if path.startswith("http://") or path.startswith("https://"):
                    abs_u = path.split("?")[0]
                else:
                    abs_u = urljoin(base_url, path.split("?")[0])
                key = abs_u.lower()
                if key in seen:
                    continue
                seen.add(key)
                out.append(
                    {
                        "action_url": abs_u,
                        "method": "POST",
                        "file_field": "file",
                        "confidence": 0.55,
                        "source": src,
                    }
                )
                if len(out) >= 40:
                    return out
        return out

    @staticmethod
    def collect_upload_hints(base_url: str, html_content: str) -> List[Dict[str, Any]]:
        """合并 HTML 上传表单与 JS 推测 API，供 GUI「发现上传点」使用。"""

        class _UnusedClient:
            def get(self, *a, **kw):
                raise RuntimeError("collect_upload_hints 仅使用已提供的 html")

        parser = FormParser(_UnusedClient())
        items: List[Dict[str, Any]] = []
        seen: Set[Tuple[str, str, str]] = set()

        try:
            upload_forms = parser.find_upload_forms(base_url, html_content)
        except Exception:
            upload_forms = []

        for form in upload_forms:
            action = form.get("action") or base_url
            method = (form.get("method") or "POST").upper()
            for ff in form.get("file_fields") or []:
                name = (ff.get("name") or "file").strip() or "file"
                key = ("form", action, name)
                if key in seen:
                    continue
                seen.add(key)
                items.append(
                    {
                        "label": f"[HTML表单] {method} {action}  file字段={name}",
                        "url": action,
                        "file_field": name,
                        "method": method,
                        "kind": "form",
                    }
                )

        for api in FormParser.find_upload_api_candidates(html_content, base_url):
            u = api["action_url"]
            name = api.get("file_field") or "file"
            key = ("api", u, name)
            if key in seen:
                continue
            seen.add(key)
            items.append(
                {
                    "label": f"[JS推测] {api.get('method', 'POST')} {u}  字段≈{name}",
                    "url": u,
                    "file_field": name,
                    "method": api.get("method", "POST"),
                    "kind": "api",
                }
            )

        return items
