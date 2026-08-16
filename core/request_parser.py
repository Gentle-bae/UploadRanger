#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""解析 Burp/Repeater 风格原始 HTTP 请求，并识别 multipart 文件字段。"""
import re
from typing import Dict, Tuple
from urllib.parse import urljoin

from .request_template import FilePart, RequestTemplate


def parse_raw_request(raw: bytes | str, base_url: str | None = None) -> RequestTemplate:
    if isinstance(raw, str):
        try:
            data = raw.encode("latin-1")
        except UnicodeEncodeError:
            data = raw.encode("utf-8")
    else:
        data = raw
    head, sep, body = data.partition(b"\r\n\r\n")
    if not sep:
        head, _, body = data.partition(b"\n\n")
    lines = head.replace(b"\r\n", b"\n").split(b"\n")
    if not lines:
        raise ValueError("请求为空")
    first = lines[0].decode("latin-1").split()
    if len(first) < 2:
        raise ValueError("请求行格式错误")
    method, target = first[0].upper(), first[1]
    headers: Dict[str, str] = {}
    for line in lines[1:]:
        text = line.decode("latin-1")
        if ":" in text:
            key, value = text.split(":", 1)
            headers[key.strip()] = value.strip()
    host = headers.get("Host") or headers.get("host")
    if target.startswith("/") and base_url:
        target = urljoin(base_url, target)
    elif target.startswith("/") and host:
        target = "http://" + host + target
    if not target.startswith(("http://", "https://")):
        raise ValueError("请求缺少绝对 URL；请提供 base_url 或 Host")
    template = RequestTemplate(method=method, url=target, headers=headers, body=body, mode="raw")
    ctype = headers.get("Content-Type", headers.get("content-type", ""))
    if "multipart/form-data" in ctype.lower():
        match = re.search(r"boundary=(?:\"([^\"]+)\"|([^;\s]+))", ctype, re.I)
        if match:
            boundary = (match.group(1) or match.group(2)).encode("latin-1")
            _detect_multipart_parts(template, boundary)
    template.metadata["raw_request"] = data
    template.validate()
    return template


def _detect_multipart_parts(template: RequestTemplate, boundary: bytes) -> None:
    marker = b"--" + boundary
    for part in template.body.split(marker)[1:]:
        part = part.strip(b"\r\n-")
        if not part:
            continue
        phead, sep, content = part.partition(b"\r\n\r\n")
        if not sep:
            phead, sep, content = part.partition(b"\n\n")
        if not sep:
            continue
        ph = {}
        for line in phead.replace(b"\r\n", b"\n").split(b"\n"):
            text = line.decode("latin-1")
            if ":" in text:
                k, v = text.split(":", 1); ph[k.lower()] = v.strip()
        disposition = ph.get("content-disposition", "")
        name = re.search(r'name="([^"]+)"', disposition, re.I)
        filename = re.search(r'filename="([^"]*)"', disposition, re.I)
        if not name:
            continue
        value = content.rstrip(b"\r\n")
        if filename:
            template.file_parts.append(FilePart(
                field=name.group(1), filename=filename.group(1),
                content_type=ph.get("content-type", "application/octet-stream"), content=value,
            ))
        else:
            template.form_fields[name.group(1)] = value.decode("utf-8", "replace")
