#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""请求模板的最小变异：保留原始请求，只替换文件字段。"""
from .request_template import FilePart, RequestTemplate


def mutate_file(template: RequestTemplate, field: str, filename: str, content: bytes, content_type: str) -> RequestTemplate:
    clone = RequestTemplate(
        method=template.method, url=template.url, headers=dict(template.headers),
        body=template.body, file_parts=[FilePart(p.field, p.filename, p.content_type, p.content) for p in template.file_parts],
        form_fields=dict(template.form_fields), mode=template.mode, metadata=dict(template.metadata),
    )
    found = False
    for part in clone.file_parts:
        if part.field == field:
            part.filename, part.content, part.content_type = filename, content, content_type
            found = True
    if not found:
        raise ValueError(f"请求中不存在文件字段: {field}")
    return clone
