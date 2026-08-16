#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""将请求模板重建为可发送的原始请求字节。"""
from .request_template import RequestTemplate
import re


def _quote_header(value: str) -> str:
    return re.sub(r'[\r\n"]', lambda m: {"\r": "%0D", "\n": "%0A", '"': "%22"}[m.group(0)], str(value))


def build_raw_request(template: RequestTemplate) -> bytes:
    template.validate()
    headers = dict(template.headers)
    body = template.body
    ctype = next((v for k, v in headers.items() if k.lower() == "content-type"), "")
    if template.file_parts and "multipart/form-data" in ctype.lower():
        boundary = ctype.split("boundary=", 1)[-1].strip().strip('"')
        chunks = []
        for key, value in template.form_fields.items():
            chunks.append(f"--{boundary}\r\nContent-Disposition: form-data; name=\"{_quote_header(key)}\"\r\n\r\n{value}\r\n".encode())
        for part in template.file_parts:
            chunks.append(f"--{boundary}\r\nContent-Disposition: form-data; name=\"{_quote_header(part.field)}\"; filename=\"{_quote_header(part.filename)}\"\r\nContent-Type: {_quote_header(part.content_type)}\r\n\r\n".encode() + part.content + b"\r\n")
        chunks.append(f"--{boundary}--\r\n".encode())
        body = b"".join(chunks)
    headers.pop("Content-Length", None); headers.pop("content-length", None)
    headers["Content-Length"] = str(len(body))
    request_target = template.url.split("://", 1)[-1]
    request_target = "/" + request_target.split("/", 1)[1] if "/" in request_target else "/"
    lines = [f"{template.method} {request_target} HTTP/1.1"] + [f"{k}: {v}" for k, v in headers.items()]
    return ("\r\n".join(lines) + "\r\n\r\n").encode("utf-8") + body
