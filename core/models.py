#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
数据模型 - TrafficLog, VulnerabilityFinding, ScanResult
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from datetime import datetime


@dataclass
class TrafficLog:
    """流量日志 - 记录请求和响应"""
    id: int
    timestamp: str
    method: str
    url: str
    status_code: int
    request_headers: str
    request_body: str
    response_headers: str
    response_body: str
    is_success: bool = False  # 【新增】是否成功上传（用于颜色渲染）
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'timestamp': self.timestamp,
            'method': self.method,
            'url': self.url,
            'status_code': self.status_code,
            'request_headers': self.request_headers,
            'request_body': self.request_body,
            'response_headers': self.response_headers,
            'response_body': self.response_body,
            'is_success': self.is_success
        }


@dataclass
class VulnerabilityFinding:
    """漏洞发现"""
    name: str
    description: str
    risk_level: str
    confidence: str
    url: str
    payload: str
    proof: str
    remediation: str
    timestamp: datetime = field(default_factory=datetime.now)
    request_data: Optional[str] = None
    response_data: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'name': self.name,
            'description': self.description,
            'risk_level': self.risk_level,
            'confidence': self.confidence,
            'url': self.url,
            'payload': self.payload,
            'proof': self.proof,
            'remediation': self.remediation,
            'timestamp': self.timestamp.isoformat(),
            'request_data': self.request_data,
            'response_data': self.response_data
        }


@dataclass
class ScanResult:
    """扫描结果"""
    target: str
    start_time: datetime
    end_time: Optional[datetime] = None
    findings: List[VulnerabilityFinding] = field(default_factory=list)
    stats: Dict[str, int] = field(default_factory=lambda: {"total_requests": 0, "vulns_found": 0})
    traffic_history: List[TrafficLog] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'target': self.target,
            'start_time': self.start_time.isoformat(),
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'findings': [f.to_dict() for f in self.findings],
            'stats': self.stats,
            'traffic_history': [t.to_dict() for t in self.traffic_history]
        }


# 风险等级
RISK_CRITICAL = "严重"
RISK_HIGH = "高危"
RISK_MEDIUM = "中危"
RISK_LOW = "低危"
RISK_INFO = "信息"

# 置信度
CONFIDENCE_CERTAIN = "确定"
CONFIDENCE_HIGH = "高"
CONFIDENCE_MEDIUM = "中"
CONFIDENCE_LOW = "低"
