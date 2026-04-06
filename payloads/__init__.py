# Payloads Module
"""
文件上传绕过Payload生成模块

包含:
- registry:         统一 Payload 注册中心（推荐使用，整合所有来源）
- bypass_payloads:  基础绕过技术 (37+种)
- intruder_payloads:高级Intruder Payload引擎 (策略模式)
- strategy_matrix:  环境-策略映射矩阵
- webshells:        WebShell生成器
- polyglots:        多语言Payload生成器
"""

from .registry import PayloadRegistry, get_registry, get_payloads as get_all_payloads
from .bypass_payloads import BypassPayloadGenerator, generate_bypass_payloads
from .intruder_payloads import (
    PayloadFactory,
    FuzzConfig,
    FuzzStrategy,
    generate_intruder_payloads,
    get_payload_statistics,
    BACKEND_LANGUAGES,
    MAGIC_BYTES,
    WEBSHELL_TEMPLATES,
)
from .strategy_matrix import (
    StrategyMatrix,
    Strategy,
    StrategyResult,
    StrategyPriority,
    StrategyCategory,
    STRATEGY_DEFINITIONS,
    get_strategies_for_environment,
    should_enable_strategy,
)
from .webshells import WebShellGenerator
from .polyglots import PolyglotGenerator

__all__ = [
    # Unified Registry（推荐入口）
    'PayloadRegistry',
    'get_registry',
    'get_all_payloads',

    # Bypass Payloads
    'BypassPayloadGenerator',
    'generate_bypass_payloads',
    
    # Intruder Payloads
    'PayloadFactory',
    'FuzzConfig',
    'FuzzStrategy',
    'generate_intruder_payloads',
    'get_payload_statistics',
    
    # Strategy Matrix
    'StrategyMatrix',
    'Strategy',
    'StrategyResult',
    'StrategyPriority',
    'StrategyCategory',
    'STRATEGY_DEFINITIONS',
    'get_strategies_for_environment',
    'should_enable_strategy',
    
    # Constants
    'BACKEND_LANGUAGES',
    'MAGIC_BYTES',
    'WEBSHELL_TEMPLATES',
    
    # Webshells & Polyglots
    'WebShellGenerator',
    'PolyglotGenerator',
]

