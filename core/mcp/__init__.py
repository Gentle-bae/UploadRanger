"""UploadRanger MCP 集成。

保持包初始化轻量，避免 ``python -m core.mcp.server`` 执行时提前导入
``server``，从而触发 runpy 的模块重复加载警告并增加启动开销。
"""

__all__ = ["create_server"]

def __getattr__(name):
    if name == "create_server":
        from .server import create_server
        return create_server
    raise AttributeError(name)
