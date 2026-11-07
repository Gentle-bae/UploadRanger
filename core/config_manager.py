#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
配置管理器 - 管理应用配置的持久化存储
支持JSON格式配置文件，存储在用户目录下
"""

import copy
import json
import os
import stat
from pathlib import Path
from typing import Dict, Any, Optional


class ConfigManager:
    """配置管理类"""
    
    def __init__(self, app_name: str = "uploadranger"):
        self.app_name = app_name
        self.config_dir = Path.home() / f".{app_name}"
        self.config_file = self.config_dir / "config.json"
        self._config: Dict[str, Any] = {}
        self._ensure_config_dir()
        self.load()
    
    def _ensure_config_dir(self):
        """确保配置目录存在"""
        self.config_dir.mkdir(parents=True, exist_ok=True)
    
    def load(self) -> Dict[str, Any]:
        """加载配置文件（与默认值深合并：手工编辑缺键时回退默认值而不是返回 None）"""
        loaded = {}
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    loaded = json.load(f)
            except Exception as e:
                print(f"加载配置文件失败: {e}")
                loaded = {}
        if not isinstance(loaded, dict):
            loaded = {}
        self._config = self._deep_merge(self._get_default_config(), loaded)
        return self._config

    @staticmethod
    def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
        """递归合并：override 优先，缺键回退 base"""
        merged = dict(base)
        for key, value in override.items():
            if isinstance(value, dict) and isinstance(merged.get(key), dict):
                merged[key] = ConfigManager._deep_merge(merged[key], value)
            else:
                merged[key] = value
        return merged

    def save(self) -> bool:
        """保存配置到文件（POSIX 下收紧为 0600，避免同机用户读取）"""
        try:
            self.config_dir.mkdir(parents=True, exist_ok=True)
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(self._config, f, ensure_ascii=False, indent=2)
            try:
                os.chmod(self.config_file, stat.S_IRUSR | stat.S_IWUSR)
            except OSError:
                pass  # Windows 无 POSIX 权限位，忽略
            return True
        except Exception as e:
            print(f"保存配置文件失败: {e}")
            return False
    
    def _get_default_config(self) -> Dict[str, Any]:
        """获取默认配置"""
        return {
            "proxy": {
                "host": "127.0.0.1",
                "port": 8080,
                "intercept": True
            },
            "history_filter": {
                "enabled": True,
                "rules": "# 每行一个排除条件\n# 域名排除\nfreebuf.com\njd.com\n\n# 路径排除\n.css\n.js\n.png"
            }
        }
    
    def get(self, key: str, default: Any = None) -> Any:
        """获取配置项"""
        keys = key.split('.')
        value = self._config
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        return value
    
    def set(self, key: str, value: Any):
        """设置配置项"""
        keys = key.split('.')
        config = self._config
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        config[keys[-1]] = value
    
    def get_proxy_config(self) -> Dict[str, Any]:
        """获取代理配置"""
        return self._config.get("proxy", {
            "host": "127.0.0.1",
            "port": 8080,
            "intercept": True
        })
    
    def set_proxy_config(self, host: str, port: int, intercept: bool):
        """设置代理配置"""
        self._config["proxy"] = {
            "host": host,
            "port": port,
            "intercept": intercept
        }
    
    def get_filter_config(self) -> Dict[str, Any]:
        """获取过滤配置"""
        return self._config.get("history_filter", {
            "enabled": True,
            "rules": ""
        })
    
    def set_filter_config(self, enabled: bool, rules: str):
        """设置过滤配置"""
        self._config["history_filter"] = {
            "enabled": enabled,
            "rules": rules
        }
    
    @property
    def config(self) -> Dict[str, Any]:
        """获取完整配置（深拷贝，避免调用方修改嵌套值写穿内部状态）"""
        return copy.deepcopy(self._config)


# 全局配置管理器实例
_config_manager: Optional[ConfigManager] = None


def get_config_manager() -> ConfigManager:
    """获取全局配置管理器实例"""
    global _config_manager
    if _config_manager is None:
        _config_manager = ConfigManager()
    return _config_manager
