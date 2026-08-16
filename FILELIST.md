# UploadRanger 项目文件清单

## 项目信息

- **名称**: UploadRanger
- **版本**: v1.2.0
- **作者**: bae
- **联系**: 1073723512@qq.com（有问题优先提交 GitHub Issues，便于互相帮助）
- **描述**: 现代化文件上传漏洞测试工具
- **v1.2.0 状态**: 待发布版本（计划发布：2026-08-16）。详见 [CHANGELOG.md](CHANGELOG.md) 与 README 的“安全与可信度说明”。

## 目录结构

### 根目录文件

| 文件名 | 说明 |
| --- | --- |
| `main.py` | 程序入口；支持 GUI 与 `--mcp-server` 启动参数 |
| `config.py` | 全局配置文件 |
| `requirements.txt` | Python 依赖列表 |
| `README.md` | 项目说明文档 |
| `CHANGELOG.md` | 版本更新日志 |
| `FILELIST.md` | 本文件 |
| `CONTRIBUTING.md` | 原项目贡献指南 |
| `test_all.py` | 功能回归测试脚本 |
| `build_exe.py` | PyInstaller EXE 打包脚本 |
| `UploadRanger.bat` / `UploadRanger.sh` | 平台启动脚本 |
| `UploadRanger.spec` | PyInstaller 规格文件 |
| `LICENSE` | MIT 许可证 |

### `core/` - 核心模块

| 文件名/目录 | 说明 |
| --- | --- |
| `async_scanner.py` | 异步扫描引擎；策略编排、真实验证、停止和恢复 |
| `async_scanner_worker.py` | Qt 扫描工作线程 |
| `async_http_client.py` / `http_client.py` / `raw_http_client.py` | 异步、兼容和原始 HTTP 客户端 |
| `async_response_analyzer.py` / `response_analyzer.py` / `smart_analyzer.py` | 上传响应、候选路径与证据分析 |
| `baseline_analyzer.py` / `fingerprinter.py` | 基线响应和环境指纹分析 |
| `auto_verifier.py` / `oob_verifier.py` | 自动与带外验证辅助 |
| `form_parser.py` | 上传表单解析 |
| `models.py` | 流量、扫描结果和验证关联的数据模型 |
| `request_parser.py` / `request_builder.py` / `request_template.py` / `request_mutator.py` | Raw 请求解析、multipart 构造、模板和变异 |
| `mutation_engine.py` | 请求变异引擎 |
| `magic_bytes.py` | 文件魔数支持 |
| `scanner.py` / `smart_layer_scanner.py` | 兼容扫描入口与智能分层扫描 |
| `url_guard.py` | 验证 URL 的同源、回环和私网保护 |
| `config_manager.py` / `proxy_server.py` | 配置管理和代理服务 |
| `mcp/` | MCP Server 包：`server.py` 提供 stdio/SSE 服务 |

### `payloads/` - Payload 模块

| 文件名 | 说明 |
| --- | --- |
| `registry.py` / `strategy_matrix.py` | Payload 注册与后缀策略矩阵 |
| `webshells.py` | WebShell 生成器 |
| `bypass_payloads.py` | 上传绕过 Payload |
| `polyglots.py` / `polyglot_builder.py` | Polyglot Payload 与构造器 |
| `intruder_payloads.py` | Intruder 专用 Payload 集合 |

### `gui/` - GUI 模块

| 文件名/目录 | 说明 |
| --- | --- |
| `main_window.py` | 主窗口、扫描设置、进度和结果展示 |
| `traffic_viewer.py` | 流量查看、验证关联和 302 最终响应展示 |
| `response_viewer.py` | Raw/Headers/Pretty/Render 响应视图 |
| `repeater_widget.py` | Repeater 重放与 30x 跟踪开关 |
| `intruder_widget.py` | Intruder 自动化请求测试 |
| `proxy_widget.py` / `proxy/` | 代理、拦截、历史记录和线程实现 |
| `wizard_widget.py` | 快速扫描向导 |
| `mcp_widget.py` | MCP 服务控制、配置 JSON 和日志 |
| `syntax_highlighter.py` / `themes/` | 语法高亮和暗色主题 |

### `test_range/` - 本地测试靶场

| 文件名/目录 | 说明 |
| --- | --- |
| `app.py` | Flask 上传靶场应用 |
| `templates/base.html` / `index.html` | 靶场公共模板和入口页 |
| `templates/level1.html` - `level13.html` | 13 个上传测试关卡 |
| `uploads/` | 测试上传文件落盘目录（不纳入源文件清单） |

### 资源与扩展

| 目录/文件 | 说明 |
| --- | --- |
| `plugins/schema.json` | Payload 插件描述 JSON Schema |
| `assets/icon.png` / `assets/icon.ico` | 应用图标 |
| `img/` | 项目截图：`main.png`、`res.png`、`scan.png`、`proxy*.png`、`Repeater*.png`、`Intruder.png`、`payload.png`、`bypass.png`、`mcp.png` |

## 使用方法

```bash
pip install -r requirements.txt
python main.py
```

本地靶场：

```bash
cd test_range
python app.py
```

回归测试：

```bash
python test_all.py
```

打包 EXE：

```bash
python build_exe.py --directory
python build_exe.py --onefile
```

## 注意事项

1. 本工具仅供安全测试使用。
2. 请遵守相关法律法规，并仅对已授权系统进行测试。
3. `test_range/uploads/` 是本地靶场上传落盘目录；不要把历史测试文件作为构建清理目标。
