# UploadRanger 项目文件清单

## 项目信息

- **名称**: UploadRanger
- **版本**: v1.1.1
- **作者**: bae
- **联系**: 1073723512@qq.com（有问题优先提交 GitHub Issues，便于互相帮助）
- **描述**: 现代化文件上传漏洞测试工具

## 目录结构

### 根目录文件

| 文件名            | 说明                |
| ----------------- | ------------------- |
| main.py           | 程序主入口          |
| config.py         | 全局配置文件        |
| requirements.txt  | Python依赖列表      |
| README.md         | 项目说明文档        |
| CHANGELOG.md      | 版本更新日志        |
| FILELIST.md       | 本文件              |
| test_all.py       | 功能测试脚本        |
| build_exe.py      | EXE打包脚本         |
| UploadRanger.bat  | Windows启动脚本     |
| UploadRanger.sh   | Linux/Mac启动脚本   |
| UploadRanger.spec | PyInstaller配置文件 |

### core/ - 核心模块

| 文件名                     | 说明                                 |
| -------------------------- | ------------------------------------ |
| **init**.py                | 模块初始化                           |
| async_http_client.py       | 异步HTTP客户端                       |
| async_response_analyzer.py | 异步响应分析器                       |
| async_scanner.py           | 异步扫描引擎                         |
| async_scanner_worker.py    | 异步扫描工作线程                     |
| config_manager.py          | 配置管理器，支持JSON格式配置持久化   |
| auto_verifier.py           | WebShell自动验证器                  |
| form_parser.py             | 表单解析器，自动发现上传表单         |
| http_client.py             | HTTP客户端，处理所有网络请求         |
| models.py                  | 数据模型定义                         |
| proxy_server.py            | 代理服务器实现                       |
| response_analyzer.py       | 响应分析器，分析上传结果             |
| scanner.py                 | 扫描引擎，核心扫描逻辑               |

### payloads/ - Payload模块

| 文件名             | 说明                                               |
| ------------------ | -------------------------------------------------- |
| **init**.py        | 模块初始化                                         |
| bypass_payloads.py | 绕过技术生成器 (263+种绕过技术)                    |
| polyglots.py       | Polyglot文件生成器                                 |
| webshells.py       | WebShell生成器 (PHP/ASP/JSP/Python/Perl等多种语言) |

### gui/ - GUI模块

| 文件名                        | 说明                     |
| ----------------------------- | ------------------------ |
| **init**.py                   | 模块初始化               |
| themes/                       | 主题文件夹               |
| &nbsp;&nbsp;├── **init**.py   | 主题模块初始化           |
| &nbsp;&nbsp;└── dark_theme.py | 暗色主题定义             |
| intruder_widget.py            | Intruder爆破模块         |
| main_window.py                | 主窗口，包含所有界面组件 |
| wizard_widget.py              | 新手快速向导（扫描页）   |
| proxy_widget.py               | 代理模块                 |
| repeater_widget.py            | Repeater重放模块         |
| response_viewer.py            | 响应查看/渲染组件          |
| syntax_highlighter.py         | 语法高亮模块             |
| traffic_viewer.py             | 流量查看器               |

### test_range/ - 测试靶场

| 文件名                               | 说明             |
| ------------------------------------ | ---------------- |
| app.py                               | Flask靶场应用    |
| requirements.txt                     | 靶场依赖         |
| templates/base.html                  | 基础模板         |
| templates/index.html                 | 主页模板         |
| templates/level1.html - level10.html | 10个关卡模板     |
| uploads/                             | 测试上传文件目录 |

### plugins/ - 插件（预留）

| 文件名      | 说明                          |
| ----------- | ----------------------------- |
| schema.json | Payload 插件描述 JSON Schema |

### assets/ - 资源文件

| 文件名   | 说明     |
| -------- | -------- |
| icon.png | 应用图标 |

### img/ - 截图文件

| 文件名       | 说明                     |
| ------------ | ------------------------ |
| Intruder.png | Intruder模块界面截图     |
| Repeater.png | Repeater模块界面截图     |
| bypass.png   | 绕过技术界面截图         |
| payload.png  | Payload生成器界面截图    |
| proxy-1.png  | 代理模块界面截图（详细） |
| proxy.png    | 代理模块界面截图（概览） |
| res.png      | 主界面截图               |
| scan.png     | 智能扫描界面截图         |

## 功能统计

### WebShell支持

- PHP: 13+种不同类型
- ASP/ASPX: 4+种
- JSP: 3+种
- Python: 2+种
- Perl: 1+种

### 绕过技术 (263+种)

1. 大小写变体
2. 双扩展名
3. 空字节注入
4. 尾部点号
5. 尾部空格
6. 路径遍历
7. MIME欺骗
8. 魔术字节
9. NTFS备用数据流
10. Unicode RTLO
11. 分号绕过
12. 多重点号
13. 反向双扩展名
14. 特殊字符
    ...（共263+种）

### Polyglot类型

1. GIF+PHP
2. PNG+PHP
3. JPG+PHP
4. GIF魔术字节+PHP
5. PNG魔术字节+PHP
6. JPG魔术字节+PHP
7. SVG XSS
8. SVG XXE

### 测试靶场关卡 (10关)

1. 无限制上传
2. 前端验证绕过
3. MIME类型绕过
4. 黑名单绕过
5. 白名单测试
6. 魔术字节绕过
7. 大小写绕过
8. 双扩展名测试
9. 路径遍历测试
10. 综合防护

## 使用方法

### 安装依赖

```bash
pip install -r requirements.txt
```

### 启动程序

```bash
# Windows
UploadRanger.bat

# Linux/Mac
./UploadRanger.sh

# 或直接运行
python main.py
```

### 启动测试靶场

```bash
cd test_range
pip install -r requirements.txt
python app.py
# 访问 http://127.0.0.1:5000
```

### 运行测试

```bash
python test_all.py
```

### 打包EXE

```bash
# 目录版（推荐）
python build_exe.py

# 单文件版
python build_exe.py --onefile
```

## 注意事项

1. 本工具仅供安全测试使用
2. 请遵守相关法律法规
3. 仅在授权的系统上使用
4. 使用本工具造成的后果由使用者承担