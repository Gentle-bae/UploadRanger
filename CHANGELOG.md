# UploadRanger 更新日志

## v1.2.0（计划发布：2026-08-16）- 强可信度版

> v1.2.0 为待发布版本。以下内容按 v1.1.1（tag `a96f4fd`）到当前代码的实际差异整理。

### ✅ 已完成修复与改进
  - 同步扫描器代理参数与 httpx 0.28 兼容性已修复。
  - 上传结果已增加真实访问/执行证据门控，并接入同源验证保护。
  - TLS 默认校验、RawHTTP 1xx/重复响应头/压缩处理和表单回归测试已补齐。

### 📦 相比 v1.1.1 的主要变化

#### MCP 集成
- 新增 `core/mcp/server.py`，支持本地 stdio 与 SSE。
- 提供 `uploadranger_scan/status/result/logs/verify/cancel` 工具，任务异步执行并支持状态查询、日志、取消和结果获取。
- 新增 `gui/mcp_widget.py`：服务开关、传输方式、端口、JSON 复制、日志和停止清理。
- stdio 配置按当前安装目录动态生成，不依赖开发者机器路径。
- 修复 Windows QProcess 日志乱码：采用按行增量缓冲解码（UTF-8/GB18030 回退），并去重 stderr 与文件日志；SSE 启动提示不再误显示为 stdio 握手。
- 增加 `uploadranger_logs`，并将 MCP 日志写入项目目录 `.uploadranger_mcp.log`，GUI 会轮询同步外部调用日志。

#### 扫描器与请求链路
- 新增 RequestTemplate、Raw 请求解析、multipart 构造和 Payload 变异模块，可从 Repeater/代理请求发送到扫描器。
- 结果判定改为“候选证据 → 同源访问确认 → 可选执行确认”，降低响应成功造成的误报。
- 新增 URL Guard，限制验证 URL 的同源、回环、私网和链路本地访问。
- 修复扫描结果回调链路和表单解析回归。
- MCP 增加进度百分比、代理参数、错误 traceback 和 finding 聚合；移除无效的 `request_body/content_type` 工具参数。
- `uploadranger_result` 现在直接返回聚合后的 `findings`，同时保留 `findings_raw` 和逐 Payload `evidence`，解决同一漏洞多种后缀导致报告冗长的问题。
- MCP 文档补充 6 工具“扫 → 查 → 取 → 记 → 验 → 撤”闭环说明。
- 修复共享上传目录的跨扫描污染误报：每次扫描为文件名加入独立 `ur_<scan_nonce>_` 前缀，并要求验证响应内容与本轮上传内容匹配；仅返回 200 不再足以判定上传成功。
- GUI 与 MCP 均可传入自定义文件字段、Payload 数量和扩展名集合；MCP 的 `max_payloads`、`selected_extensions` 会实际传递到扫描器。
- finding 取证改为优先保留原始 Raw 请求，包含 Host、Cookie、multipart boundary 和完整 body；httpx 回退路径也会构造可复制的完整请求。
- MCP“清除日志”现在同时清空 GUI、`.uploadranger_mcp.log` 和读取偏移，下次启动不会恢复已清除的旧日志；Python 源码启动时优先加载 `assets/icon.ico` 并设置 Windows AppUserModelID，保留任务栏图标分组。
- `TrafficLog` 的二进制响应改为 base64 + 长度字段，避免 `result` 在 JSON 序列化时崩溃。
- 目录版 EXE 打包补齐 MCP 隐藏导入，保证 `UploadRanger.exe --mcp-server` 与单文件版拥有一致的运行依赖。
- 目录版 EXE 现通过 PyInstaller `--add-data` 收集 `assets/`、`img/`、README 和依赖清单到 `_internal/` 运行时目录，修复图标与模块截图在打包程序中无法稳定定位的问题；发布目录仍保留同级资源副本，便于整体分发与查阅。
- 自动表单发现仅跟随初始目标同源的上传地址，避免不可信页面把扫描器自动导向内网或其他站点。
- 结果定级收紧：普通图片/文档或以安全扩展名结尾的双扩展名上传不再直接报高危，必须保留危险最终扩展名或取得执行证据。

#### HTTP、Repeater 与 Intruder
- httpx/httpcore 增加兼容版本范围，修复 httpx 0.28 参数兼容。
- RawHTTP 支持 1xx、重复响应头和压缩响应。
- Intruder 保留完整 multipart 请求、响应头、响应体和 Location，并增加“跟随重定向”开关。
- Repeater/Traffic Viewer 右键发送动作使用当前选中的数据包；响应支持完整 Raw/Header/Render 视图。
- Repeater 默认启用“跟踪 30x”，关闭时保留直接 3xx；扫描器对可用的上传 302 会记录跟进 GET，并通过 `parent_log_id` / `is_verification` 关联回上传 POST。
- Traffic Viewer 选中 302 上传流量时显示跳转链和最终响应；Render 对二进制/非 HTML 最终响应展示文件信息页，并为每次渲染规避缓存。

#### Payload 与界面
- WebShell 生成器支持自定义命令参数名并同步更新代码、密码说明和 usage。
- 增强魔法字节、Polyglot、绕过技术和自定义请求体模块。
- 绕过技术表支持单元格、整行、整列选择与复制。
- 关于页改为可滚动卡片布局，统一 UTF-8 文本与 v1.2.0 版本显示。
- 新增自适应、全量、仅自定义三种扫描策略；自适应仅在同后缀已完成真实验证后早停，全量模式不早停。
- 新增自定义 Payload 管理，并打通 GUI → Worker → 异步扫描器的数据链；停止扫描保留统计/流量/结果，可从 `next_payload_index` 继续。
- 扫描页新增计划、已测、跳过、已验证统计；重排左侧策略控件、操作按钮和结果区 splitter，避免窄窗口下重叠。

<details>
<summary>历史版本 (点击展开)</summary>

---

## v1.1.1 (2026-04-09) - 专业红队版

### 🔥 重大更新

#### 双模式扫描系统
- **安全测试模式**: 上传无害内容，仅证明漏洞存在，不含任何恶意代码
  - 生成纯文本/HTML格式的测试文件
  - PHP/JSP/ASP等文件改为HTML注释格式，不含可执行代码
  - EXE/脚本等文件改为纯文本占位符
  - 适用于授权的安全检测场景
- **渗透测试模式**: 可上传WebShell等攻击载荷
  - 支持自定义WebShell密码
  - 支持多种Shell类型：基础eval、Base64免杀、冰蝎兼容、蚁剑兼容
  - 上传可执行文件前弹出确认对话框
  - 适用于红队评估和授权渗透测试

#### Payload内容定制
- **PHP WebShell**: 支持基础eval、Base64免杀、冰蝎兼容、蚁剑兼容
- **JSP WebShell**: 支持基础执行、冰蝎兼容、蚁剑兼容
- **ASPX WebShell**: 支持基础执行、冰蝎兼容、蚁剑兼容
- **安全内容**: 生成纯文本/HTML注释格式，不含可执行代码

#### 安全改进
- **删除危险功能**: 移除压缩包炸弹（DoS攻击）相关代码
- **删除覆盖攻击**: 移除.htaccess/user.ini覆盖核心文件功能
- **渗透模式确认**: 上传EXE/脚本前需用户确认
- **全局版本控制**: 使用config.VERSION统一管理版本标记

#### UI优化
- **按钮显示修复**: 调整按钮固定宽度，确保显示完整
- **测试模式切换**: 单选按钮快速切换安全/渗透模式
- **密码输入联动**: 密码输入框仅在渗透测试模式下启用

#### 智能后缀判定
- **自动跳过**: 当某后缀达到85%置信度时，自动跳过后缀其他payload
- **连续成功跳过**: 某后缀获得2个以上成功结果时自动跳过
- **最小测试数**: 每个后缀至少测试3个payload后再评估
- **效率提升**: 避免在已确认的后缀上浪费时间

#### Payload数量实时更新
- **选择后更新**: 选择后缀后自动更新payload预估数量
- **分类统计**: 显示已选后缀数量和预估有效payload条数

#### WAF指纹库增强（19 → 33类型）

**新增国内WAF指纹 (9个)**:
- 阿里云Web应用防火墙 - 含云盾、aliyuncs特征
- 腾讯云WAF - 含waf.tencent.com、wgpAY特征
- 华为云WAF - 含HWWAFSESID、hwcloud特征
- 知道创宇WebRAY - 含创宇云安全、webshell特征
- 百度云加速 - 含yunjiasu、baidu特征
- 360网站卫士 - 含wangzhan.360.cn特征
- 京东云WAF - 含JD_VIA、jdcloud特征
- UCloud WAF - 含ucloud、ucuserauth特征
- 网宿科技CDN WAF - 含wscdn、wangsu特征

**新增海外WAF指纹 (5个)**:
- Fastly WAF - 含fastly、x-surre特征
- CloudFront - 含x-amz-cf-id特征
- DDoS-Guard - 含ddos-guard、__ddg特征
- Reblaze - 含RBZID Cookie特征
- Alert Logic - 含alertlogic特征

#### WAF绕过策略增强
- 新增国内WAF绕过建议（阿里云、腾讯云、华为云等）
- 绕过策略从10个增加到18个
- 提供针对性绕过技术和延迟/线程建议

### 🛠 技术实现

#### 核心改造
- `core/async_scanner.py`: 新增 `_generate_harmless_content()`、`_generate_php_webshell()` 等辅助函数
- `core/async_scanner_worker.py`: 支持 `scan_mode` 和 `webshell_config` 参数传递
- `gui/main_window.py`: 新增测试模式选择UI和密码配置

#### Payload生成器改造
- 按扫描模式选择内容：无害内容 vs WebShell
- 支持密码和类型参数化
- 保持原有绕过技术的完整性

### 🛠 修复问题

- **QFrame导入错误**: 修复PySide6中QFrame未导入导致的NameError
- **模块导入清理**: 清理所有已删除模块的导入引用

---

## v1.1.0 (2026-04-08)

### 核心功能
- 异步多线程文件上传漏洞扫描
- 智能Payload生成与绕过
- OOB带外检测支持
- 环境指纹识别
- Raw HTTP请求支持
- 详细的扫描报告导出

## v1.0.5 (2026-03-24)

### 判定逻辑升级

- **证据分层 + 冲突裁决**: 异步响应分析从"单关键词判定"升级为"结构化 JSON + 文本关键词 + 状态码 + 路径"综合裁决
- **结构化成功证据优先**: 支持识别 `success=true`、`files` 非空、`message` 成功语义
- **判定可解释**: 新增 `decision_reasons`（判定原因）与 `confidence_level`（置信等级）

### 上传验证增强

- **服务端重命名适配**: 从响应 JSON 提取服务端保存名
- **多候选验证**: 支持候选文件名逐个验证
- **触发条件优化**: 成功概率达到阈值时尝试二次验证

### 界面与版本

- 扫描结果表新增判定说明提示
- 项目版本更新为 **v1.0.5**

## v1.0.4 (2026-03-22)

### 新增与界面

- **扫描目标**: 文件参数名支持可编辑下拉
- **Intruder**: 攻击结果表支持排序，结果详情支持 ResponseViewer
- **右键快捷**: 代理历史/拦截列表、Repeater 请求区支持发送到 Repeater / Intruder
- **测试**: `test_response_core` / `test_response_viewer` 合并至 `test_all.py`

### 修复与逻辑

- **异步扫描响应分析**: 收紧成功词与失败优先级
- **同步响应分析**: 无明确信号时不再默认成功
- **代理**: mitmproxy 导入失败时输出具体异常
- **同步扫描 / 表单 / Worker**: 与当前 API 对齐

## v1.0.3 (2026-03-12)

### 新增功能

1. **响应查看增强**
   - Raw / Pretty / Render / Hex 统一响应展示
   - Hex 视图按 Offset / Hex / ASCII 分列
2. **渲染安全与稳定**
   - WebEngine 默认禁用 JavaScript 与本地存储

### 修复问题

- **响应渲染稳定性**: 修复大响应导致界面卡顿
- **编码识别**: 增加可选 chardet 检测
- **Hex 视图样式**: 移除焦点框/白色选中圈

## v1.0.2 (2026-03-08)

### 新增功能

1. **代理模块配置持久化**
   - 新增 ConfigManager 配置管理器
   - 代理设置自动保存和恢复
2. **代理历史记录过滤增强**
   - 实现 300ms 防抖过滤
   - 添加过滤统计信息

### 修复问题

- **代理重启问题修复**: 修复停止后无法重新启动的问题
- **导入错误修复**: 修复相对导入导致的 ImportError
- **代理模块问题修复**: 修复表格选中等问题
- **Repeater 对话框优化**: 修复重命名对话框过小
- **绕过技术表格样式修复**: 修复选中背景覆盖文字
- **线程稳定性修复**: 修复 QThread 崩溃问题

## v1.0.1 (2026-02-28)

### 修复问题

1. **界面显示修复**: 修复"清除"按钮宽度过小
2. **功能增强**: Repeater 模块增加标签页拖拽排序、双击重命名
3. **代码优化**: 优化 Payload 生成器代码
4. **其他改进**:
   - 新增 `WebShellHighlighter` 语法高亮
   - 使用 `QPlainTextEdit` 替换 `QTextEdit`

## v1.0.0 (2026-02-23)

### 新增功能

1. **Intruder爆破模块**: 支持4种攻击模式、标记payload位置、多线程并发
2. **语法高亮**: HTTP请求/响应、JSON 语法高亮
3. **Repeater功能增强**: 异步请求、响应状态显示

### 修复问题

- **响应截断问题**: 重写 `_format_response_body()`
- **请求/响应显示**: 优化布局和语法高亮
- **布局优化**: 主页面重新设计

### 改进内容

- **Payload扩充**: 绕过技术从30种扩充到263+种
- **功能整合**: 流量查看器支持发送到Intruder

</details>
