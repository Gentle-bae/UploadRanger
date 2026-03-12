# UploadRanger 更新日志

## v1.0.3 (2026-03-12)

### 新增功能

1. **响应查看增强**
   - Raw / Pretty / Render / Hex 统一响应展示
   - Hex 视图按 Offset / Hex / ASCII 分列，支持按列复制

2. **渲染安全与稳定**
   - WebEngine 默认禁用 JavaScript 与本地存储，避免日志刷屏

### 修复问题

1. **响应渲染稳定性**
   - 修复大响应导致界面卡顿，增加显示字节上限与截断提示

2. **编码识别**
   - 增加可选 chardet 检测与多编码兜底

3. **Hex 视图样式**
   - 移除焦点框/白色选中圈，保持纯色高亮

### 代码优化

- Repeater 使用 httpx 异步请求，保留响应原始字节
- 响应渲染组件解耦，统一接口 `set_response`

## v1.0.2 (2026-03-08)

### 新增功能

1. **代理模块配置持久化**
   - 新增 ConfigManager 配置管理器，支持JSON格式配置文件
   - 代理设置（地址、端口、拦截状态）自动保存和恢复
   - 配置文件存储在用户目录 `~/.uploadranger/config.json`

2. **代理历史记录过滤增强**
   - 添加过滤启用/禁用开关，避免无过滤时执行过滤逻辑
   - 实现 300ms 防抖过滤，避免输入时频繁触发
   - 添加过滤统计信息，显示"已显示 X / 总计 Y 条"

### 修复问题

1. **代理重启问题修复（关键修复）**
   - 修复代理停止后无法重新启动的严重问题
   - 彻底解决 `Task was destroyed but it is pending!` 警告
   - 使用 `asyncio.run_coroutine_threadsafe()` 实现线程安全的异步任务取消
   - 修复 "This event loop is already running" 错误
   - 确保每次启动代理都是全新的事件循环和线程

2. **导入错误修复**
   - 修复 `gui/proxy_widget.py` 相对导入导致的 ImportError
   - 将 `from ..core.config_manager import ConfigManager` 改为绝对导入

3. **代理模块问题修复**
   - 修复表格选中时边框覆盖URL的问题
   - 优化过滤规则解析逻辑，支持子域名匹配和显式语法（domain:/path:/method:）
   - 修复停止代理后拦截列表未清空的问题
   - 修复清空历史后统计信息未更新的问题

4. **Repeater 对话框优化**
   - 修复重命名标签对话框宽度过小问题
   - 确保"请输入新名称"提示文字完整显示

5. **绕过技术表格样式修复**
   - 修复表格行选中时紫色背景覆盖文字的问题
   - 优化选中状态文字可读性

6. **线程稳定性修复**
   - 修复 QThread 崩溃问题，确保线程正确停止和等待
   - 修复 Windows/WSL 环境下 `QThread: Destroyed while thread is still running` 错误
   - 修复 Linux/WSL 环境下中文乱码问题

### 代码优化

- 新增 `core/config_manager.py` 配置管理模块
- 优化代理模块过滤性能
- 优化 `ProxyThread.stop()` 方法中的任务取消逻辑
- 添加 `asyncio.wait_for()` 超时控制，避免无限等待
- 完善 `finally` 块中的资源清理顺序

## v1.0.1 (2026-02-28)

### 修复问题

1. **界面显示修复** (Issue #3)
   - 修复扫描模块和流量查看器中"清除"按钮宽度过小导致字体显示不全的问题
   - 将按钮宽度从 60px 调整为 80px

2. **功能增强** (Issue #2)
   - Repeater 模块增加标签页拖拽排序功能
   - Repeater 模块增加双击标签重命名功能
   - 优化标签页交互体验

3. **代码优化** (Issue #1)
   - 优化 Payload 生成器代码
   - 修复 Webshell 模板生成时的缩进冗余问题
   - 使用 `textwrap.dedent` 处理多行字符串

4. **其他改进**
   - 移除 `gui/proxy_widget.py` 中未使用的 `http` 模块引用，解决启动时的 NameError 警告
   - 新增 `WebShellHighlighter` 类，支持 Payload 生成器的语法高亮 (PHP, ASP, JSP, Python, Perl)
   - 使用 `QPlainTextEdit` 替换 `QTextEdit` 作为 Payload 编辑器，提升性能和显示效果
   - 更新所有文档版本号至 v1.0.1

## v1.0.0 (2026-02-23)

### 新增功能

1. **Intruder爆破模块**
   - 支持4种攻击模式：Sniper、Battering Ram、Pitchfork、Cluster Bomb
   - 支持标记payload位置（使用 $ $ 符号）
   - 支持多线程并发攻击
   - 实时显示攻击结果
   - 支持从文件加载payload
   - 内置绕过字典

2. **语法高亮**
   - HTTP请求/响应语法高亮
   - 支持HTTP方法、状态码、请求头、HTML标签等
   - JSON语法高亮
   - 颜色主题与界面风格一致

3. **Repeater功能增强**
   - 修复发送功能
   - 添加异步请求支持
   - 响应状态显示
   - 语法高亮显示

### 修复问题

1. **响应截断问题**
   - 重写 `_format_response_body()` 方法
   - 支持多种编码（UTF-8、Latin-1、GBK）
   - 显示完整响应内容

2. **请求/响应显示**
   - 添加语法高亮
   - 优化分割器布局
   - 状态码颜色显示

3. **布局优化**
   - 主页面重新设计
   - 详细信息区域带语法高亮
   - 可调整的分割器

### 改进内容

1. **Payload扩充**
   - 绕过技术从30种扩充到263+种
   - 新增多种绕过技术类型
   - 支持更多文件扩展名

2. **界面优化**
   - 版本号更新为v1.0.0
   - 标题栏显示版本信息
   - 关于页面更新

3. **功能整合**
   - 流量查看器支持发送到Intruder
   - 所有模块协同工作

### 技术改进

- 使用 `QPlainTextEdit` 替代 `QTextEdit` 提高性能
- 添加 `HTTPHighlighter` 语法高亮类
- 异步请求使用 `QThread` 避免界面卡顿
- 优化内存使用

---

## 历史版本

### v0.1.0 (2026-02-21)

- 修复302状态码判断
- 添加请求/响应分割器
- 实现基础Repeater功能

### v0.0.1 (2026-02-20)

- 初始版本
- 基础扫描功能
- 基础GUI界面
