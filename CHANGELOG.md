# UploadRanger 更新日志

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

## v1.1.0 (2026-04-08) - 初始版本

### 核心功能
- 异步多线程文件上传漏洞扫描
- 智能Payload生成与绕过
- OOB带外检测支持
- 环境指纹识别
- Raw HTTP请求支持
- 详细的扫描报告导出
