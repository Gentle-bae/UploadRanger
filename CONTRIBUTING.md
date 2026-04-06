# 贡献指南

感谢你对 UploadRanger 项目的关注！本指南说明如何有效地为项目做出贡献。

## 行为准则

我们致力于创建及维护一个友好、尊重的社区。所有参与者都应该遵循我们的行为准则。

## 如何贡献

### 报告 Bug

遇到 Bug 请按照以下步骤：

1. **检查是否已被报告** - 在 Issues 中搜索相关关键词
2. **创建新 Issue** - 如果 Bug 未被报告，请创建新的 Issue，包含：
   - 清晰的标题和描述
   - 复现步骤
   - 预期行为和实际行为
   - 环境信息（Python版本、操作系统等）
   - 错误日志或截图

### 建议新功能

1. 优先查看 Issues 中是否有类似建议
2. 创建新 Issue，标题前缀为 `[Feature]`
3. 详细描述功能需求和使用场景
4. 可以附加原型或示例代码

### 提交代码

1. **Fork 本仓库**
2. **创建特性分支**：`git checkout -b feature/AmazingFeature`
3. **提交更改**：`git commit -m 'Add some AmazingFeature'`
4. **推送分支**：`git push origin feature/AmazingFeature`
5. **提交 Pull Request**

#### 代码规范

- 遵循 PEP 8 风格规范
- 添加适当的注释和文档
- 确保代码可以在 Python 3.8+ 上运行
- 为新功能添加相应的测试

#### Pull Request 指南

- 清晰的 PR 标题和描述
- 关联相关的 Issue
- 确保改动不会破坏现有功能
- 通过所有测试

## 开发指南

### 环境设置

```bash
# 克隆仓库
git clone https://github.com/Gentle-bae/UploadRanger.git
cd UploadRanger

# 创建虚拟环境
python -m venv venv

# 激活虚拟环境
# Windows
venv\Scripts\activate
# Linux/Mac
source venv/bin/activate

# 安装依赖
pip install -r requirements.txt

# 运行程序
python main.py
```

### 运行测试

```bash
python test_all.py
```

## 文件修改说明

### core/ 模块

- 扫描引擎和HTTP客户端的核心实现
- 修改前请确保不污染全局状态

### gui/ 模块

- 使用 PySide6 框架
- 遵循 MVC 设计模式

### payloads/ 模块

- Payload 生成器
- 新增 payload 时请添加相应的文档和测试

## 许可证

所有贡献都将遵循 MIT License。

## 问题反馈

如有任何问题，请通过以下方式联系：

- 📧 Email：1073723512@qq.com
- GitHub Issues

> 💡 **建议**: 作者平时较忙，有问题优先提交 [GitHub Issues](https://github.com/Gentle-bae/UploadRanger/issues)，便于有类似问题的师傅互相帮助，也更易得到快速响应。

感谢你的贡献！🎉
