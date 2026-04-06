#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
UploadRanger 完整功能测试脚本（唯一入口，覆盖原 test_response_core / test_response_viewer）
"""

import sys
import os
import tempfile

# 部分环境在加载 QtWebEngine 后，解释器正常收尾会触发子进程异常，导致退出码非 0；成功时用 os._exit 直接结束进程。
from datetime import datetime

# 颜色输出
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RESET = '\033[0m'

def print_header(title):
    print(f"\n{Colors.BLUE}{'=' * 60}{Colors.RESET}")
    print(f"{Colors.BLUE}  {title}{Colors.RESET}")
    print(f"{Colors.BLUE}{'=' * 60}{Colors.RESET}")

def print_success(msg):
    print(f"{Colors.GREEN}[OK] {msg}{Colors.RESET}")

def print_error(msg):
    print(f"{Colors.RED}[FAIL] {msg}{Colors.RESET}")

def print_info(msg):
    print(f"  {msg}")

# ==================== 测试模块 ====================

def test_imports():
    """测试所有模块导入"""
    print_header("测试模块导入")
    
    modules = [
        # 核心模块
        ("config", "配置模块"),
        ("core.http_client", "HTTPClient (同步)"),
        ("core.form_parser", "FormParser"),
        ("core.response_analyzer", "ResponseAnalyzer (同步)"),
        ("core.scanner", "UploadScanner (同步)"),
        ("core.models", "数据模型"),
        ("core.config_manager", "配置管理器"),
        # 异步模块
        ("core.async_http_client", "AsyncHTTPClient"),
        ("core.async_response_analyzer", "AsyncResponseAnalyzer"),
        ("core.async_scanner", "AsyncScanner"),
        ("core.async_scanner_worker", "AsyncScannerWorker"),
        
        # Payload模块
        ("payloads.webshells", "WebShellGenerator"),
        ("payloads.bypass_payloads", "BypassPayloadGenerator"),
        ("payloads.polyglots", "PolyglotGenerator"),
        ("payloads.intruder_payloads", "IntruderPayloads"),
        
        # GUI模块
        ("gui.themes.dark_theme", "DarkTheme"),
        ("gui.syntax_highlighter", "SyntaxHighlighter"),
        ("gui.response_viewer", "ResponseViewer"),
        ("gui.traffic_viewer", "TrafficViewer"),
        ("gui.repeater_widget", "RepeaterWidget"),
        ("gui.intruder_widget", "IntruderWidget"),
        ("gui.proxy_widget", "ProxyWidget"),
        ("gui.main_window", "MainWindow"),
    ]
    
    passed, failed = 0, 0
    
    for module, name in modules:
        try:
            __import__(module)
            print_success(f"{name}")
            passed += 1
        except Exception as e:
            print_error(f"{name}: {str(e)[:50]}")
            failed += 1
    
    print_info(f"结果: {passed} 通过, {failed} 失败")
    return failed == 0

def test_models():
    """测试数据模型"""
    print_header("测试数据模型")
    
    try:
        from core.models import TrafficLog, VulnerabilityFinding, ScanResult
        
        # TrafficLog
        log = TrafficLog(
            id=1,
            timestamp="12:00:00",
            method="POST",
            url="http://example.com/upload",
            status_code=200,
            request_headers="Content-Type: multipart/form-data",
            request_body="--boundary",
            response_headers="HTTP/1.1 200 OK",
            response_body="Upload success"
        )
        print_success(f"TrafficLog 创建成功")
        
        # VulnerabilityFinding
        finding = VulnerabilityFinding(
            name="任意文件上传",
            description="成功上传PHP文件",
            risk_level="高危",
            confidence="确定",
            url="http://example.com/upload",
            payload="shell.php",
            proof="文件可访问",
            remediation="验证文件扩展名"
        )
        print_success(f"VulnerabilityFinding 创建成功: {finding.name}")
        
        # ScanResult
        result = ScanResult(
            target="http://example.com",
            start_time=datetime.now()
        )
        print_success(f"ScanResult 创建成功: {result.target}")
        
        return True
    except Exception as e:
        print_error(f"数据模型测试失败: {e}")
        return False

def test_config():
    """测试配置"""
    print_header("测试配置模块")
    
    try:
        import config
        
        print_success(f"应用名称: {config.APP_NAME}")
        print_success(f"版本: {config.VERSION}")
        print_success(f"作者: {config.AUTHOR}")
        print_info(f"支持扩展名: {len(config.SCAN_CONFIG['allowed_extensions'])} 种")
        print_info(f"绕过技术: 多种")
        
        return True
    except Exception as e:
        print_error(f"配置测试失败: {e}")
        return False

def test_http_client():
    """测试HTTP客户端"""
    print_header("测试HTTP客户端")
    
    try:
        from core.http_client import HTTPClient
        
        client = HTTPClient()
        print_success("HTTPClient 创建成功")
        print_info(f"超时设置: {client.timeout}s")
        
        return True
    except Exception as e:
        print_error(f"HTTP客户端测试失败: {e}")
        return False

def test_form_parser():
    """测试表单解析器"""
    print_header("测试表单解析器")
    
    try:
        from core.form_parser import FormParser
        from core.http_client import HTTPClient
        
        parser = FormParser(HTTPClient())
        print_success("FormParser 创建成功")
        
        # 测试解析HTML
        html = '''
        <form action="/upload" method="POST" enctype="multipart/form-data">
            <input type="file" name="file" />
            <input type="submit" value="Upload" />
        </form>
        '''
        forms = parser.parse_forms(html, "http://example.com")
        print_success(f"解析表单: {len(forms)} 个")
        
        if forms:
            print_info(f"表单action: {forms[0].get('action', 'N/A')}")
            print_info(f"表单method: {forms[0].get('method', 'N/A')}")
        
        return True
    except Exception as e:
        print_error(f"表单解析器测试失败: {e}")
        return False

def test_response_analyzer():
    """测试响应分析器"""
    print_header("测试响应分析器")
    
    try:
        from core.response_analyzer import ResponseAnalyzer
        from core.async_response_analyzer import AsyncResponseAnalyzer
        
        # 同步分析器
        analyzer = ResponseAnalyzer()
        print_success("ResponseAnalyzer (同步) 创建成功")
        
        # 异步分析器
        async_analyzer = AsyncResponseAnalyzer()
        print_success("AsyncResponseAnalyzer (异步) 创建成功")
        
        return True
    except Exception as e:
        print_error(f"响应分析器测试失败: {e}")
        return False

def test_scanner():
    """测试扫描器"""
    print_header("测试扫描器")
    
    try:
        from core.scanner import UploadScanner
        from core.async_scanner import AsyncScanner
        
        # 同步扫描器
        scanner = UploadScanner("http://example.com/upload")
        print_success("UploadScanner (同步) 创建成功")
        
        # 异步扫描器
        async_scanner = AsyncScanner()
        print_success("AsyncScanner (异步) 创建成功")
        
        # 测试payload生成
        payloads = async_scanner._generate_payloads()
        print_success(f"生成Payload: {len(payloads)} 个")
        
        return True
    except Exception as e:
        print_error(f"扫描器测试失败: {e}")
        return False

def test_webshell_generator():
    """测试WebShell生成器"""
    print_header("测试WebShell生成器")
    
    try:
        from payloads.webshells import WebShellGenerator
        
        gen = WebShellGenerator()
        
        php_shells = gen.get_php_shells()
        print_success(f"PHP Shells: {len(php_shells)} 个")
        
        asp_shells = gen.get_asp_shells()
        print_success(f"ASP Shells: {len(asp_shells)} 个")
        
        jsp_shells = gen.get_jsp_shells()
        print_success(f"JSP Shells: {len(jsp_shells)} 个")
        
        # 测试生成
        shell = gen.generate_shell("php", "simple_eval")
        if shell:
            print_success("成功生成 simple_eval Shell")
            print_info(f"Shell大小: {len(shell)} bytes")
        
        return True
    except Exception as e:
        print_error(f"WebShell生成器测试失败: {e}")
        return False

def test_bypass_payloads():
    """测试绕过Payload生成器"""
    print_header("测试绕过Payload生成器")
    
    try:
        from payloads.bypass_payloads import BypassPayloadGenerator
        
        gen = BypassPayloadGenerator()
        payloads = gen.generate_all_payloads("test", ".php")
        print_success(f"绕过Payloads: {len(payloads)} 个")
        
        techniques = set(p.get("technique") for p in payloads)
        print_success(f"包含 {len(techniques)} 种绕过技术")
        
        # 显示部分技术
        for t in list(techniques)[:5]:
            print_info(f"  - {t}")
        
        return True
    except Exception as e:
        print_error(f"绕过Payload生成器测试失败: {e}")
        return False

def test_polyglots():
    """测试Polyglot生成器"""
    print_header("测试Polyglot生成器")
    
    try:
        from payloads.polyglots import PolyglotGenerator
        
        gen = PolyglotGenerator()
        polyglots = gen.get_all_polyglots()
        print_success(f"Polyglot类型: {len(polyglots)} 种")
        
        # 测试GIF+PHP
        gif_php = gen.create_gif_php("<?php echo 'test'; ?>")
        print_success(f"GIF+PHP polyglot: {len(gif_php)} bytes")
        
        # 测试魔术字节+PHP (修复后的功能)
        magic_gif = gen.create_php_with_magic_bytes("<?php @eval($_POST['x']); ?>", "gif")
        print_success(f"GIF魔术字节+PHP: {len(magic_gif)} bytes")
        
        # 验证修复: 检查是否不会重复添加 <?php 标签
        if b'<?php <?php' not in magic_gif:
            print_success("图片马标签修复验证通过 (无重复标签)")
        else:
            print_error("图片马标签修复验证失败 (存在重复标签)")
            return False
        
        # 测试不带标签的输入
        magic_gif2 = gen.create_php_with_magic_bytes("@eval($_POST['x']);", "gif")
        if b'<?php' in magic_gif2 and b'?>' in magic_gif2:
            print_success("无标签输入自动添加标签验证通过")
        else:
            print_error("无标签输入自动添加标签验证失败")
            return False
        
        return True
    except Exception as e:
        print_error(f"Polyglot生成器测试失败: {e}")
        return False

def test_intruder_payloads():
    """测试Intruder Payloads"""
    print_header("测试Intruder Payloads")
    
    try:
        from payloads.intruder_payloads import (
            PayloadFactory,
            generate_intruder_payloads,
            get_payload_statistics,
        )
        
        factory = PayloadFactory()
        print_success(f"PayloadFactory 策略数: {len(factory._strategies)}")
        
        sample_template = """POST /upload.php HTTP/1.1
Host: example.com
Content-Type: multipart/form-data; boundary=----b

----b
Content-Disposition: form-data; name="file"; filename="test.jpg"
Content-Type: image/jpeg

x
----b--"""
        plist = generate_intruder_payloads(sample_template, languages=["php"], max_payloads=30)
        print_success(f"generate_intruder_payloads: {len(plist)} 个")
        
        stats = get_payload_statistics()
        print_success(f"统计: {stats['total_strategies']} 策略")
        
        return True
    except Exception as e:
        print_error(f"Intruder Payloads测试失败: {e}")
        return False

def test_gui_components():
    """测试GUI组件 (不启动界面)"""
    print_header("测试GUI组件")
    
    try:
        from PySide6.QtWidgets import QApplication
        
        # 创建QApplication实例 (GUI测试必需)
        app = QApplication.instance()
        if app is None:
            app = QApplication(sys.argv)
        
        # 测试主题
        from gui.themes.dark_theme import apply_dark_theme, COLORS
        apply_dark_theme(app)
        print_success(f"深色主题已应用 (COLORS 键: {len(COLORS)})")
        
        # 测试语法高亮
        from gui.syntax_highlighter import HTTPHighlighter
        print_success("HTTPHighlighter 导入成功")
        
        # 测试响应查看器
        from gui.response_viewer import ResponseViewerWidget
        print_success("ResponseViewerWidget 导入成功")
        
        # 测试流量查看器
        from gui.traffic_viewer import TrafficViewer
        print_success("TrafficViewer 导入成功")
        
        return True
    except Exception as e:
        print_error(f"GUI组件测试失败: {e}")
        return False

def test_async_scanner_worker():
    """测试异步扫描Worker"""
    print_header("测试异步扫描Worker")
    
    try:
        from core.async_scanner_worker import AsyncScannerWorker
        
        worker = AsyncScannerWorker(
            target_url="http://example.com/upload",
            file_param="file",
            upload_dir=None,
            proxies=None,
            headers={},
            cookies=None,
            max_payloads=200,
        )
        print_success("AsyncScannerWorker 创建成功")
        
        return True
    except Exception as e:
        print_error(f"异步扫描Worker测试失败: {e}")
        return False

def test_file_operations():
    """测试文件操作"""
    print_header("测试文件操作")
    
    try:
        from payloads.polyglots import PolyglotGenerator
        
        gen = PolyglotGenerator()
        
        # 创建临时目录
        with tempfile.TemporaryDirectory() as tmpdir:
            # 测试写入文件
            output_path = os.path.join(tmpdir, "test_shell.gif")
            gen.create_php_with_magic_bytes("<?php phpinfo(); ?>", "gif", output_path)
            
            if os.path.exists(output_path):
                print_success(f"文件写入成功: {output_path}")
                
                # 读取验证
                with open(output_path, 'rb') as f:
                    content = f.read()
                    if content.startswith(b'GIF89a'):
                        print_success("文件内容验证: GIF魔术字节正确")
                    else:
                        print_error("文件内容验证: 魔术字节不正确")
                        return False
            else:
                print_error("文件写入失败")
                return False
        
        return True
    except Exception as e:
        print_error(f"文件操作测试失败: {e}")
        return False

def test_response_viewer_core():
    """响应查看器：编码检测、二进制判断、Hex 生成（需 QApplication）"""
    print_header("ResponseViewer 核心方法")
    
    try:
        from PySide6.QtWidgets import QApplication
        from gui.response_viewer import ResponseViewerWidget
        
        app = QApplication.instance()
        if app is None:
            app = QApplication(sys.argv)
        
        viewer = ResponseViewerWidget()
        
        test_utf8 = "你好世界".encode("utf-8")
        text, encoding = viewer._detect_encoding(test_utf8, "text/html; charset=utf-8")
        assert encoding == "utf-8", f"Expected utf-8, got {encoding}"
        assert text == "你好世界"
        print_success("UTF-8 编码检测")
        
        test_gbk = "你好世界".encode("gbk")
        text2, encoding2 = viewer._detect_encoding(test_gbk, "")
        assert encoding2 == "gbk", f"Expected gbk, got {encoding2}"
        assert text2 == "你好世界"
        print_success("GBK 编码检测")
        
        png_data = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100
        assert viewer._is_binary_content("image/png", png_data) is True
        print_success("PNG 二进制检测")
        
        html_data = "<html><body>Test</body></html>".encode("utf-8")
        assert viewer._is_binary_content("text/html", html_data) is False
        print_success("HTML 非二进制检测")
        
        test_bytes = b"\x00\x01\x02\x48\x65\x6C\x6C\x6F\xFF\xFE\xFD"
        hex_rows = viewer._generate_hex_rows(test_bytes)
        assert len(hex_rows) == 1
        offset, hex_str, ascii_str = hex_rows[0]
        assert offset == "00000000"
        assert "00 01 02" in hex_str
        assert "Hello" in ascii_str
        print_success("Hex dump 生成")
        
        viewer.deleteLater()
        return True
    except Exception as e:
        print_error(f"ResponseViewer 核心测试失败: {e}")
        return False

def test_response_viewer_set_response():
    """响应查看器：set_response 各类型（无窗口、不阻塞）"""
    print_header("ResponseViewer set_response")
    
    try:
        from PySide6.QtWidgets import QApplication
        from gui.response_viewer import ResponseViewerWidget
        
        app = QApplication.instance()
        if app is None:
            app = QApplication(sys.argv)
        
        viewer = ResponseViewerWidget()
        headers = "HTTP/1.1 200 OK\nContent-Type: text/html; charset=utf-8"
        
        test_html = "<html><body>你好世界</body></html>".encode("utf-8")
        viewer.set_response(headers, test_html, "text/html; charset=utf-8")
        print_success("UTF-8 中文 HTML")
        
        test_gbk = "测试GBK编码".encode("gbk")
        viewer.set_response(headers, test_gbk, "")
        print_success("GBK 正文")
        
        png_data = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100
        viewer.set_response(
            "HTTP/1.1 200 OK\nContent-Type: image/png",
            png_data,
            "image/png",
        )
        print_success("PNG 图片")
        
        json_data = '{"name": "test", "value": 123}'.encode("utf-8")
        viewer.set_response(
            "HTTP/1.1 200 OK\nContent-Type: application/json",
            json_data,
            "application/json",
        )
        print_success("JSON")
        
        binary_data = b"\x00\x01\x02\x03\xFF\xFE\xFD" * 100
        viewer.set_response(
            "HTTP/1.1 200 OK\nContent-Type: application/octet-stream",
            binary_data,
            "application/octet-stream",
        )
        print_success("二进制流")
        
        viewer.deleteLater()
        return True
    except Exception as e:
        print_error(f"ResponseViewer set_response 测试失败: {e}")
        return False

# ==================== 主函数 ====================

def main():
    """主函数"""
    import config
    print(f"\n{Colors.BLUE}{'=' * 60}{Colors.RESET}")
    print(f"{Colors.BLUE}  UploadRanger 完整功能测试{Colors.RESET}")
    print(f"{Colors.BLUE}  版本: {config.VERSION}{Colors.RESET}")
    print(f"{Colors.BLUE}{'=' * 60}{Colors.RESET}")
    
    # 定义测试
    tests = [
        ("模块导入", test_imports),
        ("数据模型", test_models),
        ("配置模块", test_config),
        ("HTTP客户端", test_http_client),
        ("表单解析器", test_form_parser),
        ("响应分析器", test_response_analyzer),
        ("扫描器", test_scanner),
        ("WebShell生成器", test_webshell_generator),
        ("绕过Payload生成器", test_bypass_payloads),
        ("Polyglot生成器", test_polyglots),
        ("Intruder Payloads", test_intruder_payloads),
        ("GUI组件", test_gui_components),
        ("异步扫描Worker", test_async_scanner_worker),
        ("文件操作", test_file_operations),
        ("ResponseViewer 核心方法", test_response_viewer_core),
        ("ResponseViewer set_response", test_response_viewer_set_response),
    ]
    
    # 运行测试
    results = []
    for name, test_func in tests:
        try:
            result = test_func()
            results.append((name, result))
        except Exception as e:
            print_error(f"{name} 测试异常: {e}")
            results.append((name, False))
    
    # 打印总结
    print_header("测试总结")
    
    passed = 0
    failed = 0
    
    for name, result in results:
        if result:
            print_success(f"{name}")
            passed += 1
        else:
            print_error(f"{name}")
            failed += 1
    
    total = len(results)
    
    print(f"\n{Colors.BLUE}{'=' * 60}{Colors.RESET}")
    print(f"  总计: {Colors.GREEN}{passed}{Colors.RESET}/{total} 测试通过")
    
    if passed == total:
        print(f"  {Colors.GREEN}[OK] 所有测试通过!{Colors.RESET}")
        print(f"{Colors.BLUE}{'=' * 60}{Colors.RESET}\n")
        code = 0
    else:
        print(f"  {Colors.RED}[FAIL] {failed} 个测试失败{Colors.RESET}")
        print(f"{Colors.BLUE}{'=' * 60}{Colors.RESET}\n")
        code = 1

    return code

if __name__ == "__main__":
    _code = main()
    if _code == 0:
        os._exit(0)
    sys.exit(_code)
