#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
UploadRanger EXE打包脚本
"""

import os
import sys
import subprocess
import shutil
from PIL import Image


MCP_HIDDEN_IMPORTS = [
    '--hidden-import', 'mcp',
    '--hidden-import', 'mcp.server.fastmcp',
    '--hidden-import', 'core.mcp',
    '--hidden-import', 'core.mcp.server',
]

# 添加调试输出
print(f"[DEBUG] 当前Python: {sys.executable}")
print(f"[DEBUG] 当前工作目录: {os.getcwd()}")
print(f"[DEBUG] 参数: {sys.argv}")


def clean_build():
    """清理构建目录"""
    dirs_to_remove = ['build', 'dist', '__pycache__']
    for dir_name in dirs_to_remove:
        if os.path.exists(dir_name):
            print(f"清理 {dir_name}...")
            shutil.rmtree(dir_name)
    
    # 清理.pyc文件
    for root, dirs, files in os.walk('.'):
        for file in files:
            if file.endswith('.pyc'):
                os.remove(os.path.join(root, file))
        for dir in dirs:
            if dir == '__pycache__':
                shutil.rmtree(os.path.join(root, dir))

def convert_png_to_ico(png_path, ico_path=None):
    """将PNG图标转换为ICO格式"""
    if not os.path.exists(png_path):
        print(f"[!] PNG文件不存在: {png_path}")
        return None
    
    if ico_path is None:
        ico_path = os.path.splitext(png_path)[0] + '.ico'
    
    try:
        print(f"  正在转换: {png_path}")
        # 打开PNG图像
        img = Image.open(png_path)
        print(f"  原始大小: {img.size}, 模式: {img.mode}")
        
        # 确保大小合适（建议 256x256）
        if img.size != (256, 256):
            print(f"  调整大小: {img.size} → (256, 256)")
            img = img.resize((256, 256), Image.Resampling.LANCZOS)
        
        # 转换为RGB模式（ICO需要）
        if img.mode != 'RGB':
            rgb_img = Image.new('RGB', img.size, (255, 255, 255))
            if img.mode == 'RGBA':
                rgb_img.paste(img, mask=img.split()[3])
            else:
                rgb_img.paste(img)
            img = rgb_img
            print(f"  转换模式: {img.mode}")
        
        # 保存为ICO
        img.save(
            ico_path,
            format='ICO',
            sizes=[(16, 16), (24, 24), (32, 32), (48, 48),
                   (64, 64), (128, 128), (256, 256)],
        )
        print(f"[OK] 已将 {os.path.basename(png_path)} 转换为 {os.path.basename(ico_path)}")
        
        # 验证文件是否创建
        if os.path.exists(ico_path):
            size_kb = os.path.getsize(ico_path) / 1024
            print(f"  文件大小: {size_kb:.2f} KB")
            return ico_path
        else:
            print(f"[!] ICO文件创建失败")
            return None
    except Exception as e:
        print(f"[!] 转换图标失败: {e}")
        import traceback
        traceback.print_exc()
        return None

def build_exe():
    """构建EXE文件"""
    print("=" * 50)
    print("UploadRanger EXE打包工具")
    print("=" * 50)
    print("[DEBUG] 进入build_exe函数")
    
    # 检查PyInstaller
    try:
        import PyInstaller
        print("[OK] PyInstaller已安装")
    except ImportError:
        print("正在安装PyInstaller...")
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'pyinstaller'])
    
    # 清理旧构建
    print("\n清理旧构建文件...")
    clean_build()
    print("[DEBUG] 清理完成")
    
    # 处理图标
    icon_path = os.path.join('assets', 'icon.png')
    ico_path = os.path.join('assets', 'icon.ico')
    
    print("\n处理图标文件...")
    if os.path.exists(icon_path):
        # 强制删除旧的ICO文件以重新转换
        if os.path.exists(ico_path):
            os.remove(ico_path)
            print(f"  已删除旧的ICO文件")
        
        # 转换PNG为ICO
        result = convert_png_to_ico(icon_path, ico_path)
        if result and os.path.exists(ico_path):
            final_icon = ico_path
            print(f"  将使用: {os.path.basename(ico_path)}")
        else:
            print(f"[!] ICO转换失败，将不使用图标")
            final_icon = None
    else:
        print(f"[!] PNG文件不存在: {icon_path}")
        final_icon = None
    
    cmd = [
        sys.executable, '-m', 'PyInstaller',
        '--name=UploadRanger',
        '--windowed',
        '--onefile',
        '--clean',
        '--noconfirm',
        '--noupx',
    ]
    
    # 添加图标（必须是ICO格式）
    if final_icon and os.path.exists(final_icon):
        cmd.append(f'--icon={final_icon}')
    
    # 添加数据文件 (Windows使用; Linux使用:)
    import platform
    sep = ';' if platform.system() == 'Windows' else ':'
    cmd.extend([
        f'--add-data=assets{sep}assets',
        f'--add-data=img{sep}img',
    ])
    
    # 隐藏导入
    cmd.extend([
        '--hidden-import', 'requests',
        '--hidden-import', 'bs4',
        '--hidden-import', 'PIL',
        '--hidden-import', 'lxml',
        '--hidden-import', 'urllib3',
        '--hidden-import', 'asyncio',
        '--hidden-import', 'aiohttp',
        '--hidden-import', 'mitmproxy',
        '--hidden-import', 'mitmproxy.http',
        '--hidden-import', 'mitmproxy.net',
        '--hidden-import', 'mitmproxy.tls',
        '--hidden-import', 'mitmproxy.websocket',
        '--hidden-import', 'pyparsing',
        '--hidden-import', 'blinker',
    ])
    cmd.extend(MCP_HIDDEN_IMPORTS)
    
    # 排除冲突的Qt包
    cmd.extend([
        '--exclude', 'PyQt5',
        '--exclude', 'PyQt6',
        '--exclude', 'PySide2'
    ])

    # 主脚本
    cmd.append('main.py')
    
    print("\n开始构建...")
    print(" ".join(cmd))
    print()
    
    try:
        subprocess.check_call(cmd)
        print("\n" + "=" * 50)
        print("[OK] 构建成功!")
        print("=" * 50)
        print(f"\nEXE文件位置: {os.path.abspath('dist/UploadRanger.exe')}")
        print("\n注意: 运行EXE需要以下文件在同一目录:")
        print("  - payloads/ 目录")
        print("  - core/ 目录")
        print("  - gui/ 目录")
        print("  - config.py")
        return True
    except subprocess.CalledProcessError as e:
        print(f"\n[!] 构建失败: {e}")
        return False


def build_directory():
    """构建目录版本（推荐）"""
    print("=" * 50)
    print("UploadRanger 目录版打包工具")
    print("=" * 50)
    
    try:
        import PyInstaller
        print("[OK] PyInstaller已安装")
    except ImportError:
        print("正在安装PyInstaller...")
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'pyinstaller'])
    
    print("\n清理旧构建文件...")
    clean_build()
    
    # 处理图标
    icon_path = os.path.join('assets', 'icon.png')
    ico_path = os.path.join('assets', 'icon.ico')
    
    print("\n处理图标文件...")
    if os.path.exists(icon_path):
        # 强制删除旧的ICO文件以重新转换
        if os.path.exists(ico_path):
            os.remove(ico_path)
            print(f"  已删除旧的ICO文件")
        
        # 转换PNG为ICO
        result = convert_png_to_ico(icon_path, ico_path)
        if result and os.path.exists(ico_path):
            final_icon = ico_path
            print(f"  将使用: {os.path.basename(ico_path)}")
        else:
            print(f"[!] ICO转换失败，将不使用图标")
            final_icon = None
    else:
        print(f"[!] PNG文件不存在: {icon_path}")
        final_icon = None
    
    cmd = [
        sys.executable, '-m', 'PyInstaller',
        '--name=UploadRanger',
        '--windowed',
        '--clean',
        '--noconfirm',
        '--noupx',
    ]
    
    if final_icon and os.path.exists(final_icon):
        cmd.append(f'--icon={final_icon}')

    # 目录版运行时同样通过 ``sys._MEIPASS`` 查找资源；仅在构建
    # 完成后复制到 EXE 同级目录会导致图片和图标无法被运行中的程序
    # 稳定定位。因此与单文件版保持一致，交由 PyInstaller 收集。
    import platform
    sep = ';' if platform.system() == 'Windows' else ':'
    cmd.extend([
        f'--add-data=assets{sep}assets',
        f'--add-data=img{sep}img',
        f'--add-data=README.md{sep}.',
        f'--add-data=requirements.txt{sep}.',
    ])
    
    # 隐藏导入
    cmd.extend([
        '--hidden-import', 'requests',
        '--hidden-import', 'bs4',
        '--hidden-import', 'PIL',
        '--hidden-import', 'lxml',
        '--hidden-import', 'urllib3',
        '--hidden-import', 'asyncio',
        '--hidden-import', 'aiohttp',
        '--hidden-import', 'mitmproxy',
        '--hidden-import', 'mitmproxy.http',
        '--hidden-import', 'mitmproxy.net',
        '--hidden-import', 'mitmproxy.tls',
        '--hidden-import', 'mitmproxy.websocket',
        '--hidden-import', 'pyparsing',
        '--hidden-import', 'blinker',
    ])
    # 目录版和单文件版必须拥有同一套 MCP 依赖；否则 EXE 的
    # ``--mcp-server`` 入口会在目录版中因缺少动态导入而失败。
    cmd.extend(MCP_HIDDEN_IMPORTS)
    
    # 排除冲突的Qt包
    cmd.extend([
        '--exclude', 'PyQt5',
        '--exclude', 'PyQt6',
        '--exclude', 'PySide2'
    ])
    
    cmd.append('main.py')
    
    print("\n开始构建...")
    try:
        subprocess.check_call(cmd)
        
        # 复制必要文件到dist目录
        print("\n复制资源文件...")
        dist_dir = os.path.join('dist', 'UploadRanger')
        
        # 复制目录
        for dir_name in ['payloads', 'core', 'gui', 'assets', 'img']:
            if os.path.exists(dir_name):
                dst = os.path.join(dist_dir, dir_name)
                if os.path.exists(dst):
                    shutil.rmtree(dst)
                shutil.copytree(dir_name, dst)
                print(f"  [OK] 复制 {dir_name}/")
        
        # 复制文件
        for file_name in ['config.py', 'requirements.txt', 'README.md']:
            if os.path.exists(file_name):
                shutil.copy(file_name, dist_dir)
                print(f"  [OK] 复制 {file_name}")
        
        print("\n" + "=" * 50)
        print("[OK] 构建成功!")
        print("=" * 50)
        print(f"\n程序目录: {os.path.abspath(dist_dir)}")
        print(f"启动程序: {os.path.join(dist_dir, 'UploadRanger.exe')}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"\n[!] 构建失败: {e}")
        return False

if __name__ == '__main__':
    import argparse
    # 显式目录版参数；不传模式参数时仍默认构建目录版。
    parser_directory_help = '打包为目录版 EXE（启动更快）'
    
    parser = argparse.ArgumentParser(description='UploadRanger打包工具')
    parser.add_argument('--onefile', action='store_true', help='打包为单文件')
    parser.add_argument('--clean', action='store_true', help='仅清理构建文件')
    
    parser.add_argument('--directory', '--onedir', dest='directory', action='store_true', help=parser_directory_help)
    args = parser.parse_args()
    
    print(f"[DEBUG] 解析参数: onefile={args.onefile}, clean={args.clean}")
    
    if args.clean:
        clean_build()
        print("清理完成")
    elif args.onefile:
        print("[DEBUG] 调用build_exe()")
        build_exe()
    else:
        print("[DEBUG] 调用build_directory()")
        build_directory()
