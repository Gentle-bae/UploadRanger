#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
UploadRanger 测试靶场
用于测试文件上传漏洞扫描工具的各种功能
"""

import os
import uuid
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'uploadranger-test-secret-key'

# 配置
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'doc', 'docx'}

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    """检查文件扩展名是否允许"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# ============ 各种漏洞场景 ============

# 1. 无限制上传 (高危)
@app.route('/level1', methods=['GET', 'POST'])
def level1_no_restrictions():
    """无任何限制的文件上传"""
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('没有选择文件', 'error')
            return redirect(request.url)
        
        file = request.files['file']
        if file.filename == '':
            flash('没有选择文件', 'error')
            return redirect(request.url)
        
        if file:
            filename = secure_filename(file.filename)
            filepath = os.path.join(UPLOAD_FOLDER, filename)
            file.save(filepath)
            flash(f'文件上传成功: {filename}', 'success')
            return redirect(url_for('level1_no_restrictions'))
    
    return render_template('level1.html')

# 2. 仅前端验证 (可绕过)
@app.route('/level2', methods=['GET', 'POST'])
def level2_frontend_only():
    """仅前端JavaScript验证"""
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('没有选择文件', 'error')
            return redirect(request.url)
        
        file = request.files['file']
        if file.filename == '':
            flash('没有选择文件', 'error')
            return redirect(request.url)
        
        # 服务器端没有验证，直接保存
        filename = secure_filename(file.filename)
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        file.save(filepath)
        flash(f'文件上传成功: {filename}', 'success')
        return redirect(url_for('level2_frontend_only'))
    
    return render_template('level2.html')

# 3. MIME类型验证 (可绕过)
@app.route('/level3', methods=['GET', 'POST'])
def level3_mime_check():
    """仅验证Content-Type"""
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('没有选择文件', 'error')
            return redirect(request.url)
        
        file = request.files['file']
        if file.filename == '':
            flash('没有选择文件', 'error')
            return redirect(request.url)
        
        # 仅检查content-type
        content_type = file.content_type
        allowed_types = ['image/jpeg', 'image/png', 'image/gif', 'application/pdf']
        
        if content_type not in allowed_types:
            flash(f'不支持的文件类型: {content_type}', 'error')
            return redirect(request.url)
        
        filename = secure_filename(file.filename)
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        file.save(filepath)
        flash(f'文件上传成功: {filename}', 'success')
        return redirect(url_for('level3_mime_check'))
    
    return render_template('level3.html')

# 4. 扩展名黑名单 (可绕过)
@app.route('/level4', methods=['GET', 'POST'])
def level4_extension_blacklist():
    """扩展名黑名单验证"""
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('没有选择文件', 'error')
            return redirect(request.url)
        
        file = request.files['file']
        if file.filename == '':
            flash('没有选择文件', 'error')
            return redirect(request.url)
        
        filename = file.filename.lower()
        
        # 黑名单
        blacklist = ['.php', '.asp', '.aspx', '.jsp', '.py', '.pl', '.rb']
        
        for ext in blacklist:
            if filename.endswith(ext):
                flash(f'不允许的文件类型: {ext}', 'error')
                return redirect(request.url)
        
        filename = secure_filename(file.filename)
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        file.save(filepath)
        flash(f'文件上传成功: {filename}', 'success')
        return redirect(url_for('level4_extension_blacklist'))
    
    return render_template('level4.html')

# 5. 扩展名白名单 (较难绕过)
@app.route('/level5', methods=['GET', 'POST'])
def level5_extension_whitelist():
    """扩展名白名单验证"""
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('没有选择文件', 'error')
            return redirect(request.url)
        
        file = request.files['file']
        if file.filename == '':
            flash('没有选择文件', 'error')
            return redirect(request.url)
        
        filename = file.filename.lower()
        
        # 白名单
        whitelist = ['.jpg', '.jpeg', '.png', '.gif', '.pdf', '.doc', '.docx']
        
        allowed = False
        for ext in whitelist:
            if filename.endswith(ext):
                allowed = True
                break
        
        if not allowed:
            flash('只允许上传: jpg, jpeg, png, gif, pdf, doc, docx', 'error')
            return redirect(request.url)
        
        filename = secure_filename(file.filename)
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        file.save(filepath)
        flash(f'文件上传成功: {filename}', 'success')
        return redirect(url_for('level5_extension_whitelist'))
    
    return render_template('level5.html')

# 6. 文件内容验证 (魔术字节)
@app.route('/level6', methods=['GET', 'POST'])
def level6_magic_bytes():
    """验证文件魔术字节"""
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('没有选择文件', 'error')
            return redirect(request.url)
        
        file = request.files['file']
        if file.filename == '':
            flash('没有选择文件', 'error')
            return redirect(request.url)
        
        # 读取前几个字节检查魔术字节
        header = file.read(8)
        file.seek(0)  # 重置文件指针
        
        # 定义魔术字节（正确写法：真正的二进制字节）
        magic_signatures = {
            b'\xff\xd8\xff': 'image/jpeg',
            b'\x89PNG': 'image/png',
            b'GIF89a': 'image/gif',
            b'GIF87a': 'image/gif',
            b'%PDF': 'application/pdf',
        }
        
        valid = False
        for signature, filetype in magic_signatures.items():
            if header.startswith(signature):
                valid = True
                break
        
        if not valid:
            flash('无效的图片文件', 'error')
            return redirect(request.url)
        
        filename = secure_filename(file.filename)
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        file.save(filepath)
        flash(f'文件上传成功: {filename}', 'success')
        return redirect(url_for('level6_magic_bytes'))
    
    return render_template('level6.html')

# 7. 大小写绕过测试
@app.route('/level7', methods=['GET', 'POST'])
def level7_case_sensitive():
    """大小写敏感验证"""
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('没有选择文件', 'error')
            return redirect(request.url)
        
        file = request.files['file']
        if file.filename == '':
            flash('没有选择文件', 'error')
            return redirect(request.url)
        
        filename = file.filename  # 不转换为小写
        
        # 仅检查小写的.php
        if '.php' in filename:
            flash('不允许上传PHP文件', 'error')
            return redirect(request.url)
        
        filename = secure_filename(file.filename)
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        file.save(filepath)
        flash(f'文件上传成功: {filename}', 'success')
        return redirect(url_for('level7_case_sensitive'))
    
    return render_template('level7.html')

# 8. 双扩展名测试
@app.route('/level8', methods=['GET', 'POST'])
def level8_double_extension():
    """双扩展名验证"""
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('没有选择文件', 'error')
            return redirect(request.url)
        
        file = request.files['file']
        if file.filename == '':
            flash('没有选择文件', 'error')
            return redirect(request.url)
        
        filename = file.filename.lower()

        # 正确的双扩展名场景：只检查最后一个扩展名（缺陷检查），
        # 这样 shell.php.jpg 可以绕过（末尾是 .jpg），而 shell.php 会被拦截
        if filename.rsplit('.', 1)[-1] == 'php':
            flash('不允许上传PHP文件', 'error')
            return redirect(request.url)
        
        filename = secure_filename(file.filename)
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        file.save(filepath)
        flash(f'文件上传成功: {filename}', 'success')
        return redirect(url_for('level8_double_extension'))
    
    return render_template('level8.html')

# 9. 路径遍历测试
@app.route('/level9', methods=['GET', 'POST'])
def level9_path_traversal():
    """路径遍历测试"""
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('没有选择文件', 'error')
            return redirect(request.url)
        
        file = request.files['file']
        if file.filename == '':
            flash('没有选择文件', 'error')
            return redirect(request.url)
        
        # 获取文件名
        filename = file.filename
        
        # 过滤路径遍历（修正：完整检查 .. 反斜杠也包括 ..\\）
        if '..' in filename or '../' in filename:
            flash('非法文件名', 'error')
            return redirect(request.url)
        
        # 过滤绝对路径注入（防止 /etc/passwd 或 C:\Windows 类型的路径）
        if filename.startswith('/') or filename.startswith('\\') or ':' in filename:
            flash('非法文件名', 'error')
            return redirect(request.url)
        
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        file.save(filepath)
        flash(f'文件上传成功: {filename}', 'success')
        return redirect(url_for('level9_path_traversal'))
    
    return render_template('level9.html')

# 10. 综合防护 (较难绕过)
@app.route('/level10', methods=['GET', 'POST'])
def level10_comprehensive():
    """综合防护"""
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('没有选择文件', 'error')
            return redirect(request.url)
        
        file = request.files['file']
        if file.filename == '':
            flash('没有选择文件', 'error')
            return redirect(request.url)
        
        filename = file.filename.lower()
        
        # 1. 白名单验证
        whitelist = ['.jpg', '.jpeg', '.png', '.gif']
        allowed = any(filename.endswith(ext) for ext in whitelist)
        
        if not allowed:
            flash('只允许上传图片文件', 'error')
            return redirect(request.url)
        
        # 2. 验证content-type
        allowed_types = ['image/jpeg', 'image/png', 'image/gif']
        if file.content_type not in allowed_types:
            flash('无效的文件类型', 'error')
            return redirect(request.url)
        
        # 3. 验证魔术字节（修正：使用真正的二进制字节）
        header = file.read(8)
        file.seek(0)
        
        magic_signatures = {
            b'\xff\xd8\xff': 'jpg',
            b'\x89PNG': 'png',
            b'GIF89a': 'gif',
            b'GIF87a': 'gif',
        }
        
        valid = any(header.startswith(sig) for sig in magic_signatures.keys())
        
        if not valid:
            flash('无效的图片文件', 'error')
            return redirect(request.url)
        
        # 4. 重命名文件
        ext = filename.rsplit('.', 1)[1]
        new_filename = f"{uuid.uuid4().hex}.{ext}"
        
        filepath = os.path.join(UPLOAD_FOLDER, new_filename)
        file.save(filepath)
        flash(f'文件上传成功: {new_filename}', 'success')
        return redirect(url_for('level10_comprehensive'))
    
    return render_template('level10.html')

# 11. .htaccess 配置注入（Apache 特有）
@app.route('/level11', methods=['GET', 'POST'])
def level11_htaccess():
    """
    .htaccess 配置注入教学场景。
    漏洞：只检查 .jpg 扩展名，但未阻止 .htaccess 上传。
    绕过：先上传 .htaccess 让服务端将 .jpg 解析为 PHP，再上传含 PHP 代码的 .jpg。
    注意：本靶场仅演示漏洞逻辑，文件不会真正被 Apache 执行。
    """
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('没有选择文件', 'error')
            return redirect(request.url)

        file = request.files['file']
        if file.filename == '':
            flash('没有选择文件', 'error')
            return redirect(request.url)

        filename = file.filename
        # 有缺陷的检查：只允许 .jpg，但忘记拒绝 .htaccess
        if filename.lower().endswith('.jpg') or filename == '.htaccess':
            safe_name = secure_filename(filename) if filename != '.htaccess' else '_htaccess'
            filepath = os.path.join(UPLOAD_FOLDER, safe_name)
            file.save(filepath)
            flash(f'文件上传成功: {safe_name}', 'success')
        else:
            flash('只允许上传 .jpg 文件', 'error')
        return redirect(url_for('level11_htaccess'))

    return render_template('level11.html')


# 12. 文件重命名但路径泄露
@app.route('/level12', methods=['GET', 'POST'])
def level12_rename_leak():
    """
    文件重命名但响应中泄露了完整路径。
    漏洞：服务端将文件重命名为 UUID，但 JSON 响应直接返回了新文件名和完整 URL。
    攻击者可通过路径泄露访问并验证上传结果。
    """
    if request.method == 'POST':
        if 'file' not in request.files:
            from flask import jsonify
            return jsonify({'error': '没有文件'}), 400

        file = request.files['file']
        if file.filename == '':
            from flask import jsonify
            return jsonify({'error': '文件名为空'}), 400

        # 重命名为 UUID，看似安全
        ext = file.filename.rsplit('.', 1)[-1] if '.' in file.filename else 'bin'
        new_name = f"{uuid.uuid4().hex}.{ext}"
        filepath = os.path.join(UPLOAD_FOLDER, new_name)
        file.save(filepath)

        from flask import jsonify
        # 漏洞点：JSON 响应泄露了完整访问路径
        return jsonify({
            'status': 'ok',
            'message': '上传成功',
            'filename': new_name,
            'url': f'/uploads/{new_name}',        # ← 路径泄露
            'size': os.path.getsize(filepath)
        })

    return render_template('level12.html')


# 13. SVG XSS 上传
@app.route('/level13', methods=['GET', 'POST'])
def level13_svg_xss():
    """
    SVG 文件上传导致存储型 XSS。
    漏洞：允许上传 .svg 文件，但 SVG 可内嵌 JavaScript，浏览器访问时执行。
    绕过：上传含 <script> 或 onload 的 SVG，直接访问文件触发 XSS。
    """
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('没有选择文件', 'error')
            return redirect(request.url)

        file = request.files['file']
        if file.filename == '':
            flash('没有选择文件', 'error')
            return redirect(request.url)

        filename = file.filename.lower()
        # 有缺陷：只允许图片，但包含了 SVG（可执行 JS）
        allowed = {'jpg', 'jpeg', 'png', 'gif', 'svg'}
        ext = filename.rsplit('.', 1)[-1] if '.' in filename else ''
        if ext not in allowed:
            flash('只允许上传图片文件（jpg/png/gif/svg）', 'error')
            return redirect(request.url)

        safe_name = secure_filename(file.filename)
        filepath = os.path.join(UPLOAD_FOLDER, safe_name)
        file.save(filepath)
        flash(f'图片上传成功: {safe_name}  访问: /uploads/{safe_name}', 'success')
        return redirect(url_for('level13_svg_xss'))

    return render_template('level13.html')


# 上传文件访问
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    """访问上传的文件"""
    return send_from_directory(UPLOAD_FOLDER, filename)

# 主页
@app.route('/')
def index():
    """靶场主页"""
    levels = [
        {'id': 1,  'name': '无限制上传',    'difficulty': '简单', 'description': '没有任何限制的文件上传'},
        {'id': 2,  'name': '前端验证绕过',  'difficulty': '简单', 'description': '仅前端JavaScript验证'},
        {'id': 3,  'name': 'MIME类型绕过',  'difficulty': '简单', 'description': '仅验证Content-Type头'},
        {'id': 4,  'name': '黑名单绕过',    'difficulty': '中等', 'description': '扩展名黑名单验证'},
        {'id': 5,  'name': '白名单测试',    'difficulty': '中等', 'description': '扩展名白名单验证'},
        {'id': 6,  'name': '魔术字节绕过',  'difficulty': '中等', 'description': '验证文件魔术字节'},
        {'id': 7,  'name': '大小写绕过',    'difficulty': '简单', 'description': '大小写敏感验证'},
        {'id': 8,  'name': '双扩展名测试',  'difficulty': '简单', 'description': '双扩展名绕过（仅检查末尾扩展名）'},
        {'id': 9,  'name': '路径遍历测试',  'difficulty': '中等', 'description': '路径遍历防护测试'},
        {'id': 10, 'name': '综合防护',      'difficulty': '困难', 'description': '多重防护机制'},
        {'id': 11, 'name': '.htaccess注入', 'difficulty': '中等', 'description': '通过 .htaccess 修改解析规则'},
        {'id': 12, 'name': '路径泄露',      'difficulty': '简单', 'description': '重命名后 JSON 响应泄露完整路径'},
        {'id': 13, 'name': 'SVG XSS',       'difficulty': '中等', 'description': 'SVG 文件上传触发存储型 XSS'},
    ]
    return render_template('index.html', levels=levels)

if __name__ == '__main__':
    print("=" * 50)
    print("UploadRanger 测试靶场")
    print("=" * 50)
    print("访问地址: http://127.0.0.1:5000")
    print("注意: debug模式仅用于本地测试!")
    print("=" * 50)
    # debug=True 仅在本地开发时使用，生产环境应关闭
    app.run(host='127.0.0.1', port=5000, debug=False)
