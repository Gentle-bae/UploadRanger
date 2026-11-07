@echo off
chcp 936 >nul
title UploadRanger
rem 【修复】切换到脚本所在目录：双击/其他工作目录调用时 python main.py 才能找到入口
cd /d "%~dp0"

rem 【修复】优先用 pythonw 启动：不驻留黑色控制台窗口，任务栏只显示带图标的 GUI。
rem pythonw 不存在（精简 Python）时回退 python 控制台模式。
where pythonw >nul 2>nul
if %errorlevel%==0 (
    start "" pythonw main.py
    exit /b 0
)

echo ==========================================
echo   UploadRanger
echo   by bae
echo ==========================================
echo.

python main.py

if errorlevel 1 (
    echo.
    echo start failed, please install python and requirements
    echo run: pip install -r requirements.txt
    pause
)
