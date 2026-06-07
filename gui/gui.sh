#!/bin/bash
# CTF GUI启动器
# 用法: ctf-gui 或 bash gui.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# 检查显示器
if [ -z "$DISPLAY" ] && [ -z "$WAYLAND_DISPLAY" ]; then
    echo "[!] 未检测到图形环境 (DISPLAY未设置)"
    echo "    如果在SSH中,请使用: ssh -X user@host"
    echo "    或设置: export DISPLAY=:0"
    echo ""
    echo "    仍然尝试启动..."
    export DISPLAY=:0
fi

# 启动GUI
/usr/bin/python3 "$SCRIPT_DIR/ctf_gui.py" "$@" &
GUI_PID=$!

echo "[*] CTF GUI已启动 (PID: $GUI_PID)"
echo "[*] 关闭窗口或按 Ctrl+C 退出"

# 等待GUI关闭
wait $GUI_PID 2>/dev/null
