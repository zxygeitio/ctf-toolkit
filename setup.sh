#!/bin/bash
# CTF工具包初始化
# 用法: bash setup.sh

TOOLKIT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=========================================="
echo "  CTF工具包初始化"
echo "=========================================="

# 创建目录
mkdir -p "$TOOLKIT_DIR"/{loot/{web,pwn,crypto,misc,recon,auto,batch},notes,payloads/generated}

# 设置权限
chmod +x "$TOOLKIT_DIR"/ctf.sh
chmod +x "$TOOLKIT_DIR"/web/*.sh
chmod +x "$TOOLKIT_DIR"/crypto/*.sh
chmod +x "$TOOLKIT_DIR"/crypto/*.py
chmod +x "$TOOLKIT_DIR"/pwn/*.sh
chmod +x "$TOOLKIT_DIR"/pwn/*.py
chmod +x "$TOOLKIT_DIR"/reverse/*.sh
chmod +x "$TOOLKIT_DIR"/reverse/*.py
chmod +x "$TOOLKIT_DIR"/misc/*.sh
chmod +x "$TOOLKIT_DIR"/recon/*.sh
chmod +x "$TOOLKIT_DIR"/defense/*.sh
chmod +x "$TOOLKIT_DIR"/scripts/*.sh
chmod +x "$TOOLKIT_DIR"/gui/*.sh
chmod +x "$TOOLKIT_DIR"/gui/*.py

# 检查依赖
echo -e "\n[*] 检查依赖工具..."
TOOLS=("nmap" "masscan" "sqlmap" "hydra" "gobuster" "ffuf" "nuclei" "nikto" "hashcat" "john" "steghide" "binwalk" "exiftool" "checksec" "ROPgadget" "radare2" "gdb" "tshark" "curl" "socat" "nc" "strings" "objdump" "readelf" "file" "xxd")
for tool in "${TOOLS[@]}"; do
    if which "$tool" >/dev/null 2>&1; then
        echo "  [OK] $tool"
    else
        echo "  [--] $tool (未安装)"
    fi
done

# 创建快捷方式
echo -e "\n[*] 创建快捷方式..."
cat > /usr/local/bin/ctf << 'EOF'
#!/bin/bash
bash /root/ctf-toolkit/ctf.sh "$@"
EOF
chmod +x /usr/local/bin/ctf

echo -e "\n=========================================="
echo "  初始化完成!"
echo "  用法: ctf <模块> [参数...]"
echo "  或:   bash $TOOLKIT_DIR/ctf.sh <模块> [参数...]"
echo "=========================================="
