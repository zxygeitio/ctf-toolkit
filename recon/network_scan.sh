#!/bin/bash
# CTF 网络扫描
# 用法: bash network_scan.sh <TARGET>

TARGET="${1:?用法: bash network_scan.sh <TARGET>}"
OUTDIR="/root/ctf-toolkit/loot/recon/$(echo $TARGET | tr '/' '_')"
mkdir -p "$OUTDIR"

echo "=========================================="
echo "  网络扫描: $TARGET"
echo "  输出: $OUTDIR"
echo "=========================================="

echo -e "\n[1/4] 快速端口扫描 (masscan)"
masscan -p1-65535 "$TARGET" --rate=5000 -oL "$OUTDIR/masscan.txt" 2>/dev/null
open_ports=$(awk '/open/{print $3}' "$OUTDIR/masscan.txt" 2>/dev/null | sort -n | tr '\n' ',' | sed 's/,$//')
echo "  开放端口: $open_ports"

echo -e "\n[2/4] 服务版本检测 (nmap)"
if [ -n "$open_ports" ]; then
    nmap -Pn -sV -sC -p "$open_ports" "$TARGET" -oN "$OUTDIR/nmap.txt" 2>/dev/null
    cat "$OUTDIR/nmap.txt"
else
    nmap -Pn -sV -sC --top-ports 1000 "$TARGET" -oN "$OUTDIR/nmap.txt" 2>/dev/null
    cat "$OUTDIR/nmap.txt"
fi

echo -e "\n[3/4] UDP扫描 (常用端口)"
nmap -Pn -sU --top-ports 20 "$TARGET" -oN "$OUTDIR/nmap_udp.txt" 2>/dev/null | grep -E "(open|filtered)" | head -10

echo -e "\n[4/4] 指纹识别"
if [ -f "$OUTDIR/nmap.txt" ]; then
    echo "[*] 发现的服务:"
    grep -E "^[0-9]+/tcp" "$OUTDIR/nmap.txt" | awk '{print "  "$0}'
    echo "[*] 操作系统猜测:"
    grep "OS" "$OUTDIR/nmap.txt" | head -3
fi

echo -e "\n=========================================="
echo "扫描完成! 结果: $OUTDIR"
echo "=========================================="
