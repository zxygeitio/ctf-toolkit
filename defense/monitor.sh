#!/bin/bash
# CTF 流量监控 - 防御模式
# 用法: bash monitor.sh [IFACE]

IFACE="${1:-eth0}"

echo "=========================================="
echo "  流量监控: $IFACE"
echo "=========================================="

echo -e "\n[1/4] 当前连接"
ss -tnp 2>/dev/null | head -20

echo -e "\n[2/4] 监听端口"
ss -tlnp 2>/dev/null | head -20

echo -e "\n[3/4] 流量统计"
echo "[*] 入站连接TOP10:"
ss -tn 2>/dev/null | awk '{print $4}' | cut -d: -f1 | sort | uniq -c | sort -rn | head -10

echo -e "\n[4/4] 实时抓包 (10秒)"
timeout 10 tshark -i "$IFACE" -c 50 -T fields -e ip.src -e ip.dst -e tcp.dstport -e http.request.uri 2>/dev/null | head -20

echo -e "\n=========================================="
echo "监控完成"
echo "=========================================="
