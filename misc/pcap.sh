#!/bin/bash
# CTF 流量包分析
# 用法: bash pcap.sh <FILE>

FILE="${1:?用法: bash pcap.sh <FILE>}"

echo "=========================================="
echo "  流量包分析: $FILE"
echo "=========================================="

echo -e "\n[1/8] 基本信息"
capinfos "$FILE" 2>/dev/null | head -15

echo -e "\n[2/8] 协议分布"
tshark -r "$FILE" -q -z io,phs 2>/dev/null | head -20

echo -e "\n[3/8] HTTP流量"
tshark -r "$FILE" -Y "http" -T fields -e http.request.method -e http.request.uri -e http.host 2>/dev/null | head -20

echo -e "\n[4/8] HTTP对象导出"
mkdir -p /tmp/pcap_http
tshark -r "$FILE" --export-objects http,/tmp/pcap_http 2>/dev/null
ls -la /tmp/pcap_http/ 2>/dev/null | head -10

echo -e "\n[5/8] DNS查询"
tshark -r "$FILE" -Y "dns" -T fields -e dns.qry.name 2>/dev/null | sort -u | head -20

echo -e "\n[6/8] FTP流量"
tshark -r "$FILE" -Y "ftp" -T fields -e ftp.request.command -e ftp.request.arg 2>/dev/null | head -20

echo -e "\n[7/8] TCP流重组 (前5个流)"
tshark -r "$FILE" -q -z conv,tcp 2>/dev/null | head -15

echo -e "\n[8/8] 搜索Flag"
tshark -r "$FILE" -Y "frame contains \"flag\"" -T fields -e data 2>/dev/null | head -5
tshark -r "$FILE" -Y "frame contains \"ctf\"" -T fields -e data 2>/dev/null | head -5
# 搜索base64编码的flag
tshark -r "$FILE" -T fields -e data.data 2>/dev/null | grep -oP '[A-Za-z0-9+/]{20,}={0,2}' | while read b64; do
    decoded=$(echo "$b64" | base64 -d 2>/dev/null)
    echo "$decoded" | grep -qi "flag" && echo "  Base64: $b64 -> $decoded"
done

echo -e "\n=========================================="
echo "流量分析完成"
echo "HTTP对象导出在: /tmp/pcap_http/"
echo "=========================================="
