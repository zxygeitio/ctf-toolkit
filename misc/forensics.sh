#!/bin/bash
# CTF 文件取证分析
# 用法: bash forensics.sh <FILE>

FILE="${1:?用法: bash forensics.sh <FILE>}"

echo "=========================================="
echo "  取证分析: $FILE"
echo "=========================================="

echo -e "\n[1/6] 基本信息"
file "$FILE"
ls -la "$FILE"
md5sum "$FILE"
sha256sum "$FILE"

echo -e "\n[2/6] 文件头 (魔数)"
xxd "$FILE" | head -5

echo -e "\n[3/6] binwalk提取"
binwalk -e "$FILE" 2>/dev/null -C /tmp/binwalk_out
ls /tmp/binwalk_out/ 2>/dev/null

echo -e "\n[4/6] strings深度分析"
echo "[*] 可打印字符串 (长度>=6):"
strings -n 6 "$FILE" | head -30
echo "[*] Unicode字符串:"
strings -el "$FILE" | head -10
echo "[*] URL/IP:"
strings "$FILE" | grep -oP 'https?://[^\s"]+' | head -10
strings "$FILE" | grep -oP '\d+\.\d+\.\d+\.\d+' | sort -u | head -10

echo -e "\n[5/6] 元数据"
exiftool "$FILE" 2>/dev/null | grep -iE '(author|creator|title|subject|comment|description|flag|password|secret)' | head -10

echo -e "\n[6/6] 隐藏数据"
# 检查文件末尾附加数据
FILE_SIZE=$(wc -c < "$FILE")
echo "  文件大小: $FILE_SIZE bytes"

# 检查是否有压缩包签名
if xxd "$FILE" | grep -q "50 4b 03 04"; then
    echo -e "  \033[33m[?] 包含ZIP签名!\033[0m"
fi
if xxd "$FILE" | grep -q "1f 8b 08"; then
    echo -e "  \033[33m[?] 包含GZIP签名!\033[0m"
fi
if xxd "$FILE" | grep -q "37 7a bc af"; then
    echo -e "  \033[33m[?] 包含7z签名!\033[0m"
fi

echo -e "\n=========================================="
echo "取证分析完成"
echo "=========================================="
