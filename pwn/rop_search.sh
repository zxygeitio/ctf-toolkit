#!/bin/bash
# CTF ROP Gadget搜索
# 用法: bash rop_search.sh <BINARY>

BINARY="${1:?用法: bash rop_search.sh <BINARY>}"

echo "=========================================="
echo "  ROP Gadget搜索: $BINARY"
echo "=========================================="

echo -e "\n[1/4] 关键Gadgets"
echo "[*] pop rdi; ret:"
ROPgadget --binary "$BINARY" --only "pop|ret" 2>/dev/null | grep "pop rdi" | head -5

echo "[*] pop rsi; pop r15; ret:"
ROPgadget --binary "$BINARY" --only "pop|ret" 2>/dev/null | grep "pop rsi" | head -5

echo "[*] pop rdx; ret:"
ROPgadget --binary "$BINARY" --only "pop|ret" 2>/dev/null | grep "pop rdx" | head -5

echo "[*] ret:"
ROPgadget --binary "$BINARY" --only "ret" 2>/dev/null | head -3

echo -e "\n[2/4] system/puts/printf地址"
readelf -r "$BINARY" 2>/dev/null | grep -E "(system|puts|printf|execve)" | head -5

echo -e "\n[3/4] /bin/sh字符串"
strings -t x "$BINARY" | grep -i "/bin/sh"
strings -t x "$BINARY" | grep -i "sh"

echo -e "\n[4/4] ret2csu gadgets"
echo "[*] __libc_csu_init gadgets:"
ROPgadget --binary "$BINARY" 2>/dev/null | grep -A5 "ret" | head -15

echo -e "\n[*] 全部Gadget数量:"
ROPgadget --binary "$BINARY" 2>/dev/null | wc -l

echo -e "\n=========================================="
echo "ROP搜索完成"
echo "=========================================="
