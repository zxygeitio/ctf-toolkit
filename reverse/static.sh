#!/bin/bash
# CTF 静态分析
# 用法: bash static.sh <BINARY>

BINARY="${1:?用法: bash static.sh <BINARY>}"

echo "=========================================="
echo "  静态分析: $BINARY"
echo "=========================================="

# 基本信息
echo -e "\n[1/8] 文件类型"
file "$BINARY"

# 字符串
echo -e "\n[2/8] 关键字符串 (前30)"
strings -n 8 "$BINARY" | grep -iE '(flag|password|secret|key|admin|shell|/bin/|system|exec|congratul|correct|wrong|error|success|login|user)' | head -30

# ELF头
echo -e "\n[3/8] ELF头信息"
readelf -h "$BINARY" 2>/dev/null | grep -E '(Class|Machine|Entry|Type)'

# 段信息
echo -e "\n[4/8] 段信息"
readelf -S "$BINARY" 2>/dev/null | grep -E '(PROGBITS|NOTE|GNU|INIT|FINI)' | head -10

# 导入函数
echo -e "\n[5/8] 导入函数"
readelf -r "$BINARY" 2>/dev/null | grep GLOB | head -15

# 导出符号
echo -e "\n[6/8] 导出符号"
readelf -s "$BINARY" 2>/dev/null | grep FUNC | grep -v UND | head -15

# objdump反汇编main
echo -e "\n[7/8] main函数反汇编"
objdump -d -M intel "$BINARY" 2>/dev/null | awk '/^[0-9a-f]+ <main>:$/,/^$/' | head -60

# radare2分析
echo -e "\n[8/8] radare2分析"
r2 -q -c "aaa; afl; pdf @ main" "$BINARY" 2>/dev/null | head -40

echo -e "\n=========================================="
echo "静态分析完成"
echo "=========================================="
