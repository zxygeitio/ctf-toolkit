#!/bin/bash
# CTF 动态分析
# 用法: bash dynamic.sh <BINARY> [ARGS...]

BINARY="${1:?用法: bash dynamic.sh <BINARY> [ARGS...]}"
ARGS="${@:2}"

echo "=========================================="
echo "  动态分析: $BINARY"
echo "=========================================="

echo -e "\n[1/5] 运行测试"
echo "[*] 无参数运行:"
timeout 3 "$BINARY" 2>&1 | head -20

echo -e "\n[*] 带参数运行:"
timeout 3 "$BINARY" "AAAA" 2>&1 | head -20

echo -e "\n[2/5] strace (系统调用追踪)"
echo "[*] 前30个系统调用:"
timeout 3 strace -f "$BINARY" $ARGS 2>&1 | head -30

echo -e "\n[3/5] ltrace (库函数追踪)"
echo "[*] 前30个库函数调用:"
timeout 3 ltrace "$BINARY" $ARGS 2>&1 | head -30

echo -e "\n[4/5] 环境变量检查"
echo "[*] PATH: $PATH"
echo "[*] LD_PRELOAD检查:"
readelf -d "$BINARY" 2>/dev/null | grep -i "needed"
ldd "$BINARY" 2>/dev/null | head -10

echo -e "\n[5/5] 输入测试"
echo "[*] 测试格式化字符串:"
timeout 3 "$BINARY" "AAAA%x.%x.%x.%x" 2>&1 | head -5
timeout 3 "$BINARY" "AAAA%lx.%lx.%lx.%lx" 2>&1 | head -5

echo "[*] 测试溢出:"
timeout 3 python3 -c "print('A'*100)" | "$BINARY" 2>&1 | head -5

echo -e "\n=========================================="
echo "动态分析完成"
echo "提示: gdb -q $BINARY 进行交互调试"
echo "=========================================="
