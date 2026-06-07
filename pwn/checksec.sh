#!/bin/bash
# CTF 二进制保护检查
# 用法: bash checksec.sh <BINARY>

BINARY="${1:?用法: bash checksec.sh <BINARY>}"

echo "=========================================="
echo "  二进制保护检查: $BINARY"
echo "=========================================="

# checksec
echo -e "\n[1/5] 保护机制"
checksec --file="$BINARY" 2>/dev/null || readelf -l "$BINARY" 2>/dev/null | grep GNU_STACK

# 基本信息
echo -e "\n[2/5] 基本信息"
file "$BINARY"
echo "架构: $(file "$BINARY" | grep -oP '(ELF 32|ELF 64)')"
echo "链接: $(file "$BINARY" | grep -oP '(statically|dynamically)')"
echo "大小: $(wc -c < "$BINARY") bytes"

# 符号表
echo -e "\n[3/5] 关键符号"
readelf -s "$BINARY" 2>/dev/null | grep -iE '(system|execve|puts|printf|read|gets|main|flag|shell|win|backdoor|secret)' | head -10

# 字符串
echo -e "\n[4/5] 关键字符串"
strings "$BINARY" | grep -iE '(flag|password|secret|admin|shell|/bin/|system|exec|key|token|Congratulations|Correct|Wrong)' | head -20

# GOT/PLT
echo -e "\n[5/5] GOT/PLT函数"
readelf -r "$BINARY" 2>/dev/null | grep -i "GLOB" | head -10

# ROP gadgets (快速)
echo -e "\n[*] ROP gadgets (前10个):"
ROPgadget --binary "$BINARY" 2>/dev/null | head -15

# 利用建议
echo -e "\n=========================================="
echo "利用建议:"
echo "=========================================="
checksec_out=$(checksec --file="$BINARY" 2>/dev/null)
if echo "$checksec_out" | grep -q "NX.*disabled"; then
    echo "[+] NX disabled → 可以注入shellcode"
fi
if echo "$checksec_out" | grep -q "Canary.*No"; then
    echo "[+] 无Canary → 栈溢出无需绕过canary"
fi
if echo "$checksec_out" | grep -q "PIE.*No"; then
    echo "[+] 无PIE → 地址固定,可直接跳转"
fi
if echo "$checksec_out" | grep -q "RELRO.*No"; then
    echo "[+] 无RELRO → GOT表可写"
fi
echo "  如果有后门函数: ret2text"
echo "  如果NX开启: ret2libc / ret2csu"
echo "  如果有格式化字符串: 泄露canary/返回地址"
