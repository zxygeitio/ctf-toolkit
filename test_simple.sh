#!/bin/bash
echo "=========================================="
echo "CTF工具包功能测试"
echo "=========================================="

echo ""
echo "[1/6] 测试主入口帮助..."
bash ctf.sh help > /dev/null 2>&1 && echo "✓ 帮助命令正常" || echo "✗ 帮助命令失败"

echo ""
echo "[2/6] 测试game-kernel命令..."
result=$(bash ctf.sh game-kernel 左 2>&1)
if echo "$result" | grep -q "o\[0\] = 1"; then
    echo "✓ game-kernel命令正常"
else
    echo "✗ game-kernel命令失败"
fi

echo ""
echo "[3/6] 测试waf_bypass模块..."
python -c "from waf_bypass import WAFBypass; print('✓ waf_bypass模块加载正常')" 2>&1

echo ""
echo "[4/6] 测试game_auto模块..."
python -c "from game_auto import GameAutomation; print('✓ game_auto模块加载正常')" 2>&1

echo ""
echo "[5/6] 测试auto_ctf模块..."
python -c "from auto_ctf import WorkflowEngine; print('✓ auto_ctf模块加载正常')" 2>&1

echo ""
echo "[6/6] 测试Kernel生成..."
for dir in 左 右 上 下; do
    result=$(bash ctf.sh game-kernel $dir 2>&1)
    if echo "$result" | grep -q "o\[0\]"; then
        echo "✓ Kernel生成 ($dir) 正常"
    else
        echo "✗ Kernel生成 ($dir) 失败"
    fi
done

echo ""
echo "=========================================="
echo "测试完成"
echo "=========================================="
