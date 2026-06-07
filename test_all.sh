#!/bin/bash
echo "=========================================="
echo "CTF工具包功能测试"
echo "=========================================="

echo ""
echo "[1/10] 测试主入口帮助..."
bash ctf.sh help > /dev/null 2>&1 && echo "✓ 帮助命令正常" || echo "✗ 帮助命令失败"

echo ""
echo "[2/10] 测试game-kernel命令..."
result=$(bash ctf.sh game-kernel 左 2>&1)
if echo "$result" | grep -q "o\[0\] = 1"; then
    echo "✓ game-kernel命令正常"
else
    echo "✗ game-kernel命令失败"
    echo "  输出: $result"
fi

echo ""
echo "[3/10] 测试auto-solve命令..."
timeout 5 bash ctf.sh auto-solve http://test.com 2>&1 | head -5
echo "✓ auto-solve命令已测试"

echo ""
echo "[4/10] 测试waf_bypass模块..."
python -c "from waf_bypass import WAFBypass, GameAPIBypass, PDFLeakExtractor; print('✓ waf_bypass模块加载正常')" 2>&1

echo ""
echo "[5/10] 测试game_auto模块..."
python -c "from game_auto import GameAutomation, KernelGenerator; print('✓ game_auto模块加载正常')" 2>&1

echo ""
echo "[6/10] 测试auto_ctf模块..."
python -c "from auto_ctf import WorkflowEngine, DecisionEngine; print('✓ auto_ctf模块加载正常')" 2>&1

echo ""
echo "[7/10] 测试engine模块..."
python -c "import sys; sys.path.insert(0, '/root/ctf-toolkit'); from engine import Engine; print('✓ engine模块加载正常')" 2>&1

echo ""
echo "[8/10] 测试GUI模块..."
python -c "import sys; sys.path.insert(0, '/root/ctf-toolkit/gui'); import ctf_gui; print('✓ GUI模块加载正常')" 2>&1

echo ""
echo "[9/10] 测试Kernel生成..."
for dir in 左 右 上 下; do
    result=$(bash ctf.sh game-kernel $dir 2>&1)
    if echo "$result" | grep -q "o\[0\]"; then
        echo "✓ Kernel生成 ($dir) 正常"
    else
        echo "✗ Kernel生成 ($dir) 失败"
    fi
done

echo ""
echo "[10/10] 测试Flag提取..."
python -c "
from waf_bypass import PDFLeakExtractor
flags = PDFLeakExtractor.extract_flags_from_text('SAS{test_flag} and FLAG{another}')
if len(flags) == 2:
    print('✓ Flag提取正常')
else:
    print('✗ Flag提取失败')
" 2>&1

echo ""
echo "=========================================="
echo "测试完成"
echo "=========================================="
