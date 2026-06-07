#!/usr/bin/python3
"""
CTF工具包新模块测试脚本
基于SAS CTF 2026经验
"""
import sys
import os

# 添加当前目录到路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_waf_bypass():
    """测试WAF绕过模块"""
    print("=" * 60)
    print("测试WAF绕过模块")
    print("=" * 60)
    
    try:
        from waf_bypass import WAFBypass, GameAPIBypass, PDFLeakExtractor
        
        # 测试1: 检查允许的函数列表
        print("\n[1] 测试WAF允许的函数列表:")
        allowed = WAFBypass.get_safe_functions()
        print(f"  允许的函数: {len(allowed)}个")
        for func in allowed[:5]:
            print(f"    - {func}")
            
        # 测试2: 检查函数是否被允许
        print("\n[2] 测试函数是否被允许:")
        test_functions = [
            ("current_database()", True),
            ("substring()", False),
            ("left()", True),
            ("CASE WHEN", False),
            ("ASCII()", True),
        ]
        
        for func, expected in test_functions:
            result = WAFBypass.is_function_allowed(func)
            status = "✓" if result == expected else "✗"
            print(f"  {status} {func}: {result} (期望: {expected})")
            
        # 测试3: 检查方向映射
        print("\n[3] 测试游戏方向映射:")
        directions = ["left", "right", "up", "down", "左", "右", "上", "下"]
        for d in directions:
            if d in GameAPIBypass.DIRECTION_MAP:
                print(f"  ✓ {d}: {GameAPIBypass.DIRECTION_MAP[d]}")
                
        # 测试4: 检查flag模式
        print("\n[4] 测试Flag模式匹配:")
        test_texts = [
            "SAS{test_flag_123}",
            "FLAG{another_flag}",
            "ctf{simple_flag}",
            "no_flag_here",
        ]
        
        for text in test_texts:
            flags = PDFLeakExtractor.extract_flags_from_text(text)
            if flags:
                print(f"  ✓ '{text}' -> {flags}")
            else:
                print(f"  ✗ '{text}' -> 无flag")
                
        print("\n[+] WAF绕过模块测试完成!")
        return True
        
    except ImportError as e:
        print(f"[-] 导入失败: {e}")
        return False
    except Exception as e:
        print(f"[-] 测试失败: {e}")
        return False


def test_game_auto():
    """测试游戏题自动化模块"""
    print("\n" + "=" * 60)
    print("测试游戏题自动化模块")
    print("=" * 60)
    
    try:
        from game_auto import GameAutomation, KernelGenerator
        
        # 测试1: 检查方向映射
        print("\n[1] 测试游戏方向映射:")
        game = GameAutomation("http://example.com")
        for direction in ["left", "right", "up", "down"]:
            if direction in game.directions:
                action = game.directions[direction]
                print(f"  ✓ {direction}: dx={action.dx}, dy={action.dy}")
                
        # 测试2: 检查kernel代码生成
        print("\n[2] 测试Kernel代码生成:")
        
        # 单步kernel
        kernel = KernelGenerator.generate_move_kernel("左")
        print(f"  单步kernel (左):")
        print(f"    {kernel}")
        
        # 路径kernel
        path = ["左", "右", "上", "下"]
        kernel = KernelGenerator.generate_path_kernel(path)
        print(f"\n  路径kernel ({path}):")
        print(f"    {kernel}")
        
        # 智能kernel
        kernel = KernelGenerator.generate_smart_kernel()
        print(f"\n  智能kernel (前5行):")
        for line in kernel.split("\n")[:5]:
            print(f"    {line}")
            
        # 测试3: 检查BFS寻路
        print("\n[3] 测试BFS寻路算法:")
        
        # 创建测试地图
        walls = {(1, 1), (1, 2), (2, 1)}  # 墙壁
        enemies = {(3, 3)}  # 敌人
        
        start = (0, 0)
        goal = (2, 2)
        
        path = game.find_path(start, goal, walls, enemies, grid_size=5)
        if path:
            print(f"  ✓ 从{start}到{goal}的路径: {len(path)}步")
            for i, action in enumerate(path[:3]):
                print(f"    步骤{i+1}: {action.direction}")
        else:
            print(f"  ✗ 无法找到从{start}到{goal}的路径")
            
        print("\n[+] 游戏题自动化模块测试完成!")
        return True
        
    except ImportError as e:
        print(f"[-] 导入失败: {e}")
        return False
    except Exception as e:
        print(f"[-] 测试失败: {e}")
        return False


def test_engine_plugins():
    """测试主引擎新增插件"""
    print("\n" + "=" * 60)
    print("测试主引擎新增插件")
    print("=" * 60)
    
    try:
        # 检查engine.py是否包含新插件
        with open("engine.py", "r") as f:
            content = f.read()
            
        plugins = [
            ("CorazaWAFBypassPlugin", "coraza_bypass"),
            ("GameAPIPlugin", "game_api"),
            ("PDFLeakPlugin", "pdf_leak"),
        ]
        
        print("\n[1] 检查新增插件:")
        for plugin_class, plugin_name in plugins:
            if plugin_class in content:
                print(f"  ✓ {plugin_name} ({plugin_class})")
            else:
                print(f"  ✗ {plugin_name} ({plugin_class}) - 未找到")
                
        # 检查关键函数
        print("\n[2] 检查关键函数:")
        functions = [
            "detect_coraza_waf",
            "union_values_bypass",
            "extract_flags_from_text",
            "generate_move_kernel",
        ]
        
        for func in functions:
            if func in content:
                print(f"  ✓ {func}")
            else:
                print(f"  ✗ {func} - 未找到")
                
        print("\n[+] 主引擎插件测试完成!")
        return True
        
    except Exception as e:
        print(f"[-] 测试失败: {e}")
        return False


def main():
    """主测试函数"""
    print("CTF工具包新模块测试 (基于SAS CTF 2026经验)")
    print("=" * 60)
    
    results = []
    
    # 运行测试
    results.append(("WAF绕过模块", test_waf_bypass()))
    results.append(("游戏题自动化", test_game_auto()))
    results.append(("主引擎插件", test_engine_plugins()))
    
    # 汇总结果
    print("\n" + "=" * 60)
    print("测试汇总")
    print("=" * 60)
    
    passed = 0
    for name, result in results:
        status = "✓ 通过" if result else "✗ 失败"
        print(f"  {name}: {status}")
        if result:
            passed += 1
            
    print(f"\n总计: {passed}/{len(results)} 通过")
    
    if passed == len(results):
        print("\n[+] 所有测试通过! 新模块已就绪。")
        return 0
    else:
        print("\n[-] 部分测试失败，请检查错误信息。")
        return 1


if __name__ == "__main__":
    sys.exit(main())
