#!/usr/bin/python3
"""
CTF Game Automation Module - 游戏题自动化模块
基于SAS CTF 2026 Kolobok题实战验证
"""
import json, time, urllib.request, urllib.parse, ssl
from typing import Dict, List, Tuple, Optional, Set
from collections import deque
from dataclasses import dataclass
from enum import Enum

class GameStatus(Enum):
    """游戏状态枚举"""
    RUNNING = "running"
    WON = "won"
    LOST = "lost"
    ESCAPED = "escaped"
    ERROR = "error"


@dataclass
class GameState:
    """游戏状态数据类"""
    player_pos: Tuple[int, int]
    stars_collected: int
    stars_total: int
    escaped: bool
    visible_map: List[List[int]]
    message: str
    error: str
    raw: Dict


@dataclass
class GameAction:
    """游戏动作数据类"""
    dx: int
    dy: int
    direction: str
    description: str


class GameAutomation:
    """游戏题自动化引擎"""
    
    def __init__(self, base_url: str, 
                 state_endpoint: str = "/game_state",
                 move_endpoint: str = "/move_manual",
                 reset_endpoint: str = "/reset_game",
                 flag_endpoint: str = "/get_flag"):
        """
        初始化游戏自动化引擎
        
        Args:
            base_url: 游戏基础URL
            state_endpoint: 状态API端点
            move_endpoint: 移动API端点
            reset_endpoint: 重置API端点
            flag_endpoint: Flag API端点
        """
        self.base_url = base_url.rstrip("/")
        self.state_endpoint = state_endpoint
        self.move_endpoint = move_endpoint
        self.reset_endpoint = reset_endpoint
        self.flag_endpoint = flag_endpoint
        
        # SSL上下文
        self.ssl_ctx = ssl.create_default_context()
        self.ssl_ctx.check_hostname = False
        self.ssl_ctx.verify_mode = ssl.CERT_NONE
        
        # 游戏状态
        self.state: Optional[GameState] = None
        self.known_map: Dict[Tuple[int, int], int] = {}
        self.move_history: List[GameAction] = []
        
        # 方向映射
        self.directions = {
            "left":  GameAction(-1, 0, "left", "向左移动"),
            "right": GameAction(1, 0, "right", "向右移动"),
            "up":    GameAction(0, -1, "up", "向上移动"),
            "down":  GameAction(0, 1, "down", "向下移动"),
        }
        
    # ═══════════════════════════════════════════════
    # API通信
    # ═══════════════════════════════════════════════
    
    def _api_request(self, endpoint: str, method: str = "GET", 
                    data: Optional[Dict] = None) -> Optional[Dict]:
        """发送API请求"""
        try:
            url = f"{self.base_url}{endpoint}"
            
            if data:
                json_data = json.dumps(data).encode()
                req = urllib.request.Request(url, data=json_data, method=method)
                req.add_header("Content-Type", "application/json")
            else:
                req = urllib.request.Request(url, method=method)
                
            resp = urllib.request.urlopen(req, timeout=10, context=self.ssl_ctx)
            body = resp.read().decode(errors="ignore")
            
            try:
                return json.loads(body)
            except:
                print(f"[-] 响应非JSON: {body[:100]}")
                return None
                
        except Exception as e:
            print(f"[-] API请求失败: {e}")
            return None
    
    # ═══════════════════════════════════════════════
    # 状态管理
    # ═══════════════════════════════════════════════
    
    def get_state(self) -> Optional[GameState]:
        """获取游戏状态"""
        raw = self._api_request(self.state_endpoint)
        if not raw:
            return None
            
        try:
            state_data = raw.get("state", raw)
            
            # 解析玩家位置
            player_pos = state_data.get("player_pos", {})
            pos_x = player_pos.get("x", 0)
            pos_y = player_pos.get("y", 0)
            
            # 解析可见地图
            visible = state_data.get("visible", [])
            
            # 更新已知地图
            for cell in visible:
                x = cell.get("x", 0)
                y = cell.get("y", 0)
                t = cell.get("t", "?")
                self.known_map[(x, y)] = t
                
            self.state = GameState(
                player_pos=(pos_x, pos_y),
                stars_collected=state_data.get("scales_collected", 0),
                stars_total=state_data.get("scales_total", 8),
                escaped=state_data.get("escaped", False),
                visible_map=visible,
                message=state_data.get("message", ""),
                error=state_data.get("error", ""),
                raw=raw
            )
            
            return self.state
            
        except Exception as e:
            print(f"[-] 解析状态失败: {e}")
            return None
    
    def reset_game(self) -> bool:
        """重置游戏"""
        result = self._api_request(self.reset_endpoint, method="POST")
        if result:
            print("[+] 游戏已重置")
            self.known_map.clear()
            self.move_history.clear()
            return True
        return False
    
    # ═══════════════════════════════════════════════
    # 移动控制
    # ═══════════════════════════════════════════════
    
    def move(self, direction: str) -> Optional[Dict]:
        """
        移动游戏角色
        
        Args:
            direction: 方向 (left/right/up/down)
        """
        if direction not in self.directions:
            print(f"[-] 未知方向: {direction}")
            return None
            
        action = self.directions[direction]
        result = self._api_request(
            self.move_endpoint, 
            method="POST",
            data={"dx": action.dx, "dy": action.dy}
        )
        
        if result:
            self.move_history.append(action)
            status = result.get("status", "ok")
            print(f"[+] 移动: {direction} -> {status}")
            
            # 更新状态
            if "state" in result:
                self.get_state()
                
        return result
    
    def move_to(self, target_x: int, target_y: int) -> bool:
        """移动到指定位置"""
        if not self.state:
            self.get_state()
            
        if not self.state:
            print("[-] 无法获取游戏状态")
            return False
            
        current_x, current_y = self.state.player_pos
        dx = target_x - current_x
        dy = target_y - current_y
        
        # 计算移动方向
        if dx > 0:
            direction = "right"
        elif dx < 0:
            direction = "left"
        elif dy > 0:
            direction = "down"
        elif dy < 0:
            direction = "up"
        else:
            print("[*] 已在目标位置")
            return True
            
        result = self.move(direction)
        return result is not None
    
    # ═══════════════════════════════════════════════
    # BFS寻路
    # ═══════════════════════════════════════════════
    
    def find_path(self, start: Tuple[int, int], 
                 goal: Tuple[int, int],
                 avoid_enemies: bool = True,
                 grid_size: int = 20) -> Optional[List[GameAction]]:
        """
        BFS寻路算法
        
        Args:
            start: 起始位置 (x, y)
            goal: 目标位置 (x, y)
            avoid_enemies: 是否避开敌人邻格
            grid_size: 网格大小
        """
        # 方向: 右、左、下、上
        dirs = [(1, 0, "right"), (-1, 0, "left"), (0, 1, "down"), (0, -1, "up")]
        
        # 获取墙壁和敌人位置
        walls = set()
        enemies = set()
        
        for (x, y), cell_type in self.known_map.items():
            if cell_type in ["#", "W"]:  # 墙壁
                walls.add((x, y))
            elif cell_type in ["R", "F", "E", "X"]:  # 敌人/出口
                enemies.add((x, y))
                
        # BFS
        queue = deque([(start[0], start[1], [])])
        visited = {(start[0], start[1])}
        
        while queue:
            x, y, path = queue.popleft()
            
            if (x, y) == goal:
                return path
                
            for dx, dy, dir_name in dirs:
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
                if avoid_enemies and enemies:
                    enemy_nearby = False
                    for edx, edy, _ in dirs:
                        if (nx+edx, ny+edy) in enemies:
                            enemy_nearby = True
                            break
                    if enemy_nearby:
                        continue
                        
                visited.add(key)
                action = GameAction(dx, dy, dir_name, f"移动到({nx},{ny})")
                queue.append((nx, ny, path + [action]))
                
        return None
    
    # ═══════════════════════════════════════════════
    # 自动收集星星
    # ═══════════════════════════════════════════════
    
    def find_nearest_star(self) -> Optional[Tuple[int, int]]:
        """查找最近的星星位置"""
        if not self.state:
            self.get_state()
            
        if not self.state:
            return None
            
        current_pos = self.state.player_pos
        stars = []
        
        for (x, y), cell_type in self.known_map.items():
            if cell_type in ["S", "*"]:  # 星星
                stars.append((x, y))
                
        if not stars:
            return None
            
        # 计算曼哈顿距离
        def manhattan(pos):
            return abs(pos[0] - current_pos[0]) + abs(pos[1] - current_pos[1])
            
        stars.sort(key=manhattan)
        return stars[0]
    
    def collect_stars(self, max_moves: int = 400) -> int:
        """
        自动收集所有星星
        
        Returns:
            收集的星星数量
        """
        if not self.state:
            self.get_state()
            
        if not self.state:
            print("[-] 无法获取游戏状态")
            return 0
            
        collected = 0
        
        for move_num in range(max_moves):
            if self.state.escaped:
                print("[+] 游戏已逃脱!")
                break
                
            if self.state.stars_collected >= self.state.stars_total:
                print(f"[+] 已收集所有星星: {self.state.stars_collected}/{self.state.stars_total}")
                break
                
            # 查找最近的星星
            star_pos = self.find_nearest_star()
            if not star_pos:
                print("[-] 未找到星星")
                break
                
            # 寻路到星星
            path = self.find_path(self.state.player_pos, star_pos)
            if not path:
                print("[-] 无法到达星星")
                break
                
            # 执行移动
            for action in path:
                result = self.move(action.direction)
                if not result:
                    break
                    
                # 检查错误
                if self.state and self.state.error:
                    print(f"[-] 游戏错误: {self.state.error}")
                    return collected
                    
                time.sleep(0.2)  # 避免过快移动
                
            # 检查是否收集到星星
            if self.state and self.state.stars_collected > collected:
                collected = self.state.stars_collected
                print(f"[+] 收集星星: {collected}/{self.state.stars_total}")
                
        return collected
    
    # ═══════════════════════════════════════════════
    # 出口寻找与逃脱
    # ═══════════════════════════════════════════════
    
    def find_exit(self) -> Optional[Tuple[int, int]]:
        """查找出口位置"""
        for (x, y), cell_type in self.known_map.items():
            if cell_type in ["X", "O", "E"]:  # 出口
                return (x, y)
        return None
    
    def escape(self, max_moves: int = 100) -> bool:
        """
        自动逃脱游戏
        
        注意: 不要直接用move_manual进入出口!
        需要用kernel走最后一步
        """
        if not self.state:
            self.get_state()
            
        if not self.state:
            print("[-] 无法获取游戏状态")
            return False
            
        # 检查是否已收集所有星星
        if self.state.stars_collected < self.state.stars_total:
            print(f"[-] 还未收集所有星星: {self.state.stars_collected}/{self.state.stars_total}")
            return False
            
        # 查找出口
        exit_pos = self.find_exit()
        if not exit_pos:
            print("[-] 未找到出口")
            return False
            
        print(f"[*] 出口位置: {exit_pos}")
        
        # 移动到出口邻格 (不要直接进入!)
        path = self.find_path(self.state.player_pos, exit_pos)
        if not path:
            print("[-] 无法到达出口")
            return False
            
        # 移动到出口邻格
        for i, action in enumerate(path[:-1]):  # 最后一步不执行
            result = self.move(action.direction)
            if not result:
                return False
                
            time.sleep(0.2)
            
        print("[*] 已到达出口邻格，请用kernel完成最后一步")
        print("[*] 示例kernel: def player_kernel(m,a,o): o[0]=1")
        
        return True
    
    # ═══════════════════════════════════════════════
    # Flag获取
    # ═══════════════════════════════════════════════
    
    def get_flag(self) -> Optional[str]:
        """获取flag"""
        result = self._api_request(self.flag_endpoint)
        if not result:
            return None
            
        if "flag" in result:
            flag = result["flag"]
            print(f"[+] Flag: {flag}")
            return flag
        elif "error" in result:
            print(f"[-] 获取flag失败: {result['error']}")
            return None
        else:
            print(f"[-] 未知响应: {result}")
            return None
    
    # ═══════════════════════════════════════════════
    # 自动化流程
    # ═══════════════════════════════════════════════
    
    def auto_play(self, max_moves: int = 500) -> Optional[str]:
        """
        自动玩游戏
        
        Returns:
            flag或None
        """
        print("[*] 开始自动游戏...")
        
        # 重置游戏
        self.reset_game()
        time.sleep(0.5)
        
        # 获取初始状态
        self.get_state()
        if not self.state:
            print("[-] 无法获取游戏状态")
            return None
            
        print(f"[*] 初始状态: 星星 {self.state.stars_collected}/{self.state.stars_total}")
        
        # 收集星星
        collected = self.collect_stars(max_moves)
        if collected < self.state.stars_total:
            print(f"[-] 未能收集所有星星: {collected}/{self.state.stars_total}")
            return None
            
        # 尝试逃脱
        if self.escape(max_moves):
            # 获取flag
            return self.get_flag()
            
        return None
    
    # ═══════════════════════════════════════════════
    # 调试与状态显示
    # ═══════════════════════════════════════════════
    
    def print_map(self, size: int = 20):
        """打印已知地图"""
        if not self.state:
            self.get_state()
            
        print("\n[*] 已知地图:")
        
        for y in range(size):
            row = ""
            for x in range(size):
                pos = (x, y)
                if pos == self.state.player_pos:
                    row += "P"
                elif pos in self.known_map:
                    cell = self.known_map[pos]
                    if cell == "#":
                        row += "█"
                    elif cell == "S":
                        row += "★"
                    elif cell in ["R", "F", "E"]:
                        row += "☠"
                    elif cell == "X":
                        row += "🚪"
                    else:
                        row += "·"
                else:
                    row += " "
            print(row)
            
        print(f"\n玩家位置: {self.state.player_pos}")
        print(f"星星: {self.state.stars_collected}/{self.state.stars_total}")
        print(f"已探索格子: {len(self.known_map)}")


# ═══════════════════════════════════════════════
# Kernel代码生成器
# ═══════════════════════════════════════════════

class KernelGenerator:
    """Kernel代码生成器 (用于游戏题)"""
    
    # 方向编码
    DIRECTION_CODES = {
        "不动": 0,
        "左": 1,
        "右": 2,
        "上": 3,
        "下": 4,
        "left": 1,
        "right": 2,
        "up": 3,
        "down": 4,
    }
    
    @staticmethod
    def generate_move_kernel(direction: str) -> str:
        """
        生成单步移动kernel
        
        Args:
            direction: 方向 (左/右/上/下)
        """
        code = KernelGenerator.DIRECTION_CODES.get(direction, 0)
        return f"def player_kernel(m, a, o):\n    o[0] = {code}"
    
    @staticmethod
    def generate_path_kernel(path: List[str]) -> str:
        """
        生成路径移动kernel
        
        Args:
            path: 方向列表 ["左", "右", "上", "下"]
        """
        lines = ["def player_kernel(m, a, o):"]
        lines.append("    steps = " + str([KernelGenerator.DIRECTION_CODES.get(d, 0) for d in path]))
        lines.append("    for step in steps:")
        lines.append("        o[0] = step")
        return "\n".join(lines)
    
    @staticmethod
    def generate_smart_kernel() -> str:
        """
        生成智能kernel (避开敌人，收集星星)
        
        注意: sandbox限制!
        - 禁止import
        - 禁止__name__等dunder
        - 禁止三元表达式
        - 禁止while/return/or
        - 只允许for range/if/len/索引访问
        """
        return """def player_kernel(m, a, o):
    # 地图: 32=空地, 35=墙, 83=星, 80=玩家, 82/70/69=敌人
    # m[y][x] 访问地图
    # a[0]=stars_collected, a[1]=stars_total
    # o[0]=方向: 0=不动, 1=左, 2=右, 3=上, 4=下
    
    # 查找玩家位置
    px = 0
    py = 0
    for y in range(9):
        for x in range(9):
            if m[y][x] == 80:
                px = x
                py = y
    
    # 查找最近的星星
    star_x = -1
    star_y = -1
    min_dist = 100
    for y in range(9):
        for x in range(9):
            if m[y][x] == 83:
                dist = abs(x - px) + abs(y - py)
                if dist < min_dist:
                    min_dist = dist
                    star_x = x
                    star_y = y
    
    # 移动到星星
    if star_x >= 0:
        if star_x < px:
            o[0] = 1  # 左
        if star_x > px:
            o[0] = 2  # 右
        if star_y < py:
            o[0] = 3  # 上
        if star_y > py:
            o[0] = 4  # 下
    else:
        o[0] = 0  # 不动"""


# ═══════════════════════════════════════════════
# 测试代码
# ═══════════════════════════════════════════════

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("用法:")
        print("  python3 game_auto.py auto <url>")
        print("  python3 game_auto.py state <url>")
        print("  python3 game_auto.py move <url> <direction>")
        print("  python3 game_auto.py kernel <direction>")
        sys.exit(1)
        
    cmd = sys.argv[1]
    
    if cmd == "auto":
        if len(sys.argv) < 3:
            print("用法: python3 game_auto.py auto <url>")
            sys.exit(1)
        url = sys.argv[2]
        game = GameAutomation(url)
        flag = game.auto_play()
        if flag:
            print(f"\n[+] 最终Flag: {flag}")
            
    elif cmd == "state":
        if len(sys.argv) < 3:
            print("用法: python3 game_auto.py state <url>")
            sys.exit(1)
        url = sys.argv[2]
        game = GameAutomation(url)
        game.get_state()
        if game.state:
            print(f"玩家位置: {game.state.player_pos}")
            print(f"星星: {game.state.stars_collected}/{game.state.stars_total}")
            print(f"已探索: {len(game.known_map)}格子")
            
    elif cmd == "move":
        if len(sys.argv) < 4:
            print("用法: python3 game_auto.py move <url> <direction>")
            sys.exit(1)
        url = sys.argv[2]
        direction = sys.argv[3]
        game = GameAutomation(url)
        game.move(direction)
        
    elif cmd == "kernel":
        if len(sys.argv) < 3:
            print("用法: python3 game_auto.py kernel <direction>")
            sys.exit(1)
        direction = sys.argv[2]
        print(KernelGenerator.generate_move_kernel(direction))
        
    else:
        print(f"未知命令: {cmd}")
        sys.exit(1)
