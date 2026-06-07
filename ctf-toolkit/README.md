# CTF离线版工具包

**版本**: v6.1 (2026-06-07)  
**路径**: `/root/ctf-toolkit/`  
**快捷命令**: `ctf` / `ctf-gui`

## 🚀 快速开始

```bash
# 安装
cd /root/ctf-toolkit
chmod +x setup.sh
./setup.sh

# 查看帮助
bash ctf.sh

# 启动图形界面
ctf gui
```

## 📊 能力总览

| 模块 | 脚本数 | 命令数 | 漏洞类型 |
|------|--------|--------|----------|
| Web | 10 | 11 | SQLi/XSS/SSTI/LFI/CMDi/上传/JWT |
| Crypto | 4 | 4 | RSA/AES/DES/哈希/编码 |
| PWN | 4 | 4 | 栈溢出/堆利用/格式化字符串 |
| Reverse | 3 | 3 | 静态/动态/字节码 |
| Misc | 5 | 5 | 隐写/取证/流量/压缩包 |
| Recon | 4 | 4 | 端口/服务/暴力/FUZZ |
| Defense | 5 | 4 | 监控/修补/保护/检测 |
| Auto | 3 | 3 | 攻击链/Flag搜索/批量 |
| **New** | **2** | **4** | **WAF绕过/游戏题/PDF泄露** |
| **总计** | **48** | **42** | **24+漏洞类型** |

## 🎯 常用命令

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

## 🎮 新增模块详解

### 1. WAF绕过模块 (`waf_bypass.py`)

**核心发现**: Coraza WAF `@detectSQLi` 检测 `UNION SELECT` 但**不检测 `UNION VALUES`**

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
- 使用 `left/right` 替代被拦截的 `substring()`

**WAF允许/拦截函数矩阵**:
```sql
-- ✅ 允许
current_database(), current_setting(), current_user
left(), right(), ASCII(), trim(), upper(), lower()

-- ❌ 被拦截
substring(), replace(), regexp_replace()
length(), char_length(), CASE WHEN, (SELECT ...)
```

### 2. 游戏题自动化 (`game_auto.py`)

**功能**:
- 游戏API端点自动发现
- 游戏状态获取与解析
- BFS自动寻路算法
- 自动收集星星
- Kernel代码生成器
- Sandbox限制检测

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

# 智能kernel (避开敌人，收集星星)
def player_kernel(m, a, o):
    # 查找玩家位置
    for y in range(9):
        for x in range(9):
            if m[y][x] == 80:
                # 寻找星星并移动
                ...
```

**Sandbox限制**:
- ❌ 禁止: `import`, `__name__`, `lambda`, `while`, `return`, `or`, `and`
- ❌ 禁止: `list()`, `type()`, `print()`, 三元表达式
- ✅ 允许: `for range`, `if`, `len`, 索引访问, `abs`, `%`, `//`

## 📁 文件结构

```
ctf-toolkit/
├── ctf.sh              主入口路由
├── setup.sh            初始化
├── engine.py           主引擎 (21个漏洞插件)
├── waf_bypass.py       WAF绕过模块 ← NEW
├── game_auto.py        游戏题自动化 ← NEW
├── gui/                图形界面
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

## 📚 文档索引

1. **README.md** - 本文件 (快速入门)
2. **CAPABILITIES.md** - 完整能力清单 (详细版)
3. **QUICK_SUMMARY.txt** - 能力快速摘要 (简明版)
4. **UPDATE_LOG.md** - 更新日志
5. **SAS_CTF_2026_OPTIMIZATION.md** - SAS CTF经验优化
6. **USAGE.md** - 详细使用说明 (600+行)

## 🏆 核心优势

- ✓ **全覆盖**: Web/Crypto/PWN/Reverse/Misc全题型
- ✓ **自动化**: 21个漏洞插件 + 智能爬虫 + 自动利用
- ✓ **离线可用**: 不依赖网络，适合隔离环境
- ✓ **模块化**: 独立脚本，易于扩展
- ✓ **GUI支持**: 图形界面一键操作
- ✓ **AWD支持**: 攻防赛专用模块
- ✓ **实战验证**: SAS CTF 2026经验优化

## 📈 版本历史

- v1.0: 基础脚本集合
- v2.0: 模块化架构
- v3.0: GUI图形界面
- v4.0: 自动化引擎
- v5.0: AWD防御模块
- v6.0: 插件化架构 (21个插件)
- **v6.1**: SAS CTF 2026优化 (WAF绕过/游戏题/PDF泄露) ← 当前版本

## 🔧 环境要求

### 必需工具
- Python 3.8+
- Bash 4.0+
- curl/wget
- nmap
- sqlmap
- john/hashcat
- strings/objdump
- steghide/zsteg
- Wireshark/tshark

### 可选工具
- Ghidra/IDA (逆向)
- pwndbg (PWN)
- Burp Suite (Web)
- Metasploit (渗透)

## 📞 支持与反馈

- **文档**: `/root/ctf-toolkit/CAPABILITIES.md`
- **更新日志**: `/root/ctf-toolkit/UPDATE_LOG.md`
- **SAS CTF经验**: `/root/ctf-toolkit/SAS_CTF_2026_OPTIMIZATION.md`

---

**最后更新**: 2026-06-07  
**版本**: v6.1  
**作者**: CTF Automation Team
