# CTF智能自动化工作流指南

## 🎯 概述

本指南展示如何使用CTF智能自动化引擎在隔离网络内网环境中高效解题。

**核心优势**:
- ✅ 一键自动化 - 自动识别目标类型，自动选择工具链
- ✅ 智能决策 - 根据中间结果调整策略
- ✅ 离线可用 - 不依赖外部网络
- ✅ 批量处理 - 支持多目标并行解题

## 🚀 快速开始

### 安装

```bash
cd /root/ctf-toolkit
chmod +x setup.sh
./setup.sh
```

### 基本用法

```bash
# 一键自动化解题
bash ctf.sh auto-solve <target>

# 批量解题
bash ctf.sh batch-solve targets.txt
```

## 📋 场景示例

### 场景1: Web题目自动解题

**目标**: http://192.168.1.100

```bash
# 一键自动化解题
bash ctf.sh auto-solve http://192.168.1.100
```

**自动执行流程**:
1. 检测目标类型 → Web
2. Web侦察 → 技术栈/端点/泄露检测
3. 敏感文件检测 → .git/.env/.DS_Store
4. PDF泄露检测 → 提取泄露的flag
5. SQL注入测试 → 错误型/时间盲注/布尔盲注
6. SSTI测试 → Jinja2/Twig/Smarty
7. LFI测试 → 文件包含/目录穿越
8. XSS测试 → 反射/存储/DOM
9. Coraza WAF绕过 → UNION VALUES
10. 游戏API发现 → 自动化游戏题
11. Flag提取 → 自动保存结果

**输出示例**:
```
============================================================
[*] CTF智能自动化引擎 v7.0
[*] 目标: http://192.168.1.100
============================================================
[*] 目标类型: web

[Step 1] Web侦察...
[*] Web侦察: http://192.168.1.100

[Step 2] 检测敏感文件泄露...

[Step 3] 检查PDF泄露...

[Step 4] 根据技术栈选择测试策略...
[*] 检测到数据库相关技术，测试SQL注入...

[Step 5] 测试WAF绕过...

[Step 6] 检测游戏API...

============================================================
[*] 分析完成 (耗时: 45.2秒)
============================================================

[!] 发现的漏洞 (3个):
  - sqli
  - pdf_leak
  - waf_bypass

[+] 发现的flag (2个):
  - flag{sql_injection_found}
  - SAS{pdf_leaked_flag}

[*] 建议 (2个):
  - 使用UNION VALUES绕过Coraza WAF
  - 使用游戏API自动化解题

[*] 使用的工具: web_recon, sqli_test, pdf_leak_check, waf_bypass

[*] 结果已保存: /root/ctf-toolkit/loot/auto/20260607_123456_192.168.1.100
```

### 场景2: 服务目标自动解题

**目标**: 192.168.1.100

```bash
# 自动分析服务目标
bash ctf.sh auto-solve 192.168.1.100
```

**自动执行流程**:
1. 检测目标类型 → Service
2. 端口扫描 → nmap --top-ports 1000
3. 服务识别 → HTTP/SSH/FTP/MySQL等
4. Web服务分析 → 如果发现Web服务，自动进入Web解题流程
5. 服务漏洞检测 → 根据服务类型选择测试策略
6. 弱口令爆破 → SSH/FTP/MySQL等
7. Flag提取 → 自动保存结果

**输出示例**:
```
============================================================
[*] CTF智能自动化引擎 v7.0
[*] 目标: 192.168.1.100
============================================================
[*] 目标类型: service

============================================================
[*] 分析服务目标: 192.168.1.100
============================================================

[Step 1] 端口扫描...
[*] 发现端口: 22/ssh, 80/http, 3306/mysql

[Step 2] 根据服务类型选择测试策略...
[*] 发现Web服务: 端口80
[*] 发现SSH服务: 端口22
[*] 发现MySQL服务: 端口3306

============================================================
[*] 分析完成 (耗时: 120.5秒)
============================================================

[!] 发现的漏洞 (2个):
  - sqli
  - weak_password

[+] 发现的flag (1个):
  - flag{service_exploited}

[*] 建议 (3个):
  - SSH服务在端口22，尝试弱口令爆破
  - MySQL服务在端口3306，尝试弱口令爆破
  - 使用UNION VALUES绕过Coraza WAF

[*] 使用的工具: nmap, web_recon, sqli_test, brute_force
```

### 场景3: 二进制题目自动解题

**目标**: ./challenge.elf

```bash
# 自动分析二进制
bash ctf.sh auto-solve ./challenge.elf
```

**自动执行流程**:
1. 检测目标类型 → Binary
2. 保护检查 → NX/ASLR/PIE/Canary/RELRO
3. 字符串提取 → 查找flag/密码/密钥
4. 反汇编分析 → 查找system/execve调用
5. 漏洞检测 → 栈溢出/格式化字符串
6. Flag提取 → 自动保存结果

**输出示例**:
```
============================================================
[*] CTF智能自动化引擎 v7.0
[*] 目标: ./challenge.elf
============================================================
[*] 目标类型: binary

============================================================
[*] 分析二进制目标: ./challenge.elf
============================================================

[Step 1] 二进制保护检查...
[*] NX未启用，可注入shellcode
[*] 无栈保护，可直接溢出
[*] 无PIE，地址固定

[Step 2] 提取字符串...
[+] 发现flag: flag{binary_exploited}

[Step 3] 反汇编分析...
[*] 程序调用system/execve，可能存在命令执行

============================================================
[*] 分析完成 (耗时: 15.3秒)
============================================================

[!] 发现的漏洞 (2个):
  - NX_OFF
  - has_system_call

[+] 发现的flag (1个):
  - flag{binary_exploited}

[*] 建议 (3个):
  - NX未启用，可注入shellcode
  - 无栈保护，可直接溢出
  - 无PIE，地址固定

[*] 使用的工具: checksec, strings, objdump
```

### 场景4: 密码学题目自动解题

**目标**: ./encrypted.txt

```bash
# 自动分析密码学
bash ctf.sh auto-solve ./encrypted.txt
```

**自动执行流程**:
1. 检测目标类型 → Crypto
2. 编码检测 → Base64/Hex/URL/Unicode
3. 自动解码 → 尝试各种解码方式
4. 密码分析 → RSA/AES/DES/XOR
5. Flag提取 → 自动保存结果

**输出示例**:
```
============================================================
[*] CTF智能自动化引擎 v7.0
[*] 目标: ./encrypted.txt
============================================================
[*] 目标类型: crypto

============================================================
[*] 分析密码学目标: ./encrypted.txt
============================================================

[Step 1] 检测编码...
[*] 内容可能是Base64编码

[Step 2] 尝试解码...
[+] Base64解码: flag{crypto_solved}

============================================================
[*] 分析完成 (耗时: 2.1秒)
============================================================

[+] 发现的flag (1个):
  - flag{crypto_solved}

[*] 使用的工具: base64, xxd
```

### 场景5: Misc题目自动解题

**目标**: ./challenge.pdf

```bash
# 自动分析Misc
bash ctf.sh auto-solve ./challenge.pdf
```

**自动执行流程**:
1. 检测目标类型 → Misc
2. 文件类型检测 → PDF/图片/压缩包/流量包
3. 根据类型处理:
   - PDF: 提取文本，查找flag
   - 图片: EXIF/LSB隐写
   - 压缩包: 解压/破解
   - 流量包: HTTP/DNS分析
4. Flag提取 → 自动保存结果

**输出示例**:
```
============================================================
[*] CTF智能自动化引擎 v7.0
[*] 目标: ./challenge.pdf
============================================================
[*] 目标类型: misc

============================================================
[*] 分析Misc目标: ./challenge.pdf
============================================================

[Step 1] 文件类型检测...
[*] 文件类型: PDF document, version 1.7

[Step 2] 根据文件类型处理...
[*] 检测到PDF文件...
[+] 从PDF提取到flag: SAS{pdf_leaked_flag}

[Step 3] 通用字符串提取...

============================================================
[*] 分析完成 (耗时: 5.8秒)
============================================================

[+] 发现的flag (1个):
  - SAS{pdf_leaked_flag}

[*] 使用的工具: file, strings
```

### 场景6: 游戏题自动解题

**目标**: http://game.ctf.com

```bash
# 游戏题自动化
bash ctf.sh game-auto http://game.ctf.com
```

**自动执行流程**:
1. API端点发现 → /game_state, /move_manual, etc.
2. 游戏状态获取 → 解析地图/玩家位置/星星
3. BFS寻路 → 自动寻找到星星的最短路径
4. 自动收集 → 逐个收集所有星星
5. 出口寻找 → 找到出口位置
6. Kernel生成 → 生成进入出口的kernel
7. Flag获取 → 自动获取flag

**输出示例**:
```
[*] 开始自动游戏...
[+] 游戏已重置
[*] 初始状态: 星星 0/8
[+] 发现游戏API: /game_state (200)
[+] 发现游戏API: /move_manual (405)
[+] 发现游戏API: /reset_game (200)
[+] 发现游戏API: /get_flag (200)

[*] 收集星星: 1/8
[*] 收集星星: 2/8
...
[*] 收集星星: 8/8

[*] 出口位置: (15, 10)
[*] 已到达出口邻格，请用kernel完成最后一步
[*] 示例kernel: def player_kernel(m,a,o): o[0]=1

[+] Flag: SAS{game_solved}
```

### 场景7: Coraza WAF绕过

**目标**: http://target.com/api

```bash
# Coraza WAF绕过测试
bash ctf.sh coraza-bypass http://target.com/api id
```

**自动执行流程**:
1. WAF检测 → 检测是否使用Coraza WAF
2. UNION VALUES测试 → 测试绕过WAF
3. 数据提取 → 提取数据库名等信息
4. 函数矩阵 → 显示允许/拦截的函数

**输出示例**:
```
[*] 测试Coraza WAF绕过...
[+] 检测到WAF拦截(403)
[+] 确认为Coraza/类似WAF，UNION VALUES可绕过

[*] 测试UNION VALUES绕过...
[+] UNION VALUES绕过成功!
  Position 1: ASCII=99 char='c'
  Position 2: ASCII=116 char='t'
  Position 3: ASCII=102 char='f'
  Position 4: ASCII=100 char='d'
  Position 5: ASCII=98 char='b'
```

### 场景8: 批量解题

**目标**: targets.txt (每行一个目标)

```bash
# 创建目标文件
cat > targets.txt << 'EOF'
http://192.168.1.100
http://192.168.1.101
192.168.1.102
./challenge1.elf
./challenge2.pdf
EOF

# 批量解题
bash ctf.sh batch-solve targets.txt
```

**输出示例**:
```
[*] 批量解题: 5个目标

[1/5] 处理目标: http://192.168.1.100
[+] 发现flag: flag{web1_solved}

[2/5] 处理目标: http://192.168.1.101
[+] 发现flag: flag{web2_solved}

[3/5] 处理目标: 192.168.1.102
[+] 发现flag: flag{service_solved}

[4/5] 处理目标: ./challenge1.elf
[+] 发现flag: flag{binary_solved}

[5/5] 处理目标: ./challenge2.pdf
[+] 发现flag: SAS{misc_solved}

============================================================
[*] 批量解题完成
============================================================
[*] 总计: 5个目标
[+] 成功: 5个
[-] 失败: 0个

[+] 成功提取的flag:
  http://192.168.1.100: flag{web1_solved}
  http://192.168.1.101: flag{web2_solved}
  192.168.1.102: flag{service_solved}
  ./challenge1.elf: flag{binary_solved}
  ./challenge2.pdf: SAS{misc_solved}
```

## 🔧 高级用法

### 自定义超时时间

```bash
# 设置超时时间为60秒
python3 auto_ctf.py --timeout 60 http://target.com
```

### 详细输出

```bash
# 启用详细输出
python3 auto_ctf.py -v http://target.com
```

### 自定义输出目录

```bash
# 指定输出目录
python3 auto_ctf.py -o /tmp/results http://target.com
```

### 组合使用

```bash
# 先自动化解题，再手动深入
bash ctf.sh auto-solve http://target.com

# 查看结果
cat /root/ctf-toolkit/loot/auto/*/analysis.json

# 根据建议手动操作
bash ctf.sh sqli http://target.com?id=1
bash ctf.sh ssti http://target.com?input=test
```

## 📊 自动化能力矩阵

| 目标类型 | 自动检测 | 自动分析 | 自动利用 | Flag提取 |
|---------|---------|---------|---------|---------|
| Web URL | ✅ | ✅ | ✅ | ✅ |
| IP/域名 | ✅ | ✅ | ✅ | ✅ |
| 二进制 | ✅ | ✅ | ⚠️ | ✅ |
| 密码学 | ✅ | ✅ | ⚠️ | ✅ |
| Misc文件 | ✅ | ✅ | ⚠️ | ✅ |
| 游戏题 | ✅ | ✅ | ✅ | ✅ |

**说明**:
- ✅ 完全自动
- ⚠️ 部分自动，可能需要手动干预

## 🎯 最佳实践

### 1. 先自动后手动

```bash
# 先用自动化引擎快速扫描
bash ctf.sh auto-solve http://target.com

# 查看发现的漏洞和建议
cat /root/ctf-toolkit/loot/auto/*/analysis.json

# 根据建议手动深入
bash ctf.sh sqli http://target.com?id=1
```

### 2. 批量处理

```bash
# 创建目标列表
echo "http://target1.com" > targets.txt
echo "http://target2.com" >> targets.txt
echo "192.168.1.100" >> targets.txt

# 批量解题
bash ctf.sh batch-solve targets.txt

# 查看汇总结果
cat /root/ctf-toolkit/loot/auto/*/flag.txt
```

### 3. 结合手动工具

```bash
# 自动化发现SQL注入
bash ctf.sh auto-solve http://target.com

# 手动深入利用
bash ctf.sh sqli http://target.com?id=1

# 提取数据
sqlmap -u "http://target.com?id=1" --dbs --batch
```

### 4. 保存和复用

```bash
# 保存自动化结果
bash ctf.sh auto-solve http://target.com

# 复用结果
cat /root/ctf-toolkit/loot/auto/*/analysis.json | jq '.vulns'

# 根据漏洞类型选择工具
bash ctf.sh sqli http://target.com
bash ctf.sh ssti http://target.com
bash ctf.sh lfi http://target.com
```

## 🔍 故障排除

### 问题1: 自动化没有发现漏洞

**可能原因**:
- 目标有WAF防护
- 漏洞不在自动化覆盖范围
- 需要手动深入分析

**解决方案**:
```bash
# 查看详细输出
python3 auto_ctf.py -v http://target.com

# 手动测试特定漏洞
bash ctf.sh sqli http://target.com?id=1
bash ctf.sh ssti http://target.com?input=test
```

### 问题2: Flag提取失败

**可能原因**:
- Flag格式不匹配
- Flag被编码/加密
- 需要手动解密

**解决方案**:
```bash
# 手动搜索Flag
bash ctf.sh flag-hunt /tmp

# 检查编码
bash ctf.sh crypto base64 <encoded_string>

# 检查加密
bash ctf.sh crypto rsa <n> <e> <c>
```

### 问题3: 游戏题自动化失败

**可能原因**:
- API端点不匹配
- Kernel sandbox限制
- 需要手动调整策略

**解决方案**:
```bash
# 手动发现API
bash ctf.sh game-auto http://game.ctf.com

# 生成kernel
bash ctf.sh game-kernel 左

# 手动提交kernel
curl -X POST http://game.ctf.com/submit_kernel -d 'kernel_input=def player_kernel(m,a,o): o[0]=1'
```

## 📈 性能优化

### 并行处理

```bash
# 使用并行处理多个目标
cat targets.txt | xargs -P 4 -I {} bash ctf.sh auto-solve {}
```

### 超时控制

```bash
# 设置合理超时
python3 auto_ctf.py --timeout 30 http://target.com

# 批量处理时设置更长超时
python3 auto_ctf.py --timeout 60 -b targets.txt
```

### 结果缓存

```bash
# 查看历史结果
ls /root/ctf-toolkit/loot/auto/

# 复用历史分析
cat /root/ctf-toolkit/loot/auto/*/analysis.json
```

## 🎓 学习路径

### 初学者

1. 从简单题目开始
```bash
bash ctf.sh auto-solve http://simple-ctf.com
```

2. 学习自动化流程
```bash
# 查看详细输出
python3 auto_ctf.py -v http://target.com

# 理解每个步骤
cat /root/ctf-toolkit/loot/auto/*/analysis.json
```

3. 手动复现自动化发现
```bash
bash ctf.sh sqli http://target.com?id=1
```

### 中级用户

1. 批量处理
```bash
bash ctf.sh batch-solve targets.txt
```

2. 结合手动工具
```bash
# 自动化扫描
bash ctf.sh auto-solve http://target.com

# 手动深入
bash ctf.sh sqli http://target.com?id=1
sqlmap -u "http://target.com?id=1" --dbs --batch
```

3. 自定义工作流
```bash
# 创建自定义脚本
cat > custom_workflow.sh << 'EOF'
#!/bin/bash
# 自定义工作流
bash ctf.sh auto-solve $1
bash ctf.sh flag-hunt /tmp
bash ctf.sh loot
EOF
chmod +x custom_workflow.sh
```

### 高级用户

1. 扩展自动化引擎
```python
# 添加自定义检测
def custom_detection(url):
    # 自定义逻辑
    pass
```

2. 集成外部工具
```bash
# 集成sqlmap
bash ctf.sh auto-solve http://target.com
sqlmap -u "http://target.com?id=1" --dbs --batch
```

3. 优化性能
```bash
# 并行处理
cat targets.txt | xargs -P 8 -I {} bash ctf.sh auto-solve {}
```

## 📚 参考资料

- **README.md** - 快速入门
- **CAPABILITIES.md** - 完整能力清单
- **QUICK_SUMMARY.txt** - 能力快速摘要
- **FINAL_SUMMARY.md** - 最终总结
- **UPDATE_LOG.md** - 更新日志
- **SAS_CTF_2026_OPTIMIZATION.md** - SAS CTF经验优化

## 🏆 总结

CTF智能自动化引擎能够:

1. **自动识别目标类型** - Web/服务/二进制/密码学/Misc
2. **自动选择工具链** - 根据目标类型自动选择测试策略
3. **自动执行测试** - 一键执行所有相关测试
4. **自动提取Flag** - 自动识别和保存flag
5. **提供优化建议** - 根据发现提供后续操作建议

**核心价值**:
- 节省时间 - 自动化重复性工作
- 提高效率 - 智能决策减少试错
- 降低门槛 - 新手也能快速上手
- 离线可用 - 适合隔离网络环境

**适用场景**:
- CTF比赛 (Jeopardy/Attack-Defense)
- 隔离网络竞赛
- 安全培训与学习
- 渗透测试实践

---

**最后更新**: 2026-06-07  
**版本**: v7.0  
**作者**: CTF Automation Team
