# 🏴‍☠️ CTF-Toolkit - 离线版CTF自动化攻防工具包

> 一键自动化 | 智能决策 | 离线可用 | 批量处理

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-v7.0-blue.svg)](VERSION.txt)
[![Python](https://img.shields.io/badge/python-3.8+-green.svg)](https://www.python.org/)

专为CTF竞赛、安全培训、隔离网络环境设计的离线工具包。集成37+自动化插件，覆盖Web/Crypto/PWN/Reverse/Misc/Defense全题型。

---

## ✨ 核心特性

- **🚀 一键自动化** - `auto-solve` 自动识别目标、选择工具链、提取Flag
- **🎯 智能决策** - 指纹识别→漏洞映射→自动利用，全流程无人值守
- **📦 离线可用** - 无需联网，适合隔离网络竞赛环境
- **⚡ 批量处理** - `batch-solve` 批量攻击多个目标
- **🛡️ AWD攻防** - 完整的AWD防御体系：监控/检测/补丁/Flag保护
- **📊 结果保存** - 自动保存攻击日志、截图、Flag到loot目录

---

## 🚀 快速开始

### 安装

```bash
# 克隆仓库
git clone https://github.com/YOUR_USERNAME/ctf-toolkit.git
cd ctf-toolkit

# 运行安装脚本
chmod +x setup.sh
./setup.sh
```

### 基本使用

```bash
# 主入口
./ctf.sh <command> [options]

# 一键解题
./ctf.sh auto-solve <target>

# 批量解题
./ctf.sh batch-solve <targets.txt>

# 启动GUI
./ctf.sh gui
```

---

## 📚 命令列表

### 🎯 自动化命令 (v7.0新增)

| 命令 | 说明 |
|------|------|
| `auto-solve` | 一键自动化解题 |
| `batch-solve` | 批量自动化解题 |
| `coraza-bypass` | Coraza WAF绕过 |
| `game-auto` | 游戏题自动化 |
| `game-kernel` | 生成游戏kernel |
| `pdf-leak` | PDF泄露检测 |

### 🌐 Web类

| 命令 | 说明 |
|------|------|
| `sqli` | SQL注入检测与利用 |
| `xss` | XSS检测与Payload生成 |
| `ssti` | 服务端模板注入 |
| `cmdi` | 命令注入 |
| `lfi` | 本地文件包含 |
| `upload` | 文件上传绕过 |
| `webshell` | WebShell管理 |
| `jwt` | JWT攻击 |

### 🔐 Crypto类

| 命令 | 说明 |
|------|------|
| `hash-crack` | Hash破解 |
| `rsa-attack` | RSA攻击 |
| `encode-detect` | 编码识别 |

### 💥 PWN类

| 命令 | 说明 |
|------|------|
| `checksec` | 二进制安全检查 |
| `rop-search` | ROP链搜索 |
| `exploit` | Exploit模板 |

### 🔍 Reverse类

| 命令 | 说明 |
|------|------|
| `static` | 静态分析 |
| `dynamic` | 动态分析 |
| `pyc-decompile` | PYC反编译 |

### 📁 Misc类

| 命令 | 说明 |
|------|------|
| `file-analyze` | 文件分析 |
| `forensics` | 取证分析 |
| `pcap` | 流量分析 |
| `stego` | 隐写术 |
| `zip-crack` | ZIP破解 |

### 🛡️ Defense类 (AWD)

| 命令 | 说明 |
|------|------|
| `monitor` | 实时监控 |
| `detect` | 入侵检测 |
| `patch` | 漏洞修补 |
| `flag-protect` | Flag保护 |

### 🔎 Recon类

| 命令 | 说明 |
|------|------|
| `network-scan` | 网络扫描 |
| `service-enum` | 服务枚举 |
| `fuzz` | Fuzz测试 |
| `brute` | 暴力破解 |

### 🤖 Scripts类

| 命令 | 说明 |
|------|------|
| `flag-hunter` | Flag猎手 |
| `auto-attack` | 自动攻击 |
| `batch-exploit` | 批量利用 |

---

## 📂 项目结构

```
ctf-toolkit/
├── ctf.sh              # 主入口脚本
├── engine.py           # 核心引擎 (37+插件)
├── auto_ctf.py         # 智能自动化引擎
├── waf_bypass.py       # WAF绕过模块
├── game_auto.py        # 游戏题自动化
├── gui/
│   └── ctf_gui.py      # GUI界面
├── web/                # Web题型脚本
├── crypto/             # Crypto题型脚本
├── pwn/                # PWN题型脚本
├── reverse/            # Reverse题型脚本
├── misc/               # Misc题型脚本
├── defense/            # AWD防御脚本
├── recon/              # 信息收集脚本
├── scripts/            # 自动化脚本
├── loot/               # 结果输出目录 (git ignored)
└── setup.sh            # 安装脚本
```

---

## 🎮 适用场景

- **CTF竞赛** - 快速解题、批量攻击、Flag提取
- **AWD攻防** - 完整的攻击+防御体系
- **安全培训** - 学习各类题型的解题思路
- **渗透测试** - 自动化漏洞检测与利用
- **隔离网络** - 无需联网的离线工具集

---

## 🔧 依赖工具

工具包集成了以下安全工具（大部分已内置）：

- `nmap` - 网络扫描
- `sqlmap` - SQL注入
- `nikto` - Web扫描
- `gobuster` - 目录爆破
- `hashcat` / `john` - 密码破解
- `strings` / `file` / `binwalk` - 文件分析
- `wireshark` / `tshark` - 流量分析
- `gdb` / `pwntools` - PWN工具
- `python3` - 脚本运行环境

---

## 📖 使用示例

### 一键解题

```bash
# 自动识别并解题
./ctf.sh auto-solve http://target.com

# 批量解题
echo "http://target1.com" > targets.txt
echo "http://target2.com" >> targets.txt
./ctf.sh batch-solve targets.txt
```

### SQL注入

```bash
# 自动检测SQL注入
./ctf.sh sqli http://target.com/page?id=1

# 带WAF绕过
./ctf.sh sqli http://target.com/page?id=1 --waf-bypass
```

### AWD防御

```bash
# 启动实时监控
./ctf.sh monitor

# 自动修补漏洞
./ctf.sh patch

# Flag保护
./ctf.sh flag-protect
```

### GUI模式

```bash
# 启动图形界面
./ctf.sh gui
```

---

## 🤝 贡献

欢迎提交Issue和Pull Request！

1. Fork 本仓库
2. 创建你的特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交你的改动 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 打开一个Pull Request

---

## 📄 许可证

本项目采用 MIT 许可证 - 详见 [LICENSE](LICENSE) 文件

---

## ⚠️ 免责声明

本工具仅供安全研究和授权测试使用。使用者应遵守当地法律法规，不得用于非法用途。使用本工具进行任何违法行为，责任由使用者自行承担。

---

## 🔗 相关项目

- [CTFtime](https://ctftime.org/) - CTF竞赛日历
- [Pwntools](https://github.com/Gallopsled/pwntools) - CTF框架
- [Sqlmap](https://github.com/sqlmapproject/sqlmap) - SQL注入工具

---

**🏴‍☠️ Happy Hacking!**
