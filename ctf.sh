#!/bin/bash
#============================================================
# CTF 攻防自动化工具包 - 离线版
# 适用于隔离网络/内网CTF竞赛
# 用法: bash ctf.sh [模块] [目标]
#============================================================

TOOLKIT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOOT_DIR="$TOOLKIT_DIR/loot"
NOTES_DIR="$TOOLKIT_DIR/notes"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

banner() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║          CTF 攻防自动化工具包 - Offline Edition          ║"
    echo "║                   $(date '+%Y-%m-%d %H:%M')                      ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

usage() {
    banner
    echo "用法: bash ctf.sh <模块> [参数...]"
    echo ""
    echo -e "${GREEN}=== 攻击模块 ===${NC}"
    echo "  web-recon   <URL>              Web快速侦察"
    echo "  sqli        <URL>              SQL注入检测"
    echo "  upload      <URL> <UPLOAD_PATH> 文件上传绕过"
    echo "  ssti        <URL>              SSTI模板注入检测"
    echo "  lfi         <URL> <PARAM>      文件包含检测"
    echo "  xss         <URL>              XSS检测"
    echo "  jwt         <TOKEN>            JWT攻击"
    echo "  cmdi        <URL> <PARAM>      命令注入检测"
    echo "  shell       [TYPE]             生成Webshell/反弹Shell"
    echo "  exploit     <URL>              自动化漏洞利用"
    echo ""
    echo -e "${GREEN}=== 密码学 ===${NC}"
    echo "  crypto      <MODE> <INPUT>     密码解密(RSA/BASE64/CAESAR/XOR/...)"
    echo "  rsa         <n> <e> <c>        RSA攻击(小e/共模/分解)"
    echo "  hash        <HASH>             哈希识别+破解"
    echo "  encode      <TEXT>             多重编码检测"
    echo ""
    echo -e "${GREEN}=== PWN ===${NC}"
    echo "  pwn-check   <BINARY>           二进制保护检查"
    echo "  pwn-exploit <BINARY>           自动生成exploit模板"
    echo "  pwn-pattern <LEN>              生成模式字符串"
    echo "  pwn-rop     <BINARY>           ROP gadget搜索"
    echo ""
    echo -e "${GREEN}=== 逆向 ===${NC}"
    echo "  rev         <BINARY>           静态分析(strings/objdump/r2)"
    echo "  rev-dynamic <BINARY>           动态分析(ltrace/strace/gdb)"
    echo "  rev-pyc     <FILE>             Python字节码反编译"
    echo ""
    echo -e "${GREEN}=== Misc ===${NC}"
    echo "  stego       <FILE>             隐写分析(图片/音频)"
    echo "  forensics   <FILE>             文件取证分析"
    echo "  pcap        <FILE>             流量包分析"
    echo "  file        <FILE>             文件类型深度分析"
    echo "  zip         <FILE>             压缩包破解/修复"
    echo ""
    echo -e "${GREEN}=== 侦察 ===${NC}"
    echo "  scan        <TARGET>           端口扫描+服务识别"
    echo "  enum        <TARGET>           服务枚举"
    echo "  brute       <TARGET> <SERVICE> 暴力破解(ssh/ftp/mysql)"
    echo "  fuzz        <URL>              目录/参数FUZZ"
    echo ""
    echo -e "${GREEN}=== 防御 ===${NC}"
    echo "  monitor     [IFACE]            流量监控"
    echo "  patch       <SERVICE>          漏洞修补"
    echo "  flag-protect                     Flag文件保护"
    echo "  detect      [IFACE]            攻击检测"
    echo ""
    echo -e "${GREEN}=== 自动化 ===${NC}"
    echo "  auto        <TARGET>           全自动攻击链"
    echo "  flag-hunt   <PATH>             Flag搜索"
    echo "  batch       <TARGETS_FILE>     批量利用"
    echo "  loot                              查看战利品"
    echo "  gui                               启动图形界面"
    echo ""
    echo -e "${YELLOW}=== 新增智能自动化 (SAS CTF 2026经验) ===${NC}"
    echo "  auto-solve  <target>           一键自动化解题"
    echo "  batch-solve <targets.txt>      批量自动化解题"
    echo "  coraza-bypass <url> [param]    Coraza WAF绕过测试"
    echo "  game-auto   <url>              游戏题自动化"
    echo "  game-kernel <direction>        生成游戏kernel"
    echo "  pdf-leak    <url/file>         PDF泄露检测"
    echo ""
    echo -e "${YELLOW}示例:${NC}"
    echo "  bash ctf.sh web-recon http://192.168.1.100"
    echo "  bash ctf.sh scan 192.168.1.0/24"
    echo "  bash ctf.sh sqli http://target/page?id=1"
    echo "  bash ctf.sh crypto base64 SGVsbG8="
    echo "  bash ctf.sh auto 192.168.1.100"
    echo "  bash ctf.sh flag-hunt /tmp"
}

# ═══════════════════════════════════════════════
# 新增智能自动化函数 (SAS CTF 2026经验)
# ═══════════════════════════════════════════════

auto_solve() {
    local target="$1"
    if [ -z "$target" ]; then
        echo -e "${RED}用法: ctf auto-solve <target>${NC}"
        return 1
    fi
    python "$TOOLKIT_DIR/auto_ctf.py" "$target"
}

batch_solve() {
    local targets_file="$1"
    if [ -z "$targets_file" ] || [ ! -f "$targets_file" ]; then
        echo -e "${RED}用法: ctf batch-solve <targets.txt>${NC}"
        return 1
    fi
    python "$TOOLKIT_DIR/auto_ctf.py" -b "$targets_file"
}

coraza_bypass() {
    local url="$1"
    local param="${2:-id}"
    if [ -z "$url" ]; then
        echo -e "${RED}用法: ctf coraza-bypass <url> [param]${NC}"
        return 1
    fi
    python "$TOOLKIT_DIR/waf_bypass.py" waf_detect "$url"
    python "$TOOLKIT_DIR/waf_bypass.py" union_values "$url" "$param"
}

game_auto() {
    local url="$1"
    if [ -z "$url" ]; then
        echo -e "${RED}用法: ctf game-auto <url>${NC}"
        return 1
    fi
    python "$TOOLKIT_DIR/game_auto.py" auto "$url"
}

game_kernel() {
    local direction="$1"
    if [ -z "$direction" ]; then
        echo -e "${RED}用法: ctf game-kernel <direction>${NC}"
        return 1
    fi
    python "$TOOLKIT_DIR/game_auto.py" kernel "$direction"
}

pdf_leak() {
    local target="$1"
    if [ -z "$target" ]; then
        echo -e "${RED}用法: ctf pdf-leak <url/file>${NC}"
        return 1
    fi
    python "$TOOLKIT_DIR/waf_bypass.py" pdf_leak "$target"
}

# ═══════════════════════════════════════════════
# 主入口
# ═══════════════════════════════════════════════

case "${1:-help}" in
    web-recon)   bash "$TOOLKIT_DIR/web/recon.sh" "${@:2}" ;;
    sqli)        bash "$TOOLKIT_DIR/web/sqli.sh" "${@:2}" ;;
    upload)      bash "$TOOLKIT_DIR/web/upload.sh" "${@:2}" ;;
    ssti)        bash "$TOOLKIT_DIR/web/ssti.sh" "${@:2}" ;;
    lfi)         bash "$TOOLKIT_DIR/web/lfi.sh" "${@:2}" ;;
    xss)         bash "$TOOLKIT_DIR/web/xss.sh" "${@:2}" ;;
    jwt)         bash "$TOOLKIT_DIR/web/jwt.sh" "${@:2}" ;;
    cmdi)        bash "$TOOLKIT_DIR/web/cmdi.sh" "${@:2}" ;;
    shell)       bash "$TOOLKIT_DIR/web/webshell.sh" "${@:2}" ;;
    exploit)     bash "$TOOLKIT_DIR/web/exploit.sh" "${@:2}" ;;
    crypto)      python "$TOOLKIT_DIR/crypto/crypto_tool.py" "${@:2}" ;;
    rsa)         python "$TOOLKIT_DIR/crypto/rsa_attack.py" "${@:2}" ;;
    hash)        bash "$TOOLKIT_DIR/crypto/hash_crack.sh" "${@:2}" ;;
    encode)      python "$TOOLKIT_DIR/crypto/encode_detect.py" "${@:2}" ;;
    pwn-check)   bash "$TOOLKIT_DIR/pwn/checksec.sh" "${@:2}" ;;
    pwn-exploit) python "$TOOLKIT_DIR/pwn/exploit_template.py" "${@:2}" ;;
    pwn-pattern) python "$TOOLKIT_DIR/pwn/pattern.py" "${2:-100}" ;;
    pwn-rop)     bash "$TOOLKIT_DIR/pwn/rop_search.sh" "${@:2}" ;;
    rev)         bash "$TOOLKIT_DIR/reverse/static.sh" "${@:2}" ;;
    rev-dynamic) bash "$TOOLKIT_DIR/reverse/dynamic.sh" "${@:2}" ;;
    rev-pyc)     python "$TOOLKIT_DIR/reverse/pyc_decompile.py" "${@:2}" ;;
    stego)       bash "$TOOLKIT_DIR/misc/stego.sh" "${@:2}" ;;
    forensics)   bash "$TOOLKIT_DIR/misc/forensics.sh" "${@:2}" ;;
    pcap)        bash "$TOOLKIT_DIR/misc/pcap.sh" "${@:2}" ;;
    file)        bash "$TOOLKIT_DIR/misc/file_analyze.sh" "${@:2}" ;;
    zip)         bash "$TOOLKIT_DIR/misc/zip_crack.sh" "${@:2}" ;;
    scan)        bash "$TOOLKIT_DIR/recon/network_scan.sh" "${@:2}" ;;
    enum)        bash "$TOOLKIT_DIR/recon/service_enum.sh" "${@:2}" ;;
    brute)       bash "$TOOLKIT_DIR/recon/brute.sh" "${@:2}" ;;
    fuzz)        bash "$TOOLKIT_DIR/recon/fuzz.sh" "${@:2}" ;;
    monitor)     bash "$TOOLKIT_DIR/defense/monitor.sh" "${@:2}" ;;
    patch)       bash "$TOOLKIT_DIR/defense/patch.sh" "${@:2}" ;;
    flag-protect) bash "$TOOLKIT_DIR/defense/flag_protect.sh" "${@:2}" ;;
    detect)      bash "$TOOLKIT_DIR/defense/detect.sh" "${@:2}" ;;
    auto)        bash "$TOOLKIT_DIR/scripts/auto_attack.sh" "${@:2}" ;;
    flag-hunt)   bash "$TOOLKIT_DIR/scripts/flag_hunter.sh" "${@:2}" ;;
    batch)       bash "$TOOLKIT_DIR/scripts/batch_exploit.sh" "${@:2}" ;;
    loot)        echo "=== 战利品 ===" && find "$LOOT_DIR" -type f -exec echo "📂 {}" \; -exec cat {} \; 2>/dev/null || echo "暂无战利品" ;;
    gui)         python "$TOOLKIT_DIR/gui/ctf_gui.py" "${@:2}" ;;
    engine)      python "$TOOLKIT_DIR/engine.py" "${@:2}" ;;
    auto-solve)  auto_solve "${@:2}" ;;
    batch-solve) batch_solve "${@:2}" ;;
    coraza-bypass) coraza_bypass "${@:2}" ;;
    game-auto)   game_auto "${@:2}" ;;
    game-kernel) game_kernel "${@:2}" ;;
    pdf-leak)    pdf_leak "${@:2}" ;;
    help|--help|-h) usage ;;
    *) echo -e "${RED}[!] 未知模块: $1${NC}"; usage ;;
esac
