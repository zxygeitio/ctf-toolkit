#!/bin/bash
# CTF Web侦察 v2 — 多工具联动
# 用法: bash recon.sh <URL>
# 功能: 响应头→源码→JS→敏感文件→参数→目录→指纹→WAF→CORS→备份→Git

URL="${1:?用法: bash recon.sh <URL>}"
OUTDIR="/root/ctf-toolkit/loot/web/$(echo $URL | sed 's|https\?://||;s|/|_|g')_$(date +%H%M%S)"
mkdir -p "$OUTDIR"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

log() { echo -e "$1" | tee -a "$OUTDIR/report.txt"; }

log "${CYAN}══════════════════════════════════════════${NC}"
log "${CYAN}  Web侦察: $URL${NC}"
log "${CYAN}══════════════════════════════════════════${NC}"

# 1. 响应头
log "\n${YELLOW}[1/12] 响应头${NC}"
HEADERS=$(curl -skD- "$URL" 2>/dev/null)
echo "$HEADERS" | head -30 | tee "$OUTDIR/headers.txt"
# 提取关键信息
SERVER=$(echo "$HEADERS" | grep -i "^server:" | head -1 | tr -d '\r')
POWERED=$(echo "$HEADERS" | grep -i "x-powered-by:" | head -1 | tr -d '\r')
COOKIE=$(echo "$HEADERS" | grep -i "set-cookie:" | head -1 | tr -d '\r')
log "  Server: $SERVER"
log "  Powered: $POWERED"
log "  Cookie: $COOKIE"

# 2. 源码分析
log "\n${YELLOW}[2/12] 源码分析${NC}"
SRC=$(curl -sk "$URL" 2>/dev/null)
echo "$SRC" > "$OUTDIR/source.html"
# 注释
echo "$SRC" | grep -oP '<!--.*?-->' | head -10 | tee "$OUTDIR/comments.txt"
# 隐藏字段
echo "$SRC" | grep -oiP '<input[^>]*type="hidden"[^>]*>' | head -10 | tee "$OUTDIR/hidden_fields.txt"
# 关键词
echo "$SRC" | grep -ioP '(flag|password|secret|key|token|admin|api|config|debug)[^"<>]*' | head -10

# 3. JS分析
log "\n${YELLOW}[3/12] JS文件分析${NC}"
for js in $(echo "$SRC" | grep -oP '(src|href)="[^"]*\.js[^"]*"' | grep -oP '"[^"]*"' | tr -d '"'); do
    [[ "$js" != http* ]] && js="${URL%/}/$js"
    JSCONTENT=$(curl -sk "$js" 2>/dev/null)
    JSSIZE=${#JSCONTENT}
    [ "$JSSIZE" -lt 100 ] && continue
    log "  JS: $js ($JSSIZE bytes)"
    # API路由
    echo "$JSCONTENT" | grep -oP '["'"'"']/api/[^"'"'"']*["'"'"']' | sort -u | head -10 | tee -a "$OUTDIR/api_routes.txt"
    # 内网IP
    echo "$JSCONTENT" | grep -oP 'https?://[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+[^"'"'"' ]*' | sort -u | tee -a "$OUTDIR/internal_ips.txt"
    # 密钥
    echo "$JSCONTENT" | grep -oiP '(secret|key|token|password|appid|appkey)\s*[:=]\s*["'"'"'][^"'"'"']+' | head -5 | tee -a "$OUTDIR/secrets.txt"
done

# 4. 敏感文件 (扩展版)
log "\n${YELLOW}[4/12] 敏感文件探测${NC}"
SENSITIVE_PATHS=(
    # 备份/源码
    /.git/HEAD /.git/config /.svn/entries /.DS_Store
    /www.zip /backup.zip /web.zip /site.zip /src.zip /code.zip /www.tar.gz /backup.tar.gz
    /www.rar /backup.rar /source.zip /release.zip
    # 配置
    /.env /.env.local /.env.production /.env.bak
    /config.php /config.yml /config.json /config.xml /config.bak
    /web.config /appsettings.json /application.properties
    /database.yml /db.conf /settings.py
    # 框架
    /actuator /actuator/env /actuator/heapdump /actuator/configprops /actuator/mappings
    /swagger-ui.html /swagger-ui/ /api-docs /v2/api-docs /v3/api-docs
    /graphql /graphiql
    /debug /trace /console /status /info /health /metrics
    /phpinfo.php /info.php /test.php /debug.php
    /server-status /server-info /nginx_status
    # 后台
    /admin /admin/ /administrator/ /manage/ /panel/ /dashboard/
    /login /wp-admin /wp-login.php /phpmyadmin /adminer.php
    /phpMyAdmin /pma /myadmin /mysql-admin
    # 常见文件
    /robots.txt /sitemap.xml /sitemap.txt
    /crossdomain.xml /clientaccesspolicy.xml
    /.well-known/security.txt /.well-known/openid-configuration
    /readme.md /README.md /CHANGELOG.md /LICENSE
    /flag /flag.txt /flag.php /flag.html
)
for path in "${SENSITIVE_PATHS[@]}"; do
    code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 3 "$URL$path" 2>/dev/null)
    size=$(curl -sk -o /dev/null -w "%{size_download}" --max-time 3 "$URL$path" 2>/dev/null)
    if [ "$code" == "200" ] && [ "$size" -gt 10 ] 2>/dev/null; then
        log -e "  ${GREEN}[+] $path → $code ($size bytes)${NC}"
    elif [ "$code" == "301" ] || [ "$code" == "302" ]; then
        log "  [→] $path → $code"
    elif [ "$code" == "403" ]; then
        log "  [×] $path → 403"
    fi
done

# 5. Git泄露检测
log "\n${YELLOW}[5/12] Git泄露检测${NC}"
GIT_HEAD=$(curl -sk "$URL/.git/HEAD" 2>/dev/null)
if echo "$GIT_HEAD" | grep -q "ref:"; then
    log -e "  ${RED}[!] .git/HEAD泄露! $GIT_HEAD${NC}"
    log "  下载: git-dumper $URL/.git /tmp/git_dump"
    # 尝试读取config
    curl -sk "$URL/.git/config" 2>/dev/null | tee "$OUTDIR/git_config.txt"
fi

# 6. 参数FUZZ
log "\n${YELLOW}[6/12] 参数发现${NC}"
BASE_LEN=$(curl -sk "$URL" 2>/dev/null | wc -c)
for param in id page file cmd debug admin user name action view source template include path \
    redirect url callback node ip host domain search q query sort order limit offset \
    token key secret session type format lang jsonp debug trace error log level \
    cat dir data file name type cmd exec command shell passwd config env; do
    resp=$(curl -sk "$URL?$param=test" --max-time 3 2>/dev/null)
    resp_len=$(echo "$resp" | wc -c)
    if [ "$resp_len" -ne "$BASE_LEN" ] && [ "$resp_len" -gt 50 ]; then
        diff=$((resp_len - BASE_LEN))
        [ "$diff" -lt 0 ] && diff=$((-diff))
        [ "$diff" -gt 10 ] && log -e "  ${YELLOW}[?] ?$param=test → 响应变化 (${BASE_LEN}→${resp_len})${NC}"
    fi
done

# 7. 目录爆破
log "\n${YELLOW}[7/12] 目录爆破${NC}"
if which gobuster >/dev/null 2>&1; then
    gobuster dir -u "$URL" -w /root/ctf-toolkit/wordlists/common_dirs.txt -t 20 -q 2>/dev/null | tee "$OUTDIR/gobuster.txt"
fi

# 8. 子目录扫描
log "\n${YELLOW}[8/12] 子目录扫描${NC}"
for dir in admin login api upload files images css js static assets backup config data db debug \
    test dev staging v1 v2 internal manage panel dashboard wp-admin phpmyadmin adminer \
    swagger api-docs graphql console actuator shell cmd exec; do
    code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 3 "$URL/$dir/" 2>/dev/null)
    [ "$code" == "200" ] && log -e "  ${GREEN}[+] /$dir/ → 200${NC}"
done

# 9. HTTP方法
log "\n${YELLOW}[9/12] HTTP方法${NC}"
for method in GET POST PUT DELETE PATCH OPTIONS TRACE HEAD; do
    code=$(curl -sk -X "$method" -o /dev/null -w "%{http_code}" --max-time 3 "$URL" 2>/dev/null)
    [ "$code" != "404" ] && [ "$code" != "405" ] && [ "$code" != "000" ] && log "  $method → $code"
done

# 10. CORS
log "\n${YELLOW}[10/12] CORS检测${NC}"
CORS=$(curl -sk -H "Origin: http://evil.com" -D- "$URL" 2>/dev/null | grep -i "access-control")
if [ -n "$CORS" ]; then
    log -e "  ${RED}[!] CORS: $CORS${NC}"
    echo "$CORS" >> "$OUTDIR/cors.txt"
fi

# 11. WAF检测
log "\n${YELLOW}[11/12] WAF检测${NC}"
WAF=$(curl -sk -D- "$URL" 2>/dev/null | grep -iE 'cloudflare|akamai|imperva|incapsula|waf|firewall|x-powered|acw_tc|x-protected|safe3|safedog|yundun')
if [ -n "$WAF" ]; then
    log -e "  ${RED}[!] WAF: $WAF${NC}"
else
    log "  未检测到WAF"
fi
# whatweb
if which whatweb >/dev/null 2>&1; then
    whatweb -a 2 "$URL" 2>/dev/null | tee "$OUTDIR/whatweb.txt"
fi

# 12. 备份文件爆破
log "\n${YELLOW}[12/12] 备份文件爆破${NC}"
for name in www backup web site src code database db config admin; do
    for ext in .zip .tar.gz .tar .rar .7z .bak .old .sql .dump; do
        code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 3 "$URL/$name$ext" 2>/dev/null)
        [ "$code" == "200" ] && log -e "  ${RED}[!] 备份文件: $name$ext → 200${NC}"
    done
done

# 汇总
log "\n${CYAN}══════════════════════════════════════════${NC}"
log "侦察完成! 结果: $OUTDIR"
log "文件数: $(find "$OUTDIR" -type f | wc -l)"
log "${CYAN}══════════════════════════════════════════${NC}"
