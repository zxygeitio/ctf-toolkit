#!/bin/bash
# CTF 目录/参数FUZZ
# 用法: bash fuzz.sh <URL>

URL="${1:?用法: bash fuzz.sh <URL>}"

echo "=========================================="
echo "  目录/参数FUZZ: $URL"
echo "=========================================="

# 内置字典
DIRS="/root/ctf-toolkit/wordlists/common_dirs.txt"
if [ ! -f "$DIRS" ]; then
    cat > "$DIRS" << 'DICT'
admin
login
api
upload
files
images
css
js
static
assets
backup
config
data
db
debug
test
dev
staging
v1
v2
internal
manage
panel
dashboard
wp-admin
phpmyadmin
adminer
swagger
api-docs
graphql
console
actuator
actuator/env
actuator/heapdump
.env
.git/HEAD
.svn/entries
robots.txt
sitemap.xml
crossdomain.xml
web.config
.htaccess
phpinfo.php
info.php
test.php
shell.php
flag
flag.txt
flag.php
backup.zip
www.zip
web.zip
backup.tar.gz
www.tar.gz
index.php.bak
index.html.bak
config.php
config.yml
config.json
database.yml
db.sqlite
DICT
fi

echo -e "\n[1/4] 目录爆破"
while read dir; do
    code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 3 "$URL/$dir" 2>/dev/null)
    size=$(curl -sk -o /dev/null -w "%{size_download}" --max-time 3 "$URL/$dir" 2>/dev/null)
    if [ "$code" != "404" ] && [ "$code" != "000" ] && [ "$size" -gt 0 ] 2>/dev/null; then
        echo -e "  \033[32m[+] /$dir → $code ($size bytes)\033[0m"
    fi
done < "$DIRS"

echo -e "\n[2/4] 参数发现 (Arjun风格)"
PARAMS="id page file cmd debug admin user name action view source template include path redirect url callback node ip host domain search q query sort order limit offset token key secret session file upload type format lang callback jsonp debug trace error log level"
for param in $PARAMS; do
    resp=$(curl -sk "$URL?$param=test" --max-time 3 2>/dev/null)
    base=$(curl -sk "$URL" --max-time 3 2>/dev/null)
    if [ "$(echo "$resp" | md5sum | cut -d' ' -f1)" != "$(echo "$base" | md5sum | cut -d' ' -f1)" ]; then
        resp_len=$(echo "$resp" | wc -c)
        base_len=$(echo "$base" | wc -c)
        diff=$((resp_len - base_len))
        [ "$diff" -lt 0 ] && diff=$((-diff))
        if [ "$diff" -gt 10 ]; then
            echo -e "  \033[33m[?] ?$param=test → 响应变化 (${base_len}→${resp_len})\033[0m"
        fi
    fi
done

echo -e "\n[3/4] HTTP方法测试"
for method in GET POST PUT DELETE PATCH OPTIONS TRACE; do
    code=$(curl -sk -X "$method" -o /dev/null -w "%{http_code}" --max-time 3 "$URL" 2>/dev/null)
    echo "  $method → $code"
done

echo -e "\n[4/4] gobuster/ffuf (如果已安装)"
if which gobuster >/dev/null 2>&1; then
    echo "[*] gobuster扫描:"
    gobuster dir -u "$URL" -w "$DIRS" -t 20 -q 2>/dev/null | head -20
fi
if which ffuf >/dev/null 2>&1; then
    echo "[*] ffuf扫描:"
    ffuf -u "$URL/FUZZ" -w "$DIRS" -mc 200,301,302,403 -fs 0 -t 20 2>/dev/null | head -20
fi

echo -e "\n=========================================="
echo "FUZZ完成"
echo "=========================================="
