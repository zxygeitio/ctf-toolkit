#!/bin/bash
# CTF 服务枚举
# 用法: bash service_enum.sh <TARGET>

TARGET="${1:?用法: bash service_enum.sh <TARGET>}"

echo "=========================================="
echo "  服务枚举: $TARGET"
echo "=========================================="

# HTTP枚举
echo -e "\n[1/7] HTTP枚举"
for port in 80 443 8080 8443 8000 8888 9090; do
    for proto in http https; do
        code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 3 "$proto://$TARGET:$port/" 2>/dev/null)
        if [ "$code" != "000" ] && [ "$code" != "404" ]; then
            echo -e "  \033[32m[+] $proto://$TARGET:$port/ → $code\033[0m"
            # 技术栈
            server=$(curl -skI "$proto://$TARGET:$port/" 2>/dev/null | grep -i "^server:" | head -1)
            echo "    $server"
        fi
    done
done

# SSH枚举
echo -e "\n[2/7] SSH枚举"
echo "  Banner:"
timeout 3 bash -c "echo '' | nc -w2 $TARGET 22 2>/dev/null" | head -2
echo "  算法:"
nmap -Pn -p22 --script ssh2-enum-algos "$TARGET" 2>/dev/null | grep -A50 "ssh2-enum-algos" | head -15

# FTP枚举
echo -e "\n[3/7] FTP枚举"
timeout 3 bash -c "echo '' | nc -w2 $TARGET 21 2>/dev/null" | head -2
echo "  匿名登录测试:"
timeout 5 ftp -inv "$TARGET" << 'FTPEOF' 2>/dev/null | head -10
user anonymous anonymous@
ls
quit
FTPEOF

# MySQL枚举
echo -e "\n[4/7] MySQL枚举"
timeout 3 bash -c "echo '' | nc -w2 $TARGET 3306 2>/dev/null" | head -2
echo "  默认凭证测试:"
for user in root mysql admin; do
    for pass in "" "root" "mysql" "admin" "123456" "password"; do
        result=$(timeout 3 mysql -h "$TARGET" -u "$user" -p"$pass" -e "SELECT version();" 2>&1)
        if echo "$result" | grep -q "version"; then
            echo -e "  \033[31m[!] MySQL登录成功: $user:$pass\033[0m"
            echo "$result" | head -3
            break 2
        fi
    done
done

# Redis枚举
echo -e "\n[5/7] Redis枚举"
resp=$(timeout 3 redis-cli -h "$TARGET" INFO 2>/dev/null)
if [ -n "$resp" ]; then
    echo -e "  \033[31m[!] Redis未授权!\033[0m"
    echo "$resp" | head -10
    echo "  数据库:"
    redis-cli -h "$TARGET" DBSIZE 2>/dev/null
    echo "  密钥:"
    redis-cli -h "$TARGET" KEYS "*" 2>/dev/null | head -10
fi

# SMB枚举
echo -e "\n[6/7] SMB枚举"
smbclient -L "//$TARGET" -N 2>/dev/null | head -10
enum4linux -a "$TARGET" 2>/dev/null | grep -iE "(share|user|group)" | head -10

# SNMP枚举
echo -e "\n[7/7] SNMP枚举"
snmpwalk -v2c -c public "$TARGET" 2>/dev/null | head -10
snmpwalk -v2c -c public "$TARGET" 1.3.6.1.2.1.25.4.2.1.2 2>/dev/null | head -10

echo -e "\n=========================================="
echo "服务枚举完成"
echo "=========================================="
