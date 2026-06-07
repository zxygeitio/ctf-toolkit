#!/bin/bash
# CTF 攻击检测
# 用法: bash detect.sh [IFACE]

IFACE="${1:-eth0}"

echo "=========================================="
echo "  攻击检测: $IFACE"
echo "=========================================="

echo -e "\n[1/6] 网络连接监控"
echo "[*] 当前活跃连接:"
ss -tnp 2>/dev/null | grep ESTAB | head -20

echo -e "\n[2/6] 异常端口检测"
echo "[*] 监听端口:"
ss -tlnp 2>/dev/null | head -20

echo -e "\n[3/6] 进程监控"
echo "[*] 可疑进程:"
ps aux | grep -iE "(nc |ncat |socat |bash -i |/dev/tcp|python.*socket|perl.*socket|ruby.*socket)" | grep -v grep
echo "[*] 新进程 (最近5分钟):"
find /proc -maxdepth 1 -newer /proc/1 -type d 2>/dev/null | head -10

echo -e "\n[4/6] 文件监控"
echo "[*] 最近修改的系统文件:"
find /etc /var/www /tmp -type f -mmin -10 2>/dev/null | head -20
echo "[*] 可疑SUID文件:"
find / -perm -4000 -newer /proc/1 -type f 2>/dev/null | head -10
echo "[*] 可疑cron:"
for f in /etc/crontab /var/spool/cron/* /etc/cron.d/*; do
    [ -f "$f" ] && echo "  $f:" && cat "$f" 2>/dev/null | grep -v "^#" | head -5
done

echo -e "\n[5/6] 用户监控"
echo "[*] 当前登录:"
who 2>/dev/null
echo "[*] 最近登录:"
last -10 2>/dev/null
echo "[*] 可疑用户:"
awk -F: '$3==0{print}' /etc/passwd
echo "[*] 空密码用户:"
awk -F: '($2==""){print $1}' /etc/shadow 2>/dev/null

echo -e "\n[6/6] 日志监控"
echo "[*] 最近SSH登录失败:"
grep "Failed password" /var/log/auth.log 2>/dev/null | tail -5
echo "[*] 最近SSH登录成功:"
grep "Accepted" /var/log/auth.log 2>/dev/null | tail -5
echo "[*] Web访问日志 (最近):"
tail -5 /var/log/apache2/access.log 2>/dev/null || tail -5 /var/log/nginx/access.log 2>/dev/null

echo -e "\n=========================================="
echo "攻击检测完成"
echo "=========================================="
