#!/bin/bash
# CTF Flag文件保护
# 用法: bash flag_protect.sh

echo "=========================================="
echo "  Flag文件保护"
echo "=========================================="

echo -e "\n[1/5] 常见Flag位置"
for path in /flag /flag.txt /flag.php /root/flag /home/*/flag /home/*/flag.txt /tmp/flag /var/www/flag /opt/flag; do
    if [ -f "$path" ]; then
        echo -e "  \033[31m[!] 发现Flag: $path\033[0m"
        ls -la "$path"
    fi
done

echo -e "\n[2/5] Flag文件权限加固"
for path in /flag /flag.txt /root/flag; do
    if [ -f "$path" ]; then
        chmod 600 "$path"
        echo "  已加固: $path (600)"
    fi
done

echo -e "\n[3/5] 监控Flag文件"
echo "  inotify监控 (检测谁在读取flag):"
echo "  inotifywait -m /flag.txt -e access,open,modify"
echo "  auditd监控:"
echo "  auditctl -w /flag.txt -p rwa -k flag_access"

echo -e "\n[4/5] 防止常见攻击"
echo "  1. 禁止目录遍历: chmod 750 / /root /home"
echo "  2. 禁止LFI: 检查PHP的open_basedir"
echo "  3. 禁止命令注入: 过滤输入中的;|&$\`"
echo "  4. 禁止SUID提权: mount -o remount,nosuid /"
echo "  5. 限制/proc访问: mount -o remount,hidepid=2 /proc"

echo -e "\n[5/5] 快速加固脚本"
cat << 'PATCH'
#!/bin/bash
# 快速加固 - 复制到目标执行
chmod 600 /flag /flag.txt /root/flag 2>/dev/null
chmod 750 / /root /home 2>/dev/null
echo "disable_functions = exec,passthru,shell_exec,system" >> /etc/php/*/cli/php.ini 2>/dev/null
# 禁用SSH密码登录
sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config 2>/dev/null
# 禁止Redis远程访问
redis-cli CONFIG SET requirepass "$(openssl rand -hex 16)" 2>/dev/null
# 修改MySQL默认密码
mysqladmin -u root password "$(openssl rand -hex 16)" 2>/dev/null
echo "[+] 加固完成"
PATCH

echo -e "\n=========================================="
echo "Flag保护完成"
echo "=========================================="
