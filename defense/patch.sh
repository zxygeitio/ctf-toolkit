#!/bin/bash
# CTF 漏洞修补
# 用法: bash patch.sh <SERVICE>

SERVICE="${1:?用法: bash patch.sh <SERVICE>}"

echo "=========================================="
echo "  漏洞修补: $SERVICE"
echo "=========================================="

case "$SERVICE" in
    ssh)
        echo "[1] SSH加固"
        echo "  禁用密码登录:"
        echo "  sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config"
        echo "  sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config"
        echo "  systemctl restart sshd"
        ;;
    mysql)
        echo "[1] MySQL加固"
        echo "  修改root密码: mysqladmin -u root password 'NEW_PASS'"
        echo "  删除匿名用户: mysql -e \"DELETE FROM mysql.user WHERE User='';\""
        echo "  禁止远程root: mysql -e \"DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost','127.0.0.1','::1');\""
        ;;
    redis)
        echo "[1] Redis加固"
        echo "  设置密码: redis-cli CONFIG SET requirepass 'NEW_PASS'"
        echo "  绑定地址: redis-cli CONFIG SET bind '127.0.0.1'"
        echo "  禁用危险命令: rename-command FLUSHALL '' / rename-command CONFIG ''"
        ;;
    apache)
        echo "[1] Apache加固"
        echo "  隐藏版本: ServerTokens Prod / ServerSignature Off"
        echo "  禁用目录列表: Options -Indexes"
        echo "  禁用TRACE: TraceEnable Off"
        ;;
    nginx)
        echo "[1] Nginx加固"
        echo "  隐藏版本: server_tokens off;"
        echo "  禁用目录列表: autoindex off;"
        ;;
    ftp)
        echo "[1] FTP加固"
        echo "  禁用匿名: anonymous_enable=NO"
        echo "  限制用户: chroot_local_user=YES"
        ;;
    smb)
        echo "[1] SMB加固"
        echo "  禁用匿名: map to guest = Never"
        echo "  删除空密码: null passwords = no"
        ;;
    php)
        echo "[1] PHP加固"
        echo "  禁用危险函数: disable_functions = exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source"
        echo "  禁用远程文件: allow_url_include = Off"
        echo "  禁用错误显示: display_errors = Off"
        ;;
    all)
        for svc in ssh mysql redis apache nginx ftp smb php; do
            bash "$0" "$svc"
            echo "---"
        done
        ;;
    *)
        echo "支持: ssh, mysql, redis, apache, nginx, ftp, smb, php, all"
        ;;
esac

echo -e "\n=========================================="
echo "修补建议完成"
echo "=========================================="
