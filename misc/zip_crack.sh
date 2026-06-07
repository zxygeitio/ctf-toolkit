#!/bin/bash
# CTF 压缩包破解/修复
# 用法: bash zip_crack.sh <FILE>

FILE="${1:?用法: bash zip_crack.sh <FILE>}"

echo "=========================================="
echo "  压缩包破解/修复: $FILE"
echo "=========================================="

echo -e "\n[1/5] 文件信息"
file "$FILE"
unzip -l "$FILE" 2>/dev/null || 7z l "$FILE" 2>/dev/null || unrar l "$FILE" 2>/dev/null

echo -e "\n[2/5] 伪加密检测"
/usr/bin/python3 -c "
data = open('$FILE','rb').read()
# ZIP伪加密: 通用位标志的bit0设为1
if data[:2] == b'PK':
    # 搜索本地文件头
    pos = 0
    while True:
        pos = data.find(b'PK\x03\x04', pos)
        if pos < 0: break
        flags = int.from_bytes(data[pos+6:pos+8], 'little')
        if flags & 1:
            print(f'  [!] 文件头 0x{pos:x}: 加密标志位=1 (可能是伪加密)')
            # 尝试修复: 清除加密标志
            fixed = bytearray(data)
            fixed[pos+6] = flags & 0xFE
            fixed[pos+7] = 0
            with open('${FILE}.fixed.zip', 'wb') as f:
                f.write(fixed)
            print(f'  [+] 已生成修复文件: ${FILE}.fixed.zip')
        pos += 4
" 2>/dev/null

echo -e "\n[3/5] 已知明文攻击 (bkcrack)"
if which bkcrack >/dev/null 2>&1; then
    echo "  bkcrack已安装"
    echo "  用法: bkcrack -C encrypted.zip -c file.txt -P known.zip -p known.txt"
else
    echo "  bkcrack未安装"
fi

echo -e "\n[4/5] 密码破解"
echo "[*] fcrackzip (常见密码):"
fcrackzip -u -D -p /usr/share/wordlists/rockyou.txt "$FILE" 2>/dev/null | head -5

echo "[*] john破解:"
zip2john "$FILE" 2>/dev/null > /tmp/ctf_zip_hash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt /tmp/ctf_zip_hash.txt 2>/dev/null
john --show /tmp/ctf_zip_hash.txt 2>/dev/null | head -5

echo "[*] hashcat破解:"
# ZIP hashcat mode 17200 (PKZIP) or 13600 (WinZip)
hashcat -m 17200 /tmp/ctf_zip_hash.txt /usr/share/wordlists/rockyou.txt --force 2>/dev/null | tail -3

echo -e "\n[5/5] CRC32暴力 (小文件)"
/usr/bin/python3 -c "
import zipfile, binascii
try:
    zf = zipfile.ZipFile('$FILE')
    for info in zf.infolist():
        if info.file_size < 6 and info.file_size > 0:
            print(f'  [!] {info.filename}: CRC32=0x{info.CRC:08x}, 大小={info.file_size}')
            print(f'      可用CRC32暴力: https://github.com/theonlyDarthworx/CRC32-Collision')
except Exception as e:
    print(f'  错误: {e}')
" 2>/dev/null

rm -f /tmp/ctf_zip_hash.txt
echo -e "\n=========================================="
echo "压缩包分析完成"
echo "=========================================="
