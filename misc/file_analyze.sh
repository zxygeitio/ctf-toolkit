#!/bin/bash
# CTF 文件类型深度分析
# 用法: bash file_analyze.sh <FILE>

FILE="${1:?用法: bash file_analyze.sh <FILE>}"

echo "=========================================="
echo "  文件深度分析: $FILE"
echo "=========================================="

echo -e "\n[1/5] 文件识别"
file "$FILE"
file -b "$FILE"
# 检查真实类型vs扩展名
REAL_TYPE=$(file -b "$FILE")
echo "扩展名: ${FILE##*.}"
echo "真实类型: $REAL_TYPE"

echo -e "\n[2/5] 文件头 (前32字节)"
xxd "$FILE" | head -2

# 文件头签名判断
HEADER=$(xxd -l 4 -p "$FILE")
case "$HEADER" in
    89504e47) echo "  → PNG图片" ;;
    47494638) echo "  → GIF图片" ;;
    ffd8ffe*) echo "  → JPEG图片" ;;
    25504446) echo "  → PDF文档" ;;
    504b0304) echo "  → ZIP压缩包/JAR/APK/DOCX" ;;
    1f8b0800) echo "  → GZIP压缩" ;;
    425a6839) echo "  → BZIP2压缩" ;;
    377abc??) echo "  → 7z压缩" ;;
    52617221) echo "  → RAR压缩" ;;
    d0cf11e0) echo "  → MS Office (旧格式)" ;;
    7f454c46) echo "  → ELF可执行" ;;
    4d5a????) echo "  → PE可执行 (Windows)" ;;
    cafebabe) echo "  → Java Class / Mach-O" ;;
    64383a3a) echo "  → Torrent文件" ;;
    4944330?) echo "  → MP3音频" ;;
    000001ba) echo "  → MPEG视频" ;;
    000000??) echo "  → 可能是MP4/MOV视频" ;;
esac

echo -e "\n[3/5] binwalk嵌入分析"
binwalk "$FILE" 2>/dev/null | head -20

echo -e "\n[4/5] strings分析"
echo "[*] 可打印字符串 (>=6字符):"
strings -n 6 "$FILE" | head -30
echo "[*] 搜索flag/secret/key:"
strings "$FILE" | grep -iE '(flag|ctf|secret|key|password|hidden|base64|xor|hint)' | head -10

echo -e "\n[5/5] 十六进制搜索"
# 搜索常见文件头嵌入
/usr/bin/python3 -c "
data = open('$FILE','rb').read()
signatures = {
    b'PK\x03\x04': 'ZIP',
    b'\x89PNG': 'PNG',
    b'GIF89a': 'GIF',
    b'\xff\xd8\xff': 'JPEG',
    b'%PDF': 'PDF',
    b'\x1f\x8b': 'GZIP',
    b'Rar!': 'RAR',
    b'\x7fELF': 'ELF',
    b'flag{': 'FLAG',
    b'ctf{': 'CTF_FLAG',
    b'FLAG{': 'FLAG',
}
for sig, name in signatures.items():
    pos = data.find(sig)
    if pos >= 0:
        print(f'  [!] {name} found at offset {pos} (0x{pos:x})')
" 2>/dev/null

echo -e "\n=========================================="
echo "文件分析完成"
echo "=========================================="
