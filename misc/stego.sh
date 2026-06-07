#!/bin/bash
# CTF 隐写分析
# 用法: bash stego.sh <FILE>

FILE="${1:?用法: bash stego.sh <FILE>}"

echo "=========================================="
echo "  隐写分析: $FILE"
echo "=========================================="

# 基本信息
echo -e "\n[1/10] 文件信息"
file "$FILE"
ls -la "$FILE"

# strings
echo -e "\n[2/10] 关键字符串"
strings -n 6 "$FILE" | grep -iE '(flag|ctf|secret|key|password|hidden|base64|xor)' | head -20

# binwalk
echo -e "\n[3/10] binwalk嵌入分析"
binwalk "$FILE" 2>/dev/null | head -20

# exiftool
echo -e "\n[4/10] 元数据 (exiftool)"
exiftool "$FILE" 2>/dev/null | head -30

# 检查trailer
echo -e "\n[5/10] Trailer数据检查"
trailer=$(exiftool "$FILE" 2>/dev/null | grep -i "trailer")
if [ -n "$trailer" ]; then
    echo -e "  \033[31m[!] 发现Trailer数据!\033[0m"
    # 提取trailer
    offset=$(exiftool "$FILE" 2>/dev/null | grep "File Size" | grep -oP '\d+')
    # IEND位置
    iend_offset=$(/usr/bin/python3 -c "
data = open('$FILE','rb').read()
pos = data.find(b'IEND')
if pos >= 0: print(pos+8)
" 2>/dev/null)
    if [ -n "$iend_offset" ] && [ "$iend_offset" -gt 0 ]; then
        echo "  IEND偏移: $iend_offset"
        /usr/bin/python3 -c "
data = open('$FILE','rb').read()
trailer = data[$iend_offset:]
print(f'  Trailer长度: {len(trailer)} bytes')
print(f'  Trailer(hex): {trailer[:100].hex()}')
try: print(f'  Trailer(text): {trailer.decode(\"utf-8\",errors=\"replace\")[:200]}')
except: pass
"
    fi
fi

# PNG特定分析
if file "$FILE" | grep -q "PNG"; then
    echo -e "\n[6/10] PNG分析"
    pngcheck "$FILE" 2>/dev/null

    echo -e "\n[*] zsteg LSB分析:"
    zsteg -a "$FILE" 2>/dev/null | head -20

    echo -e "\n[*] IHDR高度篡改检查:"
    /usr/bin/python3 -c "
data = open('$FILE','rb').read()
width = int.from_bytes(data[16:20], 'big')
height = int.from_bytes(data[20:24], 'big')
print(f'  宽度: {width}, 高度: {height}')
# 尝试修改高度
if height < 2000:
    import struct
    new_data = data[:20] + struct.pack('>I', height*2) + data[24:]
    with open('/tmp/ctf_height_modified.png', 'wb') as f:
        f.write(new_data)
    print(f'  已生成高度x2图片: /tmp/ctf_height_modified.png')
" 2>/dev/null
fi

# JPEG特定分析
if file "$FILE" | grep -q "JPEG"; then
    echo -e "\n[6/10] JPEG隐写"
    echo "[*] steghide提取 (空密码):"
    steghide extract -sf "$FILE" -p "" -f 2>/dev/null
    echo "[*] steghide提取 (常见密码):"
    for pass in "password" "123456" "admin" "ctf" "flag" "secret"; do
        steghide extract -sf "$FILE" -p "$pass" -f 2>/dev/null && echo "  密码: $pass" && break
    done
fi

# stegoveritas
echo -e "\n[7/10] stegoveritas深度分析"
if which stegoveritas >/dev/null 2>&1; then
    stegoveritas "$FILE" -trailing -carve -imageTransform -out /tmp/stego_out 2>/dev/null | tail -10
    echo "  结果在: /tmp/stego_out/"
else
    echo "  stegoveritas未安装"
fi

# XOR暴力
echo -e "\n[8/10] 单字节XOR (检查前100字节)"
/usr/bin/python3 -c "
data = open('$FILE','rb').read()[:100]
for key in range(1, 256):
    xored = bytes(b ^ key for b in data)
    if b'flag' in xored.lower() or b'ctf' in xored.lower():
        print(f'  key=0x{key:02x}: {xored[:50]}')
" 2>/dev/null

# 音频分析提示
echo -e "\n[9/10] 音频隐写提示"
if file "$FILE" | grep -qE "(WAV|MP3|FLAC|OGG)"; then
    echo "  可能的方法:"
    echo "  1. Audacity打开 - 频谱图查看"
    echo "  2. SSTV解码 (Slow Scan TV)"
    echo "  3. DTMF解码"
    echo "  4. 摩尔斯电码"
    echo "  5. LSB音频隐写"
fi

# 通用提示
echo -e "\n[10/10] 其他工具提示"
echo "  Audacity (音频频谱)"
echo "  Stegsolve (图片通道分析)"
echo "  CyberChef (编码/解码)"
echo "  010 Editor (十六进制分析)"

echo -e "\n=========================================="
echo "隐写分析完成"
echo "=========================================="
