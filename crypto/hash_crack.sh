#!/bin/bash
# CTF 哈希识别与破解
# 用法: bash hash_crack.sh <HASH_OR_FILE>

INPUT="${1:?用法: bash hash_crack.sh <hash 或 hash文件>}"

echo "=========================================="
echo "  哈希识别与破解"
echo "=========================================="

# 如果是文件,读取内容
if [ -f "$INPUT" ]; then
    HASH=$(cat "$INPUT" | head -1 | tr -d '\n\r ')
else
    HASH="$INPUT"
fi

echo "[*] 哈希: ${HASH:0:80}..."
echo "[*] 长度: ${#HASH}"

# 识别哈希类型
echo -e "\n[1/3] 哈希类型识别"
case ${#HASH} in
    32)  echo "  可能: MD5 / NTLM / MD4" ;;
    40)  echo "  可能: SHA1 / MySQL5.x / Tiger160" ;;
    56)  echo "  可能: SHA224 / SHA3-224" ;;
    64)  echo "  可能: SHA256 / SHA3-256 / RIPEMD256" ;;
    96)  echo "  可能: SHA384 / SHA3-384" ;;
    128) echo "  可能: SHA512 / SHA3-512 / Whirlpool" ;;
    *)   echo "  未知长度, 可能是自定义哈希" ;;
esac

# 常见哈希格式
echo "$HASH" | grep -qP '^\$2[aby]?\$' && echo "  类型: bcrypt"
echo "$HASH" | grep -qP '^\$6\$' && echo "  类型: SHA512-crypt"
echo "$HASH" | grep -qP '^\$5\$' && echo "  类型: SHA256-crypt"
echo "$HASH" | grep -qP '^\$1\$' && echo "  类型: MD5-crypt"
echo "$HASH" | grep -qP '^\$argon2' && echo "  类型: Argon2"
echo "$HASH" | grep -qP '^\*[A-F0-9]{40}' && echo "  类型: MySQL"

# 尝试破解
echo -e "\n[2/3] 自动破解"

# 方法1: 常见明文库 (离线彩虹表片段)
echo "[*] 尝试常见密码..."
COMMON_PASSES=("admin" "password" "123456" "root" "flag" "ctf" "test" "guest" "qwerty" "abc123" "letmein" "welcome" "monkey" "dragon" "master" "hello" "shadow" "123456789" "football" "iloveyou")
for pass in "${COMMON_PASSES[@]}"; do
    md5=$(echo -n "$pass" | md5sum | cut -d' ' -f1)
    sha1=$(echo -n "$pass" | sha1sum | cut -d' ' -f1)
    sha256=$(echo -n "$pass" | sha256sum | cut -d' ' -f1)
    if [ "$md5" == "$HASH" ] || [ "$sha1" == "$HASH" ] || [ "$sha256" == "$HASH" ]; then
        echo -e "  \033[31m[!] 破解成功! 明文: $pass\033[0m"
        exit 0
    fi
done

# 方法2: john
echo "[*] 尝试john..."
echo "$HASH" > /tmp/ctf_hash.txt
if [ ${#HASH} -eq 32 ]; then
    john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt /tmp/ctf_hash.txt 2>/dev/null
elif [ ${#HASH} -eq 40 ]; then
    john --format=raw-sha1 --wordlist=/usr/share/wordlists/rockyou.txt /tmp/ctf_hash.txt 2>/dev/null
elif [ ${#HASH} -eq 64 ]; then
    john --format=raw-sha256 --wordlist=/usr/share/wordlists/rockyou.txt /tmp/ctf_hash.txt 2>/dev/null
fi
john --show /tmp/ctf_hash.txt 2>/dev/null | head -5

# 方法3: hashcat
echo "[*] 尝试hashcat..."
if [ ${#HASH} -eq 32 ]; then
    hashcat -m 0 -a 0 "$HASH" /usr/share/wordlists/rockyou.txt --force 2>/dev/null | tail -3
elif [ ${#HASH} -eq 40 ]; then
    hashcat -m 100 -a 0 "$HASH" /usr/share/wordlists/rockyou.txt --force 2>/dev/null | tail -3
elif [ ${#HASH} -eq 64 ]; then
    hashcat -m 1400 -a 0 "$HASH" /usr/share/wordlists/rockyou.txt --force 2>/dev/null | tail -3
fi

# 在线查询 (离线不可用,仅提示)
echo -e "\n[3/3] 在线查询提示 (离线不可用)"
echo "  md5decrypt.net"
echo "  crackstation.net"
echo "  hashes.com"
echo "  cmd5.com"
echo "  somd5.com"

rm -f /tmp/ctf_hash.txt
echo -e "\n=========================================="
echo "哈希破解完成"
echo "=========================================="
