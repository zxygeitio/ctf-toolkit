#!/usr/bin/python3
"""
CTF 多重编码自动检测
用法: python3 encode_detect.py <TEXT>
"""
import sys, base64, binascii, urllib.parse, string

def try_decode(s):
    results = []
    # Base64
    for padding in range(4):
        try:
            d = base64.b64decode(s + '=' * padding).decode()
            if d.isprintable(): results.append(('base64', d))
        except: pass
    # Base32
    try:
        d = base64.b32decode(s.upper()).decode()
        if d.isprintable(): results.append(('base32', d))
    except: pass
    # Hex
    try:
        d = binascii.unhexlify(s).decode()
        if d.isprintable(): results.append(('hex', d))
    except: pass
    # URL decode
    d = urllib.parse.unquote(s)
    if d != s: results.append(('url', d))
    # ROT13
    d = s.translate(str.maketrans(
        string.ascii_uppercase + string.ascii_lowercase,
        string.ascii_uppercase[13:] + string.ascii_uppercase[:13] +
        string.ascii_lowercase[13:] + string.ascii_lowercase[:13]))
    if d != s: results.append(('rot13', d))
    # Binary (01字符串)
    if all(c in '01 ' for c in s) and len(s) > 8:
        try:
            d = ''.join(chr(int(s[i:i+8], 2)) for i in range(0, len(s), 8))
            if d.isprintable(): results.append(('binary', d))
        except: pass
    # Decimal (空格分隔的数字)
    if all(c.isdigit() or c == ' ' for c in s.strip()):
        try:
            d = ''.join(chr(int(x)) for x in s.strip().split())
            if d.isprintable(): results.append(('decimal', d))
        except: pass
    # Octal
    if all(c in '01234567 ' for c in s):
        try:
            d = ''.join(chr(int(s[i:i+3], 8)) for i in range(0, len(s), 3))
            if d.isprintable(): results.append(('octal', d))
        except: pass
    return results

def deep_decode(s, depth=3, visited=None):
    if visited is None: visited = set()
    if depth <= 0 or s in visited: return []
    visited.add(s)
    all_results = []
    for enc_type, decoded in try_decode(s):
        all_results.append((enc_type, decoded))
        # 递归解码
        for sub_type, sub_decoded in deep_decode(decoded, depth-1, visited):
            all_results.append((f"{enc_type}->{sub_type}", sub_decoded))
    return all_results

def main():
    if len(sys.argv) < 2:
        print("用法: python3 encode_detect.py <TEXT>")
        return
    s = ' '.join(sys.argv[1:])
    print(f"输入: {s}")
    print(f"长度: {len(s)}")
    print()
    
    results = deep_decode(s)
    if not results:
        print("未检测到编码")
    else:
        print("解码结果:")
        seen = set()
        for enc_type, decoded in results:
            key = f"{enc_type}:{decoded}"
            if key not in seen:
                seen.add(key)
                flag_hint = ""
                if "flag" in decoded.lower() or "ctf" in decoded.lower():
                    flag_hint = " <-- FLAG!"
                print(f"  [{enc_type}] {decoded}{flag_hint}")

if __name__ == '__main__':
    main()
