#!/usr/bin/python3
"""
CTF 综合密码学工具 - 离线版
用法: python3 crypto_tool.py <mode> <input>
模式: base64, base32, hex, url, rot13, caesar, vigenere, xor, morse, bacon, rail_fence, atbash, reverse, decode_all
"""
import sys, base64, binascii, urllib.parse, string, itertools

def base64_decode(s):
    for padding in range(4):
        try: return base64.b64decode(s + '=' * padding).decode()
        except: pass
    return None

def base64_encode(s):
    return base64.b64encode(s.encode()).decode()

def base32_decode(s):
    try: return base64.b32decode(s.upper()).decode()
    except: return None

def hex_decode(s):
    try: return binascii.unhexlify(s.strip()).decode()
    except: return None

def hex_encode(s):
    return binascii.hexlify(s.encode()).decode()

def url_decode(s):
    return urllib.parse.unquote(s)

def rot13(s):
    return s.translate(str.maketrans(
        string.ascii_uppercase + string.ascii_lowercase,
        string.ascii_uppercase[13:] + string.ascii_uppercase[:13] +
        string.ascii_lowercase[13:] + string.ascii_lowercase[:13]))

def caesar_bruteforce(s):
    results = []
    for shift in range(26):
        decoded = ''
        for c in s:
            if c.isalpha():
                base = ord('A') if c.isupper() else ord('a')
                decoded += chr((ord(c) - base + shift) % 26 + base)
            else:
                decoded += c
        results.append((shift, decoded))
    return results

def xor_single_byte(s):
    """单字节XOR暴力破解"""
    try:
        data = binascii.unhexlify(s) if all(c in '0123456789abcdef' for c in s.lower()) and len(s) % 2 == 0 else s.encode()
    except:
        data = s.encode()
    results = []
    for key in range(256):
        decoded = bytes(b ^ key for b in data)
        try:
            text = decoded.decode('utf-8', errors='strict')
            if text.isprintable():
                results.append((key, text))
        except: pass
    return results

def xor_repeating_key(data_hex, key_hex):
    """重复密钥XOR"""
    data = binascii.unhexlify(data_hex)
    key = binascii.unhexlify(key_hex)
    return bytes(d ^ key[i % len(key)] for i, d in enumerate(data))

def morse_decode(s):
    MORSE = {'.-':'A','-...':'B','-.-.':'C','-..':'D','.':'E','..-.':'F','--.':'G',
             '....':'H','..':'I','.---':'J','-.-':'K','.-..':'L','--':'M','-.':'N',
             '---':'O','.--.':'P','--.-':'Q','.-.':'R','...':'S','-':'T','..-':'U',
             '...-':'V','.--':'W','-..-':'X','-.--':'Y','--..':'Z',
             '-----':'0','.----':'1','..---':'2','...--':'3','....-':'4',
             '.....':'5','-....':'6','--...':'7','---..':'8','----.':'9'}
    words = s.strip().split(' / ')
    result = []
    for word in words:
        chars = word.split()
        decoded = ''
        for c in chars:
            decoded += MORSE.get(c, '?')
        result.append(decoded)
    return ' '.join(result)

def bacon_decode(s):
    BACON = {'AAAAA':'A','AAAAB':'B','AAABA':'C','AAABB':'D','AABAA':'E',
             'AABAB':'F','AABBA':'G','AABBB':'H','ABAAA':'I','ABAAB':'J',
             'ABABA':'K','ABABB':'L','ABBAA':'M','ABBAB':'N','ABBBA':'O',
             'ABBBB':'P','BAAAA':'Q','BAAAB':'R','BAABA':'S','BAABB':'T',
             'BABAA':'U','BABAB':'V','BABBA':'W','BABBB':'X','BBAAA':'Y','BBAAB':'Z'}
    s = s.upper().replace('A','A').replace('B','B')
    result = ''
    for i in range(0, len(s)-4, 5):
        chunk = s[i:i+5]
        result += BACON.get(chunk, '?')
    return result

def rail_fence_decode(ciphertext, rails):
    if rails < 2: return ciphertext
    n = len(ciphertext)
    fence = [['\n'] * n for _ in range(rails)]
    idx, direction = 0, 1
    for i in range(n):
        fence[idx][i] = '*'
        if idx == 0: direction = 1
        elif idx == rails - 1: direction = -1
        idx += direction
    pos = 0
    for r in range(rails):
        for c in range(n):
            if fence[r][c] == '*':
                fence[r][c] = ciphertext[pos]
                pos += 1
    result = ''
    idx, direction = 0, 1
    for i in range(n):
        result += fence[idx][i]
        if idx == 0: direction = 1
        elif idx == rails - 1: direction = -1
        idx += direction
    return result

def atbash(s):
    upper = string.ascii_uppercase
    lower = string.ascii_lowercase
    trans = str.maketrans(upper + lower, upper[::-1] + lower[::-1])
    return s.translate(trans)

def detect_and_decode(s):
    """自动检测编码并尝试解码"""
    results = []
    # Base64
    r = base64_decode(s)
    if r and r.isprintable(): results.append(('base64', r))
    # Base32
    r = base32_decode(s)
    if r and r.isprintable(): results.append(('base32', r))
    # Hex
    r = hex_decode(s)
    if r and r.isprintable(): results.append(('hex', r))
    # URL
    r = url_decode(s)
    if r != s: results.append(('url', r))
    # ROT13
    r = rot13(s)
    if r != s: results.append(('rot13', r))
    # Atbash
    r = atbash(s)
    if r != s: results.append(('atbash', r))
    # Morse
    if all(c in '.-/ ' for c in s):
        r = morse_decode(s)
        results.append(('morse', r))
    # Bacon
    if all(c in 'ABab' for c in s.replace(' ','')) and len(s.replace(' ','')) >= 5:
        r = bacon_decode(s)
        results.append(('bacon', r))
    return results

def main():
    if len(sys.argv) < 2:
        print("用法: python3 crypto_tool.py <mode> <input>")
        print("模式: base64/base32/hex/url/rot13/caesar/xor/morse/bacon/rail/atbash/auto")
        return

    mode = sys.argv[1].lower()
    inp = ' '.join(sys.argv[2:]) if len(sys.argv) > 2 else sys.stdin.read().strip()

    if mode == 'base64':
        print(f"解码: {base64_decode(inp) or '失败'}")
        print(f"编码: {base64_encode(inp)}")
    elif mode == 'base32':
        print(f"解码: {base32_decode(inp) or '失败'}")
    elif mode == 'hex':
        print(f"解码: {hex_decode(inp) or '失败'}")
        print(f"编码: {hex_encode(inp)}")
    elif mode == 'url':
        print(f"解码: {url_decode(inp)}")
    elif mode == 'rot13':
        print(f"解码: {rot13(inp)}")
    elif mode == 'caesar':
        print("凯撒暴力枚举:")
        for shift, text in caesar_bruteforce(inp):
            print(f"  shift={shift:2d}: {text}")
    elif mode == 'xor':
        print("单字节XOR暴力:")
        for key, text in xor_single_byte(inp)[:20]:
            print(f"  key=0x{key:02x} ({key:3d}): {text}")
    elif mode == 'morse':
        print(f"解码: {morse_decode(inp)}")
    elif mode == 'bacon':
        print(f"解码: {bacon_decode(inp)}")
    elif mode == 'rail':
        for r in range(2, 11):
            print(f"  rails={r}: {rail_fence_decode(inp, r)}")
    elif mode == 'atbash':
        print(f"解码: {atbash(inp)}")
    elif mode == 'reverse':
        print(f"解码: {inp[::-1]}")
    elif mode == 'auto' or mode == 'decode_all':
        print("自动检测:")
        results = detect_and_decode(inp)
        if not results:
            print("  未识别编码")
        for enc_type, decoded in results:
            print(f"  [{enc_type}] {decoded}")
        # 多层解码
        print("\n多层解码尝试:")
        for enc_type, decoded in results:
            sub_results = detect_and_decode(decoded)
            for sub_type, sub_decoded in sub_results:
                print(f"  [{enc_type} -> {sub_type}] {sub_decoded}")
    else:
        print(f"未知模式: {mode}")

if __name__ == '__main__':
    main()
