#!/usr/bin/python3
"""
CTF 模式字符串生成器 (无需pwntools)
用法: python3 pattern.py <长度>
"""
import sys, string, itertools

def generate_pattern(length):
    """生成Aa0Aa1Aa2...模式"""
    uppers = string.ascii_uppercase
    lowers = string.ascii_lowercase
    digits = string.digits
    pattern = ''
    for u, l, d in itertools.product(uppers, lowers, digits):
        pattern += u + l + d
        if len(pattern) >= length:
            return pattern[:length]
    return pattern[:length]

def find_offset(pattern, value):
    """在模式中查找偏移"""
    # 处理不同格式的地址
    if isinstance(value, int):
        # 尝试大端和小端
        for endian in ['big', 'little']:
            try:
                val_bytes = value.to_bytes(4, endian)
                pos = pattern.encode().find(val_bytes)
                if pos >= 0:
                    return pos, endian
            except: pass
    elif isinstance(value, str):
        # ASCII字符串
        pos = pattern.find(value)
        if pos >= 0:
            return pos, 'ascii'
    return -1, None

def main():
    if len(sys.argv) < 2:
        print("用法:")
        print("  python3 pattern.py <长度>          - 生成模式")
        print("  python3 pattern.py find <值> <长度> - 查找偏移")
        return

    if sys.argv[1] == 'find':
        if len(sys.argv) < 4:
            print("用法: python3 pattern.py find <值> <模式长度>")
            return
        value = sys.argv[2]
        length = int(sys.argv[3])
        pattern = generate_pattern(length)
        # 尝试解析为整数
        try:
            value_int = int(value, 16) if value.startswith('0x') else int(value)
            pos, endian = find_offset(pattern, value_int)
            if pos >= 0:
                print(f"偏移: {pos} (endian: {endian})")
            else:
                print("未找到")
        except:
            pos, _ = find_offset(pattern, value)
            if pos >= 0:
                print(f"偏移: {pos}")
            else:
                print("未找到")
    else:
        length = int(sys.argv[1])
        pattern = generate_pattern(length)
        print(pattern)

if __name__ == '__main__':
    main()
