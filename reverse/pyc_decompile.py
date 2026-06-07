#!/usr/bin/python3
"""
CTF Python字节码反编译
用法: python3 pyc_decompile.py <FILE.pyc>
"""
import sys, marshal, dis, struct, types

def decompile_pyc(filepath):
    with open(filepath, 'rb') as f:
        magic = f.read(4)
        print(f"[*] Magic: {magic.hex()}")

        # Python 3.8+ has 16 byte header
        if struct.unpack('<H', magic[:2])[0] >= 3400:
            flags = struct.unpack('<I', f.read(4))[0]
            if flags & 0x1:  # PEP 552 hash-based
                f.read(8)
            else:
                f.read(8)  # timestamp + size
        else:
            f.read(8)  # timestamp + size for older

        code = marshal.load(f)

    print(f"[*] 文件名: {code.co_filename}")
    print(f"[*] 行数: {code.co_firstlineno}")
    print(f"[*] 参数数: {code.co_argcount}")

    print("\n[*] 常量池:")
    for i, c in enumerate(code.co_consts):
        if isinstance(c, types.CodeType):
            print(f"  [{i}] <code object {c.co_name}>")
        else:
            print(f"  [{i}] {repr(c)[:100]}")

    print("\n[*] 变量名:", code.co_varnames)
    print("[*] 函数名:", code.co_names)

    print("\n[*] 反汇编:")
    dis.dis(code)

    # 嵌套代码对象
    for c in code.co_consts:
        if isinstance(c, types.CodeType):
            print(f"\n[*] 嵌套函数 {c.co_name}:")
            print(f"  常量: {c.co_consts}")
            print(f"  变量: {c.co_varnames}")
            dis.dis(c)

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("用法: python3 pyc_decompile.py <FILE.pyc>")
    else:
        decompile_pyc(sys.argv[1])
