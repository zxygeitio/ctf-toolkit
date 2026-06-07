#!/usr/bin/python3
"""
CTF RSA攻击工具集
用法: python3 rsa_attack.py <mode> <args...>
模式: small_e, common_mod, fermat, wiener, hastad, pollard, chinese
"""
import sys, math
from math import gcd, isqrt
from functools import reduce

def modinv(a, m):
    """扩展欧几里得求模逆"""
    if gcd(a, m) != 1: return None
    old_r, r = a, m
    old_s, s = 1, 0
    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
    return old_s % m

def iroot(n, k):
    """整数k次方根"""
    if n < 0: return -iroot(-n, k) if k % 2 else None
    if n == 0: return 0
    x = int(round(n ** (1/k)))
    for delta in [-1, 0, 1]:
        cand = x + delta
        if cand >= 0 and cand**k == n:
            return cand
    return None

def small_e(e, c, n=None):
    """小指数攻击 (e=3, m^e < n)"""
    print(f"[*] 小指数攻击: e={e}")
    m = iroot(c, e)
    if m is not None:
        try:
            text = m.to_bytes((m.bit_length()+7)//8, 'big').decode()
            print(f"[!] 明文m = {m}")
            print(f"[!] 解码: {text}")
        except:
            print(f"[!] 明文m = {m}")
        return m
    print("[-] m^e >= n, 需要其他方法")
    return None

def common_mod(n, e1, c1, e2, c2):
    """共模攻击 (同n不同e)"""
    print(f"[*] 共模攻击")
    g, s, t = extended_gcd(e1, e2)
    if g != 1:
        print(f"[-] gcd(e1,e2)={g} != 1")
        return None
    # s*e1 + t*e2 = 1
    m = (pow(c1, s, n) * pow(c2, t, n)) % n
    try:
        text = m.to_bytes((m.bit_length()+7)//8, 'big').decode()
        print(f"[!] 明文: {text}")
    except:
        print(f"[!] 明文m = {m}")
    return m

def extended_gcd(a, b):
    if a == 0: return b, 0, 1
    g, x, y = extended_gcd(b % a, a)
    return g, y - (b // a) * x, x

def fermat_factor(n):
    """费马分解 (p和q接近时)"""
    print(f"[*] 费马分解 n={n}")
    a = isqrt(n) + 1
    b2 = a * a - n
    for _ in range(1000000):
        if isqrt(b2) ** 2 == b2:
            b = isqrt(b2)
            p, q = a + b, a - b
            if p * q == n:
                print(f"[!] p = {p}")
                print(f"[!] q = {q}")
                return p, q
        a += 1
        b2 = a * a - n
    print("[-] 分解失败")
    return None

def pollard_rho(n):
    """Pollard Rho分解"""
    print(f"[*] Pollard Rho分解")
    if n % 2 == 0: return 2, n//2
    x = 2; y = 2; d = 1
    f = lambda x: (x*x + 1) % n
    while d == 1:
        x = f(x); y = f(f(y))
        d = gcd(abs(x-y), n)
    if d != n:
        print(f"[!] p = {d}, q = {n//d}")
        return d, n//d
    print("[-] 分解失败")
    return None

def chinese_remainder(remainders, moduli):
    """中国剩余定理"""
    N = reduce(lambda a,b: a*b, moduli)
    result = 0
    for r, m in zip(remainders, moduli):
        Ni = N // m
        result += r * Ni * modinv(Ni, m)
    return result % N

def hastad(N_list, e, c_list):
    """Hastad广播攻击 (同e, 不同n)"""
    print(f"[*] Hastad广播攻击: e={e}, {len(N_list)}组")
    if len(N_list) < e:
        print(f"[-] 需要至少{e}组")
        return None
    m_e = chinese_remainder(c_list[:e], N_list[:e])
    m = iroot(m_e, e)
    if m:
        try:
            text = m.to_bytes((m.bit_length()+7)//8, 'big').decode()
            print(f"[!] 明文: {text}")
        except:
            print(f"[!] m = {m}")
        return m
    print("[-] 开方失败")
    return None

def decrypt_rsa(c, d, n):
    """RSA解密"""
    m = pow(c, d, n)
    try:
        return m.to_bytes((m.bit_length()+7)//8, 'big').decode()
    except:
        return str(m)

def main():
    if len(sys.argv) < 2:
        print("用法: python3 rsa_attack.py <mode> args...")
        print("模式: small_e, common_mod, fermat, pollard, hastad, decrypt")
        return

    mode = sys.argv[1]

    if mode == 'small_e':
        e, c = int(sys.argv[2]), int(sys.argv[3])
        n = int(sys.argv[4]) if len(sys.argv) > 4 else None
        small_e(e, c, n)

    elif mode == 'common_mod':
        n = int(sys.argv[2])
        e1, c1 = int(sys.argv[3]), int(sys.argv[4])
        e2, c2 = int(sys.argv[5]), int(sys.argv[6])
        common_mod(n, e1, c1, e2, c2)

    elif mode == 'fermat':
        n = int(sys.argv[2])
        fermat_factor(n)

    elif mode == 'pollard':
        n = int(sys.argv[2])
        pollard_rho(n)

    elif mode == 'hastad':
        e = int(sys.argv[2])
        N_list = [int(x) for x in sys.argv[3].split(',')]
        c_list = [int(x) for x in sys.argv[4].split(',')]
        hastad(N_list, e, c_list)

    elif mode == 'decrypt':
        c, d, n = int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
        print(f"明文: {decrypt_rsa(c, d, n)}")

    else:
        print(f"未知模式: {mode}")

if __name__ == '__main__':
    main()
