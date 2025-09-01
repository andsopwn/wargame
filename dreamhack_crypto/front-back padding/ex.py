#!/usr/bin/env python3
from pwn import *
import os, binascii

context.log_level = 'debug'

PREFIX = b'DreamHack_prefix'   # 16
SUFFIX = b'happy_Amo_suffix'   # 16

def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def recv_menu(r):
    r.recvuntil(b' > ')

def enc_oracle(r, msg: bytes) -> bytes:
    r.sendline(b'1')
    r.recvuntil(b'input your message(hex) > ')
    r.sendline(binascii.hexlify(msg))
    r.recvuntil(b'here is your encrypted message: ')
    ct_hex = r.recvline().strip()
    return bytes.fromhex(ct_hex.decode())

def dec_oracle(r, ct: bytes):
    r.sendline(b'2')
    r.recvuntil(b'input your message(hex) > ')
    r.sendline(binascii.hexlify(ct))
    # 한 번에 프롬프트까지 받아서 판별
    data = r.recvuntil(b' > ', drop=True)
    if b'failed due to error:' in data:
        return False, data.split(b'failed due to error:')[-1].strip()
    if b'here is your decrypted message: ' in data:
        out_hex = data.split(b'here is your decrypted message: ')[-1].strip()
        try:
            return True, bytes.fromhex(out_hex.decode())
        except Exception:
            return False, b'parse error'
    return False, b'unknown response'

def get_flag_ct(r) -> bytes:
    r.sendline(b'3')
    r.recvuntil(b'take my stupid flag: ')
    ct_hex = r.recvline().strip()
    return bytes.fromhex(ct_hex.decode())

def pkcs7_unpad(b: bytes) -> bytes:
    if not b:
        raise ValueError
    p = b[-1]
    if p < 1 or p > 16:
        raise ValueError
    if len(b) < p or any(x != p for x in b[-p:]):
        raise ValueError
    return b[:-p]

def compute_EK_of(r, w: bytes) -> bytes:
    # 길이 32 → FB_pad에서 n1=n2=8, 두 번째 블록 완전 제어
    m1 = b'\x00' * 32
    ct1 = enc_oracle(r, m1)
    C1 = ct1[:16]

    # 두 번째 평문블록을 P2=C1⊕w로 세팅
    P2 = xor_bytes(C1, w)
    msg2 = b'\x00'*8 + P2 + b'\x00'*8
    ct2 = enc_oracle(r, msg2)
    return ct2[16:32]  # E_K(w)

def extract_flag(pt: bytes) -> str:
    # 1) 바로 찾기
    s = pt.find(b'DH{')
    if s != -1:
        e = pt.find(b'}', s)
        if e != -1:
            return pt[s:e+1].decode()

    # 2) prefix 앞부분(0..16)을 접두로 붙여 정렬 시도 후 PKCS#7 제거
    for k in range(0, 17):
        candidate = PREFIX[:k] + pt
        # 블록 경계 맞춰 자르기
        blk = candidate[: (len(candidate)//16)*16]
        if len(blk) < 16:
            continue
        try:
            unp = pkcs7_unpad(blk)
        except ValueError:
            continue
        s = unp.find(b'DH{')
        if s != -1:
            e = unp.find(b'}', s)
            if e != -1:
                return unp[s:e+1].decode()

    # 3) 특수케이스: 맨앞이 b'H{'면 'D' 복원
    if pt.startswith(b'H{'):
        t = b'D' + pt
        blk = t[: (len(t)//16)*16]
        try:
            unp = pkcs7_unpad(blk)
            s = unp.find(b'DH{'); e = unp.find(b'}', s)
            if s != -1 and e != -1:
                return unp[s:e+1].decode()
        except ValueError:
            pass
    raise RuntimeError('flag not found')

def main():
    # 실제 원격
    r = remote('host8.dreamhack.games', 20819)
    recv_menu(r)

    # 플래그 암호문
    C = get_flag_ct(r)

    # 트레일러 구성: Y || X,  X = E_K(Y⊕SUFFIX)
    Y = os.urandom(16)
    X = compute_EK_of(r, xor_bytes(Y, SUFFIX))

    # 복호 질의
    ok, out = dec_oracle(r, C + Y + X)
    if not ok:
        log.failure(b'Decrypt oracle failed: ' + out)
        r.close()
        return

    flag = extract_flag(out)
    print(flag)
    r.close()

if __name__ == '__main__':
    main()
