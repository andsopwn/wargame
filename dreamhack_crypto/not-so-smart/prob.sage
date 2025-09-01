from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import long_to_bytes
from random import randint
import hashlib
import os

FLAG = b"DH{?????????????????????????}"

def encrypt_flag(shared_secret):
    key = hashlib.sha256(long_to_bytes(shared_secret)).digest()[:16]
    iv = os.urandom(16)
    encrypted_flag = AES.new(key,AES.MODE_CBC,iv).encrypt(pad(FLAG,16))
    return (iv,encrypted_flag)

def decrypt_flag(shared_secret,iv,encrypted_flag):
    key = hashlib.sha256(long_to_bytes(int(shared_secret))).digest()[:16]
    return unpad(AES.new(key,AES.MODE_CBC,iv).decrypt(encrypted_flag),16)

# parameter initializing
p = 0x91f7989d5e019623425111dc87c6341898974a4286dd6080d23994ac7b39f0b7
a = 0x3043c0f99b2ff3e508255c08cb49f2df7e51b8faa5f181f95c164260a63fa96a
b = 0x244bfc977577b2e886524e4c58cb5e233bf6c32d265149640ca1cf11be4ad84d
g_x = 0x08f390922552640fd604f5dea148e1cdc11555535457a5474f6ef036c545203d
g_y = 0x05ad9e50b76b6af0e5d0fe5f3eae4f78d1b5a6e8f333cab237807d74334a76e7

F = GF(p)
E = EllipticCurve(F,[a,b])
G = E(g_x,g_y) # Generator

n = randint(1,p)
P = n*G
m = randint(1,p)
Q = m*G
shared_secret = (m*P).xy()[0]

iv, encrypted_flag = encrypt_flag(shared_secret)

print(E)
print(G)
print(P)
print(Q)
print(iv.hex())
print(encrypted_flag.hex())