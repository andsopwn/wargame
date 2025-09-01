from secret import flag
import string
from gmpy2 import *
from random import SystemRandom

SIZE = 2048

# read flag and construct RSA p, q
assert(len(flag) == SIZE // 8)
assert(all(c in string.ascii_letters or c in ['{', '}', '_'] for c in flag))

p = int.from_bytes(flag[:SIZE // 2 // 8].encode(), byteorder = "big")
q = int.from_bytes(flag[SIZE // 2 // 8:].encode(), byteorder = "big")
assert(is_prime(p))
assert(is_prime(q))

# generate textbook RSA key
N = p*q
phi = (p - 1) * (q - 1)
e = 0x10001
d = int(gmpy2.invert(e, phi))

pt = int.from_bytes(b"flag{this_is_fake_flag_:P}", byteorder = "big") 
ct = pow(pt, e, N)

# generate random mask and redact p,q
p_mask = 0
q_mask = 0
cryptogen = SystemRandom()
for i in range(SIZE // 2):
    # the SOTA paper says u need 50%
    # not a chance :p
    if cryptogen.random() < 0.35:
        p_mask |= 1
    if cryptogen.random() < 0.35:
        q_mask |= 1
    p_mask <<= 1
    q_mask <<= 1

p_redacted = p & p_mask
q_redacted = q & q_mask

print("N  : 0x%x"%N)
print("e  : 0x%x"%e)

print("p_redacted : 0x%x"%p_redacted)
print("p_mask : 0x%x"%p_mask)
print("q_redacted : 0x%x"%q_redacted)
print("q_mask : 0x%x"%q_mask)

print("ct : 0x%x"%ct)

