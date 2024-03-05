from pwn import *

#p = process('./chall')
p = remote('host3.dreamhack.games', '11551')

p.recvuntil(b"number: ")
rn = int(p.recv(10), 16)

payload = 0x7d1c4b0a ^ rn
#print("\n\noffset {}\n\ninput {}\n\n".format(hex(rn), hex(payload)))

p.sendlineafter(b"Input? ", str(payload).encode())

p.interactive()

# 문제 풀면서 형식 실수하지 말 것