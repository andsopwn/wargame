from pwn import *
import time

JOKER = "\x5f\x75\x43\x30\x6e\x5f\x00"
token = int(time.time())
key = JOKER + '_' + str(token)

print(key)

p = process('./darim', key)
p.interactive()