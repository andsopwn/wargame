from pwn import *

p = process('./fsb_overwrite')
#p = remote('host3.dreamhack.games', '11341')
e = ELF('./fsb_overwrite')


'''
p.interactive()