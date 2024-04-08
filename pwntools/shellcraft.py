from pwn import *

shellcode = ''
shellcode += shellcraft.push(1)
log.info(shellcode)

print(asm(shellcode))