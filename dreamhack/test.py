from pwn import *

argv = ['ea']
argv.append(b'\x00')
p = process(executable = 'ea', argv = argv)
p.interactive()