from pwn import *

p = process('./chall')

p.recvuntil(b"address: ")
fake = int(p.recv(14), 16)
p.recvuntil(b"address: ")
addb = int(p.recv(14), 16)
p.recvuntil(b"address): ")
real = int(p.recv(14), 16)

print("\nfake flag - {}\naddr of buf - {}\nreal flag - {}\n".format(hex(fake), hex(addb), hex(real)))
p.interactive()