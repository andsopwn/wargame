#!/usr/bin/env python3

hex_list = [(hex(i)[2:].zfill(2).upper()) for i in range(256)]

with open('flag.png', 'rb') as f:
    plain_s = f.read()

plain_list = [hex(i)[2:].zfill(2).upper() for i in plain_s]

dec_list = list(range(len(plain_list)))

for i in range(len(plain_list)):
    hex_b = plain_list[i]
    index = hex_list.index(hex_b)
    dec_list[i] = hex_list[(index + 128) % len(hex_list)]

dec_list = ''.join(dec_list)

with open('encfile', 'w', encoding='utf-8') as f:
    f.write(dec_list)
