hex_list = [(hex(i)[2:].zfill(2).upper()) for i in range(256)]

with open('encfile', 'r') as f:
    enc_s = f.read()
enc_list = [enc_s[i:i+2] for i in range(0, len(enc_s), 2)]

plain_list = list(range(len(enc_list)))

for i in range(len(enc_list)):
    hex_b=enc_list[i]
    index = hex_list.index(hex_b)
    plain_list[i] = hex_list[(index - 128) % len(hex_list)]

plain_list=''.join(plain_list)
byte_data = bytes.fromhex(plain_list)

with open('flag.png', 'wb') as f:
    f.write(byte_data)