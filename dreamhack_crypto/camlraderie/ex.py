#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Camlraderie(crypto) — DreamHack remote solver (fast: pre-invert mix64)
#   python solve_fast.py
#
from pwn import *
from z3 import BitVec, Solver, BitVecVal, LShR, RotateLeft, sat

# ====== remote target (hard-coded) ======
HOST = "host8.dreamhack.games"
PORT = 15811

context.log_level = "debug"   # 항상 디버그
context.terminal = ["tmux", "splitw", "-h"]

MASK = (1 << 64) - 1
M = 0xd1342543de82ef95            # LCG multiplier
C = 0xdaba0b6eb09322e3            # mix64 constant (odd -> invertible mod 2^64)
INV_C = pow(C, -1, 1 << 64)       # modular inverse of C (mod 2^64)

# ---------- helpers ----------
def to_u64(x): return x & MASK
def to_i64(u): return u - (1 << 64) if (u >> 63) & 1 else u

def unxorshift_right(y, shift):
    """Invert x ^= x >> shift  (64-bit)."""
    x = 0
    for i in range(0, 64, shift):
        # recover 'shift' bits at a time
        part_mask = ((1 << shift) - 1) << i
        part = (y ^ (x >> shift)) & part_mask
        x |= part
    return x & MASK

def invmix64(y):
    """Invert mix64: z ^= z>>32; z*=C; z ^= z>>32; z*=C; z ^= z>>32"""
    z = unxorshift_right(y, 32)
    z = (z * INV_C) & MASK
    z = unxorshift_right(z, 32)
    z = (z * INV_C) & MASK
    z = unxorshift_right(z, 32)
    return z & MASK

def mix64_py(z):
    z ^= (z >> 32); z = (z * C) & MASK
    z ^= (z >> 32); z = (z * C) & MASK
    z ^= (z >> 32)
    return z & MASK

def step_py(s, a, x0, x1):
    out = mix64_py((s + x0) & MASK)
    s = (s * M + a) & MASK
    q1 = x0 ^ x1
    q0 = ((x0 << 24) | (x0 >> (64 - 24))) & MASK
    q0 = (q0 ^ q1 ^ ((q1 << 16) & MASK)) & MASK
    q1 = ((q1 << 37) | (q1 >> (64 - 37))) & MASK
    return out, s, q0, q1

def bv(x): return BitVecVal(x, 64)

def step_constraint_bv(s, a, x0, x1, target_sum):
    """
    한 스텝 제약:
      1) s + x0 == target_sum  (mix64 역적용으로 얻은 값)
      2) 그 다음 상태 갱신
    """
    # constrain s + x0 == t
    constraint = ((s + x0) & bv(MASK)) == bv(target_sum)
    # next state
    s2 = ((s * bv(M)) + a) & bv(MASK)
    q1 = x0 ^ x1
    q0 = RotateLeft(x0, 24)
    q0 = (q0 ^ q1 ^ ((q1 << 16) & bv(MASK))) & bv(MASK)
    q1 = RotateLeft(q1, 37)
    return constraint, s2, q0, q1

# ---------- solver pipeline ----------
def recover_state_from_preinverted(T, unroll=10):
    """
    T[i] = invmix64(Y[i]) = s_i + x0_i  (mod 2^64)
    미지수: s0, a, x0_0, x1_0
    언롤 unroll 스텝으로 제약.
    """
    s0 = BitVec("s0", 64)
    a  = BitVec("a", 64)
    x0 = BitVec("x0", 64)
    x1 = BitVec("x1", 64)
    S  = Solver()

    # Known properties
    S.add((a & bv(1)) == bv(1))   # a is odd
    S.add(x0 != bv(0))
    S.add(x1 != bv(0))

    s, xx0, xx1 = s0, x0, x1
    for i in range(unroll):
        cst, s, xx0, xx1 = step_constraint_bv(s, a, xx0, xx1, T[i])
        S.add(cst)

    # (선택) 살짝 더 정보: 마지막 스텝도 합 일치
    # S.add(((s + xx0) & bv(MASK)) == bv(T[unroll]))

    if S.check() != sat:
        raise RuntimeError("unsat — unroll을 늘리거나 입력을 확인하세요.")
    m = S.model()
    return (m[s0].as_long(), m[a].as_long(), m[x0].as_long(), m[x1].as_long())

def read_initial_outputs(io, count=130):
    vals = []
    for _ in range(count):
        line = io.recvline(timeout=5).decode(errors="ignore").strip()
        parts = line.split()
        val = int(parts[-1])   # signed 64-bit decimal
        vals.append(to_u64(val))
    return vals

def main():
    io = remote(HOST, PORT)

    # 1) 130개 관측값 수집
    Y = read_initial_outputs(io, 130)
    log.info("Read 130 outputs")

    # 2) mix64 역변환 적용 (제약 단순화)
    T = [invmix64(y) for y in Y]

    # 3) 상태 복구 (언롤 10으로도 충분)
    s0, a, x0, x1 = recover_state_from_preinverted(T, unroll=10)
    log.success(f"Recovered: s0=0x{s0:016x}, a=0x{a:016x}, x0=0x{x0:016x}, x1=0x{x1:016x}")

    # 4) 전체 130개 검증 후, 다음 50개 예측·송신
    s, xx0, xx1 = s0, x0, x1
    for i, y in enumerate(Y):
        out, s, xx0, xx1 = step_py(s, a, xx0, xx1)
        if out != y:
            raise ValueError(f"Mismatch at {i}: got {out:#x} != {y:#x}")

    answers = []
    for _ in range(50):
        out, s, xx0, xx1 = step_py(s, a, xx0, xx1)
        answers.append(str(to_i64(out)))

    log.info("Sending 50 predictions...")
    for a_line in answers:
        io.sendline(a_line.encode())

    io.interactive()

if __name__ == "__main__":
    main()
