from pwn import *
context.log_level = 'debug'

N  = int("12376eadc9b0bd1f13fa9d904f5a1a75bb7ddaaa77ec5b1e8dec4cb7532b662fcc63a0dfa982e1702be449c9b295bf7a0b7c6ba3dc7aaf3856d681601e723aa3bce3e0cd064793a9c6b00eb01d3e3f0fbceddb208cba2598d9d6a35f3cf8623a1389686807fb5f8f53dd0a7f544c02d030f498f7aa315b7547783399bc88cd3e2859b6786b858a35593537ead5a0cc48401a24cefe6ac6997035f6571af098d5d5b24313437fd89d22cce7fa5907d73c219b609eeea9bcffab0f18504e1d2ed5669752e21dd17b57ea5cf6e6efa76cd965e4589539dc087e152fb4d3f1f90edcdcab22b71b326a3e7e0674f8820a24aa3be15756db2e908d434b80419061bf45", 16)
e  = int("10001", 16)

p_red = int("50b4040146040415a04084000094153182141460200401063040440024200046055600042240040410248014e00410444640240166000001e09141101084025181052000c30004260000406100601226058401613084a0040492001040404620100401344612000215221412811086840005d06001060000008460040025000", 16)
p_msk = int("1250b70401c6444455a8418d2800945d3182dc1c7060a4010630c0c4282c2a0047575e8084aa4207ac592ca034e02e78445640f40366020089e0b9791119940b53818d2842c3082ea70818e0610a601b2e35844169708ca00404931912e04046e01004893e4632c80a1da23c9ab310868d402dd0600307283300cd680c1a25602", 16)

q_red = int("80902304402050a7145440048082208004041205b60014000102340106007002a240b0108404005604000190060092010010004504c2104002100140009020270500022101530484551206642004c1424200000202040042210204c4143704000480101004809114629230312040040000600400420520943204412216404", 16)
q_msk = int("1aa0809033046833d9e7945e420480822090ac0c1a35bf00b48a21223c23060070c2a240b0328c4c235e0408819817209a11531101c50cd21a6012309b40c292302f05000221c353a5845f126e65210ec9c24a0001820284004bf1a206c45637b4500680581894d0d1d46bb2b039a2e84d008a604508420d219c32166b2276c04", 16)

ct = int("97090fc71e4c4c7fe52fb9c5cafde7bae8cf5f911c2755174f3a61515f475c7000d127e23ad99498bd58078abe2890fe40c64067116c66be74ac5422e731905103f4ecc4ae6cf9478580d6fb373744b897caf2b95f01531b626afb46eb88c0f5f419635a27f903ab8ffc55094e015008cbb9520f07755da279226fefa8859bfef694b86ca3fdf88042361d18ecb7ae1ecf98041140b3f167687f45e3da914ee35f9d345782438018310da609578a1047a99a9c54ff846eb2017ac26a0cfb8f5e542c0c7feba904e0ff15a6e2712c2135f9c80b057185cd31a8e9e5371194d063776bdf3537837c705d3761dd6f0ec9419034c294914015bc0e3fbea474fdc15", 16)

def to_le_bytes(x, n):
    return [(x >> (8*i)) & 0xFF for i in range(n)]

def bytes_le_to_int(b):
    v = 0
    for i, x in enumerate(b):
        v += x << (8*i)
    return v

def be_bytes_from_le_list(lst, length):
    return bytes(list(reversed(lst[:length])))

SIGMA = list(range(0x41,0x5B)) + [0x5F] + list(range(0x61,0x7B)) + [0x7B, 0x7D]

BL = 128
N_le  = to_le_bytes(N, 256)
pm_le = to_le_bytes(p_msk, BL)
pr_le = to_le_bytes(p_red, BL)
qm_le = to_le_bytes(q_msk, BL)
qr_le = to_le_bytes(q_red, BL)

Pdom = []
Qdom = []
for i in range(BL):
    Pdom.append([v for v in SIGMA if (v & pm_le[i]) == pr_le[i]])
    Qdom.append([v for v in SIGMA if (v & qm_le[i]) == qr_le[i]])

# LSB 홀수 필터
Pdom[0] = [v for v in Pdom[0] if v & 1]
Qdom[0] = [v for v in Qdom[0] if v & 1]

log.info(f"domain sizes P min/avg/max = {min(map(len,Pdom))}/{sum(map(len,Pdom))/BL:.2f}/{max(map(len,Pdom))}")
log.info(f"domain sizes Q min/avg/max = {min(map(len,Qdom))}/{sum(map(len,Qdom))/BL:.2f}/{max(map(len,Qdom))}")

solution = None

def try_complete(P, Q, carry):
    c = carry
    for i in range(BL, 2*BL):
        kmin = i-(BL-1)
        kmax = BL-1
        total = c
        for k in range(kmin, kmax+1):
            total += P[k] * Q[i-k]
        if (total & 0xFF) != N_le[i]:
            return False
        c = total >> 8
    if c != 0:
        return False
    return True

def dfs(P, Q, i, carry, p0, q0, inv_p0):
    global solution
    if solution is not None:
        return
    if i == BL:
        if try_complete(P, Q, carry):
            solution = (P[:], Q[:])
        return
    # S_i 부분합
    S = carry
    for k in range(1, i):
        S += P[k] * Q[i-k]
    # p_i 분기
    for pi in Pdom[i]:
        rhs = (N_le[i] - S - pi*q0) & 0xFF
        qi = (rhs * inv_p0) & 0xFF
        if qi not in Qdom[i]:
            continue
        total = S + pi*q0 + p0*qi
        next_c = total >> 8
        P[i] = pi
        Q[i] = qi
        dfs(P, Q, i+1, next_c, p0, q0, inv_p0)
        if solution is not None:
            return
        P[i] = None
        Q[i] = None

from math import gcd

for p0 in Pdom[0]:
    inv_p0 = pow(p0, -1, 256)
    for q0 in Qdom[0]:
        if (p0 * q0) & 0xFF != N_le[0]:
            continue
        c1 = (p0 * q0) >> 8
        P = [None]*BL
        Q = [None]*BL
        P[0] = p0
        Q[0] = q0
        dfs(P, Q, 1, c1, p0, q0, inv_p0)
        if solution is not None:
            break
    if solution is not None:
        break


P_sol, Q_sol = solution
p = bytes_le_to_int(P_sol)
q = bytes_le_to_int(Q_sol)
assert p*q == N

flag = be_bytes_from_le_list(P_sol, BL) + be_bytes_from_le_list(Q_sol, BL)
flag_str = flag.decode()
log.success(f"flag = {flag_str}")
print(flag_str)
