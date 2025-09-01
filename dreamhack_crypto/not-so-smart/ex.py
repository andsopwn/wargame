from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Util.number import long_to_bytes
import hashlib, binascii

p  = int("91f7989d5e019623425111dc87c6341898974a4286dd6080d23994ac7b39f0b7", 16)
a  = int("3043c0f99b2ff3e508255c08cb49f2df7e51b8faa5f181f95c164260a63fa96a", 16)
b  = int("244bfc977577b2e886524e4c58cb5e233bf6c32d265149640ca1cf11be4ad84d", 16)
gx = int("08f390922552640fd604f5dea148e1cdc11555535457a5474f6ef036c545203d", 16)
gy = int("05ad9e50b76b6af0e5d0fe5f3eae4f78d1b5a6e8f333cab237807d74334a76e7", 16)

Px = 18967137804592015321433852596446099783651635801031927546667662519327897949264
Py = 51878950646609279465160873411757881583198147506397321335972377510896867061403
Qx = 45247794627663199855719600118312767438283240652545104631155981138796271885440
Qy = 41557770757629901825113762897064437585835652311804577964971081316706921316412

iv_hex = "6c638f168c37a477dbc14f8a045548c8"
ct_hex = "85130457085fc26b522c106a19cf2aa3a74297e48e39a1b5b230f04bb03da0a8"

def add_aff(P,Q,mod,p_a):
    if P is None: return Q
    if Q is None: return P
    x1,y1=P; x2,y2=Q
    if x1==x2 and (y1+y2)%mod==0: return None
    if P!=Q:
        lam = ((y2-y1)*pow((x2-x1)%mod, -1, mod))%mod
    else:
        lam = ((3*x1*x1 + p_a)%mod * pow((2*y1)%mod, -1, mod))%mod
    x3 = (lam*lam - x1 - x2) % mod
    y3 = (lam*(x1 - x3) - y1) % mod
    return (x3,y3)

def mul_aff(k,P,mod,p_a):
    R=None; Q=P
    while k>0:
        if k&1: R=add_aff(R,Q,mod,p_a)
        Q=add_aff(Q,Q,mod,p_a); k>>=1
    return R

# Jacobian arithmetic mod N (N = p^2)
def j_double(P, N, p_a):
    X1,Y1,Z1 = P
    if Y1 % N == 0 or Z1 % N == 0: return (0,1,0)
    A = (X1*X1) % N
    B = (Y1*Y1) % N
    C = (B*B) % N
    Z1_sq = (Z1*Z1) % N
    Z1_4  = (Z1_sq*Z1_sq) % N
    S = (4 * X1 * B) % N
    E = (3*A + (p_a % N) * Z1_4) % N
    F = (E*E) % N
    X3 = (F - 2*S) % N
    Y3 = (E * (S - X3) - 8*C) % N
    Z3 = (2 * Y1 * Z1) % N
    return (X3,Y3,Z3)

def j_add(P, Q, N, p_a):
    X1,Y1,Z1 = P; X2,Y2,Z2 = Q
    if Z1 % N == 0: return (X2,Y2,Z2)
    if Z2 % N == 0: return (X1,Y1,Z1)
    Z1_sq = (Z1*Z1) % N; Z2_sq = (Z2*Z2) % N
    U1 = (X1 * Z2_sq) % N; U2 = (X2 * Z1_sq) % N
    Z1_cu = (Z1_sq*Z1) % N; Z2_cu = (Z2_sq*Z2) % N
    S1 = (Y1 * Z2_cu) % N; S2 = (Y2 * Z1_cu) % N
    if (U1 - U2) % N == 0:
        if (S1 - S2) % N == 0: return j_double(P,N,p_a)
        else: return (0,1,0)
    H = (U2 - U1) % N; R = (S2 - S1) % N
    H_sq = (H*H) % N; H_cu = (H_sq*H) % N
    U1_H_sq = (U1 * H_sq) % N
    X3 = (R*R - H_cu - 2*U1_H_sq) % N
    Y3 = (R * (U1_H_sq - X3) - S1 * H_cu) % N
    Z3 = (H * Z1 * Z2) % N
    return (X3,Y3,Z3)

def j_mul(k,P,N,p_a):
    R = (0,1,0); Q = P
    while k>0:
        if k&1: R = j_add(R,Q,N,p_a)
        Q = j_double(Q,N,p_a); k>>=1
    return R

def hensel_lift_mod_p2(x,y,p,a,b,alpha=1):
    fxy = (y*y - (pow(x,3) + a*x + b))
    assert fxy % p == 0
    c0 = (fxy // p) % p
    denom = (2*y) % p
    invden = pow(denom, p-2, p)
    beta = (( (3*(x*x % p) + (a % p)) * (alpha % p) - c0) * invden) % p
    X = (x + p*(alpha % p)) % (p*p)
    Y = (y + p*beta) % (p*p)
    return (X,Y)

def tau_from_Sj(Sj, N, p):
    X,Y,Z = Sj
    psi = (-(X * Z) * pow(Y % N, -1, N)) % N
    return (psi // p) % p

G  = (gx, gy)

N = p*p
G_l = hensel_lift_mod_p2(gx,gy,p,a,b,alpha=1)
P_l = hensel_lift_mod_p2(Px,Py,p,a,b,alpha=1)
Q_l = hensel_lift_mod_p2(Qx,Qy,p,a,b,alpha=1)

Sg = j_mul(p, (G_l[0],G_l[1],1), N, a)
Sp = j_mul(p, (P_l[0],P_l[1],1), N, a)
Sq = j_mul(p, (Q_l[0],Q_l[1],1), N, a)

tauG = tau_from_Sj(Sg, N, p)
tauP = tau_from_Sj(Sp, N, p)
tauQ = tau_from_Sj(Sq, N, p)

inv_tauG = pow(tauG, -1, p)
n = (tauP * inv_tauG) % p
m = (tauQ * inv_tauG) % p

xS = mul_aff(m, (Px%p,Py%p), p, a)[0]
key = hashlib.sha256(long_to_bytes(xS)).digest()[:16]

pt = unpad(AES.new(key, AES.MODE_CBC, binascii.unhexlify(iv_hex))
           .decrypt(binascii.unhexlify(ct_hex)), 16)
print(pt.decode())