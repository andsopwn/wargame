k = [161,55,37,106,136,128,88,143,139,247,182,192,140,132,222,141,79,38,69,75,184,232,66,72,152,14,202,49,143,58,194,161,241,230,237,118,254,112,85,32,220,192,179,201,216,132,141,42,53]

MASK32 = 0xFFFFFFFF
CONST = (0xDE << 24) | (0xAD << 16) | (0xBE << 8) | 0xEF
def _rotl32(x: int, r: int) -> int:
    r &= 31
    return ((x << r) | (x >> (32 - r))) & MASK32

def _load32_le(mv, i: int) -> int:
    # mv: memoryview(bytearray)
    return (mv[i]
            | (mv[i+1] << 8)
            | (mv[i+2] << 16)
            | (mv[i+3] << 24))

def _store32_le(mv, i: int, x: int) -> None:
    mv[i]   =  x        & 0xFF
    mv[i+1] = (x >> 8)  & 0xFF
    mv[i+2] = (x >> 16) & 0xFF
    mv[i+3] = (x >> 24) & 0xFF

def decode(data: bytes) -> bytes:
    b = bytearray(data)
    mv = memoryview(b)
    i = len(b) - 4
    while i >= 0:
        x = _load32_le(mv, i)
        r = (i + 16) & 31
        y = _rotl32(x ^ CONST, r)
        _store32_le(mv, i, y)
        i -= 1
    return bytes(b)

if __name__ == "__main__":

    ct = bytes(k)
    pt = decode(ct)
    print(pt) 