ENC1 = 25889043021335548821260878832004378483521260681242675042883194031946048423533693101234288009087668042920762024679407711250775447692855635834947612028253548739678779
ENC2 = 332075826660041992234163956636404156206918624
E    = 5  

def iroot(n: int, k: int):
    lo, hi = 0, 1
    while hi ** k <= n:
        hi <<= 1
    while lo + 1 < hi:
        mid = (lo + hi) // 2
        if mid ** k <= n:
            lo = mid
        else:
            hi = mid
    return lo, (lo ** k == n)

def long_to_bytes(n: int) -> bytes:
    if n == 0:
        return b"\x00"
    length = (n.bit_length() + 7) // 8
    return n.to_bytes(length, "big")

def vigenere_decrypt_bytewise(ct: bytes, key: bytes) -> bytes:
    out = bytearray(len(ct))
    L = len(key)
    for i, b in enumerate(ct):
        out[i] = (b - key[i % L]) % 256
    return bytes(out)

def main():
    key_int, exact = iroot(ENC2, 5)

    key_bytes = key_int.to_bytes(4, "big")
    print(f"key (int): {key_int}")
    print(f"key (hex): {key_bytes.hex()}")

    ct_bytes = long_to_bytes(ENC1)
    pt_bytes = vigenere_decrypt_bytewise(ct_bytes, key_bytes)

    print(pt_bytes.decode())

if __name__ == "__main__":
    main()
