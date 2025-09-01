# ex_sweep_all.py
from pathlib import Path
import re, json, hashlib, base64
from Crypto.Cipher import AES
try:
    from Crypto.Cipher import ChaCha20
    HAS_CHACHA = True
except Exception:
    HAS_CHACHA = False

MODE_IVLEN = {
    "cbc":      (16,),
    "cfb":      (16,),
    "ofb":      (16,),
    "ctr":      (16,),      # (12,)은 pycryptodome CTR 카운터 구현상 번거로워서 기본 16만
    "gcm":      (12,16),    # OpenSSL 쪽은 12 선호, 라이브러리는 12/16 모두 가능
    "chacha20": (12,),      # ChaCha20 nonce는 일반적으로 12B
}
MODE_TAGLEN = {
    "cbc":      (0,),       # CBC는 태그 없음(PKCS#7 패딩만)
    "cfb":      (0,),
    "ofb":      (0,),
    "ctr":      (0,),       # CTR도 태그 없음
    "gcm":      (16,),      # GCM 태그 16B 가정
    "chacha20": (0,),       # 태그 없음(별도 Poly1305가 아니면)
}


def parse_ypub(p: Path):
    d = p.read_bytes()
    assert d.startswith(b"YPUB@"), "bad magic"
    i = 5
    while i < len(d) and d[i] == 0: i += 1
    HEX = b"0123456789abcdefABCDEF"
    hexbuf = bytearray()
    while i < len(d) and len(hexbuf) < 64 and d[i] in HEX:
        hexbuf.append(d[i]); i += 1
    assert len(hexbuf) == 64, f"need 64 hex chars, got {len(hexbuf)}"
    hexhdr = bytes(hexbuf).decode()
    algo = int.from_bytes(d[i:i+4], "little"); i += 4
    body = d[i:]
    return hexhdr, algo, body

def pkcs7_unpad(b: bytes):
    if not b: return b
    p = b[-1]
    if 1 <= p <= 16 and all(x == p for x in b[-p:]): return b[:-p]
    return b

def ratio(b: bytes):
    return 0.0 if not b else sum((32<=c<127) or c in (9,10,13) for c in b)/len(b)

def magic(b: bytes):
    h = b[:8]
    if h.startswith(b'%PDF-'): return 'PDF'
    if h.startswith(b'PK\x03\x04'): return 'ZIP'
    if h.startswith(b'\x89PNG\r\n\x1a\n'): return 'PNG'
    if h.startswith(b'7z\xbc\xaf'): return '7Z'
    if h.startswith(b'{') or h.startswith(b'['): return 'JSON-like'
    return ''

def json_norms(raw: bytes):
    out = []
    out.append(("raw", raw))
    out.append(("raw_nows", re.sub(rb"\s+", b"", raw)))
    try:
        obj = json.loads(raw.decode('utf-8'))
        out.append(("dumps", json.dumps(obj, ensure_ascii=False, separators=(',',':')).encode()))
        out.append(("dumps_sorted", json.dumps(obj, ensure_ascii=False, separators=(',',':'), sort_keys=True).encode()))
        vals=[]
        def walk(x):
            if isinstance(x, dict):
                for k,v in x.items():
                    vals.append(str(k).encode()); walk(v)
            elif isinstance(x, list):
                for v in x: walk(v)
            else:
                vals.append(str(x).encode())
        walk(obj)
        out.append(("vals_concat", b"".join(vals)))
        out.append(("vals_join0", b"\x00".join(vals)))
    except Exception:
        pass
    # dedup by sha
    seen=set(); fin=[]
    for n,b in out:
        h=hashlib.sha256(b).hexdigest()
        if h in seen: continue
        seen.add(h); fin.append((n,b))
    return fin
def try_block_modes(name_prefix, body, key, iv_len, tag_len, iv_pos, mode):
    hits=[]
    N=len(body)
    # IV 배치
    if iv_pos=="head":
        if N < iv_len+tag_len: return hits
        iv = body[:iv_len]; rest = body[iv_len:]
    else:
        if N < iv_len+tag_len: return hits
        iv = body[N-iv_len:]; rest = body[:N-iv_len]
    # 태그 분리
    if tag_len:
        if len(rest) < tag_len: return hits
        ct = rest[:-tag_len]; tag = rest[-tag_len:]
    else:
        ct = rest; tag = b""

    try:
        if mode=="cbc":
            if (len(ct)%16)!=0 or len(iv)!=16: return hits
            cipher = AES.new(key, AES.MODE_CBC, iv)
            pt = pkcs7_unpad(cipher.decrypt(ct))

        elif mode=="cfb":
            if len(iv)!=16: return hits
            cipher = AES.new(key, AES.MODE_CFB, iv)
            pt = cipher.decrypt(ct)

        elif mode=="ofb":
            if len(iv)!=16: return hits
            cipher = AES.new(key, AES.MODE_OFB, iv)
            pt = cipher.decrypt(ct)

        elif mode=="ctr":
            if len(iv)!=16: return hits
            from Crypto.Util import Counter
            ctr = Counter.new(128, initial_value=int.from_bytes(iv, 'big'))
            cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
            pt = cipher.decrypt(ct)

        elif mode=="gcm":
            if tag_len!=16 or len(iv) not in (12,16): return hits
            cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
            pt = cipher.decrypt_and_verify(ct, tag)

        elif mode=="chacha20" and HAS_CHACHA:
            if len(iv)!=12: return hits
            cipher = ChaCha20.new(key=key, nonce=iv)
            pt = cipher.decrypt(ct)

        else:
            return hits

    except Exception:
        return hits

    sc=ratio(pt); sig=magic(pt)
    if sig or sc>=0.70:
        out=f"{name_prefix}.{mode}_iv{iv_pos}{iv_len}_tag{tag_len}.bin"
        Path(out).write_bytes(pt)
        hits.append((sc,sig,mode,iv_pos,iv_len,tag_len,out))
    return hits

if __name__=="__main__":
    import sys, hashlib, base64
    ypub = Path(sys.argv[1])
    hacked = Path("hacked.json")
    hexhdr, algo, body = parse_ypub(ypub)
    print("algo=",algo,"body_len=",len(body),"hexhdr[-8:]=",hexhdr[-8:])

    # --- 키 후보 구성 (이전과 동일) ---
    keyset=[]
    hh = bytes.fromhex(hexhdr)
    keyset += [("hdr_hex", hh),
               ("sha256(hdr_hex)", hashlib.sha256(hh).digest()),
               ("ascii_hdr", hexhdr.encode()),
               ("sha256(ascii_hdr)", hashlib.sha256(hexhdr.encode()).digest())]
    if hacked.exists():
        raw = hacked.read_bytes()
        for nm,buf in json_norms(raw):
            keyset.append((f"sha256[{nm}]", hashlib.sha256(buf).digest()))
    # resp.json에서 추가 키가 나중에 생기면 여기에 넣으세요
    EXTRA_KEYS = []  # 예: ["3f..(64-hex)..", "b64:AAECAwQF..."]
    for v in EXTRA_KEYS:
        if v.startswith("b64:"):
            keyset.append(("resp_b64", base64.b64decode(v[4:])))
        else:
            try: keyset.append(("resp_hex", bytes.fromhex(v)))
            except Exception: pass

    # dedup & 길이검사
    seen=set(); uniq=[]
    for n,k in keyset:
        if len(k) not in (16,24,32): continue
        h=hashlib.sha256(k).hexdigest()
        if h in seen: continue
        seen.add(h); uniq.append((n,k))
    print(f"keys: {len(uniq)} candidates")

    # --- 스윕 ---
    MODES = ("cbc","cfb","ofb","ctr","gcm","chacha20")
    hits=[]
    for n,k in uniq:
        name_prefix=f"{ypub.name}.dec.{n}"
        for mode in MODES:
            for iv_len in MODE_IVLEN[mode]:
                for iv_pos in ("head","tail"):
                    for tag_len in MODE_TAGLEN[mode]:
                        for h in try_block_modes(name_prefix, body, k, iv_len, tag_len, iv_pos, mode):
                            hits.append((h[0],h[1],h[2],h[3],h[4],h[5],n,h[6]))
    hits.sort(key=lambda x:(-x[0], x[2], x[3], x[4], x[5]))
    if not hits:
        print("no hits. 도커로 받은 서버 키를 EXTRA_KEYS에 넣고 재시도하세요.")
    else:
        for sc,sig,mode,ivp,ivl,tag,n,out in hits[:20]:
            print(f"[HIT] score={sc:.3f} sig={sig or '-':<8} mode={mode:<7} iv={ivp}/{ivl} tag={tag:02d} key={n} -> {out}")