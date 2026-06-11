#!/usr/bin/env python3
"""
Test script to verify X-Wing test vectors and produce intermediate values.
Based on draft-connolly-cfrg-xwing-kem-09 Appendix B and C.

Setup instructions:
    # Create virtual environment (one-time setup)
    python3 -m venv .venv

    # Activate the virtual environment
    source .venv/bin/activate

    # Install required packages
    pip install pycryptodome

    # Run the script
    python xwing_test_vectors.py

Required packages:
    - pycryptodome: For SHAKE128/SHAKE256 hash functions
"""

import hashlib
from Crypto.Hash import SHAKE128, SHAKE256
import collections
from math import floor

# =============================================================================
# X25519 Implementation (from spec Appendix B.2)
# =============================================================================

p = 2**255 - 19
a24 = 121665
X25519_BASE = b'\x09' + b'\x00'*31

def x25519_decode(bs):
    return sum(bs[i] << 8*i for i in range(32)) % p

def x25519_decodeScalar(k):
    bs = list(k)
    bs[0] &= 248
    bs[31] &= 127
    bs[31] |= 64
    return x25519_decode(bytes(bs))

def x25519_X(k, u):
    assert len(k) == 32
    assert len(u) == 32

    k = x25519_decodeScalar(k)
    u = x25519_decode(u)
    x1, x2, x3, z2, z3, swap = u, 1, u, 0, 1, 0

    for t in range(255, -1, -1):
        kt = (k >> t) & 1
        swap ^= kt
        if swap == 1:
            x3, x2 = x2, x3
            z3, z2 = z2, z3
        swap = kt

        A = x2 + z2
        AA = (A*A) % p
        B = x2 - z2
        BB = (B*B) % p
        E = AA - BB
        C = x3 + z3
        D = x3 - z3
        DA = (D*A) % p
        CB = (C*B) % p
        x3 = DA + CB
        x3 = (x3 * x3) % p
        z3 = DA - CB
        z3 = (x1 * z3 * z3) % p
        x2 = (AA * BB) % p
        z2 = (E * (AA + (a24 * E) % p)) % p

    if swap == 1:
        x3, x2 = x2, x3
        z2, z3 = z3, z2

    ret = (x2 * pow(z2, p-2, p)) % p
    return bytes((ret >> 8*i) & 255 for i in range(32))

# =============================================================================
# ML-KEM Implementation (from spec Appendix B.3)
# =============================================================================

q = 3329
nBits = 8
zeta = 17
eta2 = 2
n = 2**nBits
inv2 = (q+1)//2

params = collections.namedtuple('params', ('k', 'du', 'dv', 'eta1'))
params768 = params(k=3, du=10, dv=4, eta1=2)

def smod(x):
    r = x % q
    if r > (q-1)//2:
        r -= q
    return r

def Round(x):
    return int(floor(x + 0.5))

def Compress(x, d):
    return Round((2**d / q) * x) % (2**d)

def Decompress(y, d):
    assert 0 <= y and y <= 2**d
    return Round((q / 2**d) * y)

def BitsToWords(bs, w):
    assert len(bs) % w == 0
    return [sum(bs[i+j] * 2**j for j in range(w))
            for i in range(0, len(bs), w)]

def WordsToBits(bs, w):
    return sum([[(b >> i) % 2 for i in range(w)] for b in bs], [])

def Encode(a, w):
    return bytes(BitsToWords(WordsToBits(a, w), 8))

def Decode(a, w):
    return BitsToWords(WordsToBits(a, 8), w)

def brv(x):
    return int(''.join(reversed(bin(x)[2:].zfill(nBits-1))), 2)

class Poly:
    def __init__(self, cs=None):
        self.cs = (0,)*n if cs is None else tuple(cs)
        assert len(self.cs) == n

    def __add__(self, other):
        return Poly((a+b) % q for a,b in zip(self.cs, other.cs))

    def __neg__(self):
        return Poly(q-a for a in self.cs)
    def __sub__(self, other):
        return self + -other

    def __eq__(self, other):
        return self.cs == other.cs

    def NTT(self):
        cs = list(self.cs)
        layer = n // 2
        zi = 0
        while layer >= 2:
            for offset in range(0, n-layer, 2*layer):
                zi += 1
                z = pow(zeta, brv(zi), q)
                for j in range(offset, offset+layer):
                    t = (z * cs[j + layer]) % q
                    cs[j + layer] = (cs[j] - t) % q
                    cs[j] = (cs[j] + t) % q
            layer //= 2
        return Poly(cs)

    def InvNTT(self):
        cs = list(self.cs)
        layer = 2
        zi = n//2
        while layer < n:
            for offset in range(0, n-layer, 2*layer):
                zi -= 1
                z = pow(zeta, brv(zi), q)
                for j in range(offset, offset+layer):
                    t = (cs[j+layer] - cs[j]) % q
                    cs[j] = (inv2*(cs[j] + cs[j+layer])) % q
                    cs[j+layer] = (inv2 * z * t) % q
            layer *= 2
        return Poly(cs)

    def MulNTT(self, other):
        cs = [None]*n
        for i in range(0, n, 2):
            a1 = self.cs[i]
            a2 = self.cs[i+1]
            b1 = other.cs[i]
            b2 = other.cs[i+1]
            z = pow(zeta, 2*brv(i//2)+1, q)
            cs[i] = (a1 * b1 + z * a2 * b2) % q
            cs[i+1] = (a2 * b1 + a1 * b2) % q
        return Poly(cs)

    def Compress(self, d):
        return Poly(Compress(c, d) for c in self.cs)

    def Decompress(self, d):
        return Poly(Decompress(c, d) for c in self.cs)

    def Encode(self, d):
        return Encode(self.cs, d)

def sampleUniform(stream):
    cs = []
    while True:
        b = stream.read(3)
        d1 = b[0] + 256*(b[1] % 16)
        d2 = (b[1] >> 4) + 16*b[2]
        for d in [d1, d2]:
            if d >= q:
                continue
            cs.append(d)
            if len(cs) == n:
                return Poly(cs)

def CBD(a, eta):
    assert len(a) == 64*eta
    b = WordsToBits(a, 8)
    cs = []
    for i in range(n):
        cs.append((sum(b[:eta]) - sum(b[eta:2*eta])) % q)
        b = b[2*eta:]
    return Poly(cs)

def XOF(seed, j, i):
    h = SHAKE128.new()
    h.update(seed + bytes([j, i]))
    return h

def PRF1(seed, nonce):
    assert len(seed) == 32
    h = SHAKE256.new()
    h.update(seed + bytes([nonce]))
    return h

def PRF2(seed, msg):
    assert len(seed) == 32
    h = SHAKE256.new()
    h.update(seed + msg)
    return h.read(32)

def G(seed):
    h = hashlib.sha3_512(seed).digest()
    return h[:32], h[32:]

def H(msg):
    return hashlib.sha3_256(msg).digest()

class Vec:
    def __init__(self, ps):
        self.ps = tuple(ps)

    def NTT(self):
        return Vec(p.NTT() for p in self.ps)

    def InvNTT(self):
        return Vec(p.InvNTT() for p in self.ps)

    def DotNTT(self, other):
        return sum((a.MulNTT(b) for a, b in zip(self.ps, other.ps)), Poly())

    def __add__(self, other):
        return Vec(a+b for a,b in zip(self.ps, other.ps))

    def Compress(self, d):
        return Vec(p.Compress(d) for p in self.ps)

    def Decompress(self, d):
        return Vec(p.Decompress(d) for p in self.ps)

    def Encode(self, d):
        return Encode(sum((p.cs for p in self.ps), ()), d)

    def __eq__(self, other):
        return self.ps == other.ps

def EncodeVec(vec, w):
    return Encode(sum([p.cs for p in vec.ps], ()), w)

def DecodeVec(bs, k, w):
    cs = Decode(bs, w)
    return Vec(Poly(cs[n*i:n*(i+1)]) for i in range(k))

def DecodePoly(bs, w):
    return Poly(Decode(bs, w))

class Matrix:
    def __init__(self, cs):
        self.cs = tuple(tuple(row) for row in cs)

    def MulNTT(self, vec):
        return Vec(Vec(row).DotNTT(vec) for row in self.cs)

    def T(self):
        k = len(self.cs)
        return Matrix((self.cs[j][i] for j in range(k)) for i in range(k))

def sampleMatrix(rho, k):
    return Matrix([[sampleUniform(XOF(rho, j, i))
            for j in range(k)] for i in range(k)])

def sampleNoise(sigma, eta, offset, k):
    return Vec(CBD(PRF1(sigma, i+offset).read(64*eta), eta) for i in range(k))

def constantTimeSelectOnEquality(a, b, ifEq, ifNeq):
    return ifEq if a == b else ifNeq

def InnerKeyGen(seed, params):
    assert len(seed) == 32
    rho, sigma = G(seed + bytes([params.k]))
    A = sampleMatrix(rho, params.k)
    s = sampleNoise(sigma, params.eta1, 0, params.k)
    e = sampleNoise(sigma, params.eta1, params.k, params.k)
    sHat = s.NTT()
    eHat = e.NTT()
    tHat = A.MulNTT(sHat) + eHat
    pk = EncodeVec(tHat, 12) + rho
    sk = EncodeVec(sHat, 12)
    return (pk, sk)

def InnerEnc(pk, msg, seed, params):
    assert len(msg) == 32
    tHat = DecodeVec(pk[:-32], params.k, 12)
    if EncodeVec(tHat, 12) != pk[:-32]:
        raise Exception("ML-KEM public key not normalized")
    rho = pk[-32:]
    A = sampleMatrix(rho, params.k)
    r = sampleNoise(seed, params.eta1, 0, params.k)
    e1 = sampleNoise(seed, eta2, params.k, params.k)
    e2 = sampleNoise(seed, eta2, 2*params.k, 1).ps[0]
    rHat = r.NTT()
    u = A.T().MulNTT(rHat).InvNTT() + e1
    m = Poly(Decode(msg, 1)).Decompress(1)
    v = tHat.DotNTT(rHat).InvNTT() + e2 + m
    c1 = u.Compress(params.du).Encode(params.du)
    c2 = v.Compress(params.dv).Encode(params.dv)
    return c1 + c2

def InnerDec(sk, ct, params):
    split = params.du * params.k * n // 8
    c1, c2 = ct[:split], ct[split:]
    u = DecodeVec(c1, params.k, params.du).Decompress(params.du)
    v = DecodePoly(c2, params.dv).Decompress(params.dv)
    sHat = DecodeVec(sk, params.k, 12)
    return (v - sHat.DotNTT(u.NTT()).InvNTT()).Compress(1).Encode(1)

def mlkem_KeyGen(seed, params):
    assert len(seed) == 64
    z = seed[32:]
    pk, sk2 = InnerKeyGen(seed[:32], params)
    h = H(pk)
    return (pk, sk2 + pk + h + z)

def mlkem_Enc(pk, seed, params):
    assert len(seed) == 32
    K, r = G(seed + H(pk))
    ct = InnerEnc(pk, seed, r, params)
    return (ct, K)

def mlkem_Dec(sk, ct, params):
    sk2 = sk[:12 * params.k * n//8]
    pk = sk[12 * params.k * n//8 : 24 * params.k * n//8 + 32]
    h = sk[24 * params.k * n//8 + 32 : 24 * params.k * n//8 + 64]
    z = sk[24 * params.k * n//8 + 64 : 24 * params.k * n//8 + 96]
    m2 = InnerDec(sk, ct, params)
    K2, r2 = G(m2 + h)
    ct2 = InnerEnc(pk, m2, r2, params)
    return constantTimeSelectOnEquality(ct2, ct, K2, PRF2(z, ct))

# =============================================================================
# X-Wing Implementation (from spec Appendix B.1)
# =============================================================================

XWingLabel = br"""
                \./
                /^\
              """.replace(b'\n', b'').replace(b' ', b'')

assert len(XWingLabel) == 6
assert XWingLabel.hex() == '5c2e2f2f5e5c'

def expandDecapsulationKey(seed):
    expanded = hashlib.shake_256(seed).digest(length=96)
    pkM, skM = mlkem_KeyGen(expanded[0:64], params768)
    skX = expanded[64:96]
    pkX = x25519_X(skX, X25519_BASE)
    return skM, skX, pkM, pkX

def GenerateKeyPairDerand(seed):
    assert len(seed) == 32
    skM, skX, pkM, pkX = expandDecapsulationKey(seed)
    return seed, pkM + pkX

def Combiner(ssM, ssX, ctX, pkX):
    return hashlib.sha3_256(
        ssM +
        ssX +
        ctX +
        pkX +
        XWingLabel
    ).digest()

def EncapsulateDerand(pk, eseed):
    assert len(eseed) == 64
    assert len(pk) == 1216
    pkM = pk[0:1184]
    pkX = pk[1184:1216]
    ekX = eseed[32:64]
    ctX = x25519_X(ekX, X25519_BASE)
    ssX = x25519_X(ekX, pkX)
    ctM, ssM = mlkem_Enc(pkM, eseed[0:32], params768)
    ss = Combiner(ssM, ssX, ctX, pkX)
    return ss, ctM + ctX

def Decapsulate(ct, sk):
    assert len(ct) == 1120
    assert len(sk) == 32
    ctM = ct[0:1088]
    ctX = ct[1088:1120]
    skM, skX, pkM, pkX = expandDecapsulationKey(sk)
    ssM = mlkem_Dec(skM, ctM, params768)
    ssX = x25519_X(skX, ctX)
    return Combiner(ssM, ssX, ctX, pkX)

# =============================================================================
# Test Vectors from Appendix C
# =============================================================================

def test_vector_1():
    print("=" * 80)
    print("TEST VECTOR 1")
    print("=" * 80)
    
    seed = bytes.fromhex("7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26")
    expected_pk = bytes.fromhex(
        "e2236b35a8c24b39b10aa1323a96a919a2ced88400633a7b07131713fc14b2b5b19cfc3d"
        "a5fa1a92c49f25513e0fd30d6b1611c9ab9635d7086727a4b7d21d34244e66969cf15b3b"
        "2a785329f61b096b277ea037383479a6b556de7231fe4b7fa9c9ac24c0699a0018a52534"
        "01bacfa905ca816573e56a2d2e067e9b7287533ba13a937dedb31fa44baced4076992361"
        "0034ae31e619a170245199b3c5c39864859fe1b4c9717a07c30495bdfb98a0a002ccf56c"
        "1286cef5041dede3c44cf16bf562c7448518026b3d8b9940680abd38a1575fd27b58da06"
        "3bfac32c39c30869374c05c1aeb1898b6b303cc68be455346ee0af699636224a148ca2ae"
        "a10463111c709f69b69c70ce8538746698c4c60a9aef0030c7924ceec42a5d36816f545e"
        "ae13293460b3acb37ea0e13d70e4aa78686da398a8397c08eaf96882113fe4f7bad4da40"
        "b0501e1c753efe73053c87014e8661c33099afe8bede414a5b1aa27d8392b3e131e9a70c"
        "1055878240cad0f40d5fe3cdf85236ead97e2a97448363b2808caafd516cd25052c5c362"
        "543c2517e4acd0e60ec07163009b6425fc32277acee71c24bab53ed9f29e74c66a0a3564"
        "955998d76b96a9a8b50d1635a4d7a67eb42df5644d330457293a8042f53cc7a69288f17e"
        "d55827e82b28e82665a86a14fbd96645eca8172c044f83bc0d8c0b4c8626985631ca87af"
        "829068f1358963cb333664ca482763ba3b3bb208577f9ba6ac62c25f76592743b64be519"
        "317714cb4102cb7b2f9a25b2b4f0615de31decd9ca55026d6da0b65111b16fe52feed8a4"
        "87e144462a6dba93728f500b6ffc49e515569ef25fed17aff520507368253525860f58be"
        "3be61c964604a6ac814e6935596402a520a4670b3d284318866593d15a4bb01c35e3e587"
        "ee0c67d2880d6f2407fb7a70712b838deb96c5d7bf2b44bcf6038ccbe33fbcf51a54a584"
        "fe90083c91c7a6d43d4fb15f48c60c2fd66e0a8aad4ad64e5c42bb8877c0ebec2b5e387c"
        "8a988fdc23beb9e16c8757781e0a1499c61e138c21f216c29d076979871caa6942bafc09"
        "0544bee99b54b16cb9a9a364d6246d9f42cce53c66b59c45c8f9ae9299a75d15180c3c95"
        "2151a91b7a10772429dc4cbae6fcc622fa8018c63439f890630b9928db6bb7f9438ae406"
        "5ed34d73d486f3f52f90f0807dc88dfdd8c728e954f1ac35c06c000ce41a0582580e3bb5"
        "7b672972890ac5e7988e7850657116f1b57d0809aaedec0bede1ae148148311c6f7e3173"
        "46e5189fb8cd635b986f8c0bdd27641c584b778b3a911a80be1c9692ab8e1bbb12839573"
        "cce19df183b45835bbb55052f9fc66a1678ef2a36dea78411e6c8d60501b4e60592d1369"
        "8a943b509185db912e2ea10be06171236b327c71716094c964a68b03377f513a05bcd99c"
        "1f346583bb052977a10a12adfc758034e5617da4c1276585e5774e1f3b9978b09d0e9c44"
        "d3bc86151c43aad185712717340223ac381d21150a04294e97bb13bbda21b5a182b6da96"
        "9e19a7fd072737fa8e880a53c2428e3d049b7d2197405296ddb361912a7bcf4827ced611"
        "d0c7a7da104dde4322095339f64a61d5bb108ff0bf4d780cae509fb22c256914193ff734"
        "9042581237d522828824ee3bdfd07fb03f1f942d2ea179fe722f06cc03de5b69859edb06"
        "eff389b27dce59844570216223593d4ba32d9abac8cd049040ef6534"
    )
    
    eseed = bytes.fromhex(
        "3cb1eea988004b93103cfb0aeefd2a686e01fa4a58e8a3639ca8a1e3f9ae57e235b8cc87"
        "3c23dc62b8d260169afa2f75ab916a58d974918835d25e6a435085b2"
    )
    
    expected_ct = bytes.fromhex(
        "b83aa828d4d62b9a83ceffe1d3d3bb1ef31264643c070c5798927e41fb07914a273f8f96"
        "e7826cd5375a283d7da885304c5de0516a0f0654243dc5b97f8bfeb831f68251219aabdd"
        "723bc6512041acbaef8af44265524942b902e68ffd23221cda70b1b55d776a92d1143ea3"
        "a0c475f63ee6890157c7116dae3f62bf72f60acd2bb8cc31ce2ba0de364f52b8ed38c79d"
        "719715963a5dd3842d8e8b43ab704e4759b5327bf027c63c8fa857c4908d5a8a7b88ac7f"
        "2be394d93c3706ddd4e698cc6ce370101f4d0213254238b4a2e8821b6e414a1cf20f6c12"
        "44b699046f5a01caa0a1a55516300b40d2048c77cc73afba79afeea9d2c0118bdf2adb88"
        "70dc328c5516cc45b1a2058141039e2c90a110a9e16b318dfb53bd49a126d6b73f215787"
        "517b8917cc01cabd107d06859854ee8b4f9861c226d3764c87339ab16c3667d2f49384e5"
        "5456dd40414b70a6af841585f4c90c68725d57704ee8ee7ce6e2f9be582dbee985e038ff"
        "c346ebfb4e22158b6c84374a9ab4a44e1f91de5aac5197f89bc5e5442f51f9a5937b102b"
        "a3beaebf6e1c58380a4a5fedce4a4e5026f88f528f59ffd2db41752b3a3d90efabe46389"
        "9b7d40870c530c8841e8712b733668ed033adbfafb2d49d37a44d4064e5863eb0af0a08d"
        "47b3cc888373bc05f7a33b841bc2587c57eb69554e8a3767b7506917b6b70498727f16ea"
        "c1a36ec8d8cfaf751549f2277db277e8a55a9a5106b23a0206b4721fa9b3048552c5bd5b"
        "594d6e247f38c18c591aea7f56249c72ce7b117afcc3a8621582f9cf71787e183dee0936"
        "7976e98409ad9217a497df888042384d7707a6b78f5f7fb8409e3b535175373461b77600"
        "2d799cbad62860be70573ecbe13b246e0da7e93a52168e0fb6a9756b895ef7f0147a0dc8"
        "1bfa644b088a9228160c0f9acf1379a2941cd28c06ebc80e44e17aa2f8177010afd78a97"
        "ce0868d1629ebb294c5151812c583daeb88685220f4da9118112e07041fcc24d5564a99f"
        "dbde28869fe0722387d7a9a4d16e1cc8555917e09944aa5ebaaaec2cf62693afad42a3f5"
        "18fce67d273cc6c9fb5472b380e8573ec7de06a3ba2fd5f931d725b493026cb0acbd3fe6"
        "2d00e4c790d965d7a03a3c0b4222ba8c2a9a16e2ac658f572ae0e746eafc4feba023576f"
        "08942278a041fb82a70a595d5bacbf297ce2029898a71e5c3b0d1c6228b485b1ade509b3"
        "5fbca7eca97b2132e7cb6bc465375146b7dceac969308ac0c2ac89e7863eb8943015b243"
        "14cafb9c7c0e85fe543d56658c213632599efabfc1ec49dd8c88547bb2cc40c9d38cbd30"
        "99b4547840560531d0188cd1e9c23a0ebee0a03d5577d66b1d2bcb4baaf21cc7fef1e038"
        "06ca96299df0dfbc56e1b2b43e4fc20c37f834c4af62127e7dae86c3c25a2f696ac8b589"
        "dec71d595bfbe94b5ed4bc07d800b330796fda89edb77be0294136139354eb8cd3759157"
        "8f9c600dd9be8ec6219fdd507adf3397ed4d68707b8d13b24ce4cd8fb22851bfe9d63240"
        "7f31ed6f7cb1600de56f17576740ce2a32fc5145030145cfb97e63e0e41d354274a079d3"
        "e6fb2e15"
    )
    
    expected_ss = bytes.fromhex("d2df0522128f09dd8e2c92b1e905c793d8f57a54c3da25861f10bf4ca613e384")
    
    # Generate keypair
    sk, pk = GenerateKeyPairDerand(seed)
    
    print(f"seed:       {seed.hex()}")
    print(f"sk:         {sk.hex()}")
    print(f"pk length:  {len(pk)} bytes")
    print(f"pk matches: {pk == expected_pk}")
    
    if pk != expected_pk:
        print(f"MISMATCH!")
        print(f"Expected pk: {expected_pk.hex()[:100]}...")
        print(f"Got pk:      {pk.hex()[:100]}...")
        return False
    
    # Now extract intermediate values for the combiner test
    skM, skX, pkM, pkX = expandDecapsulationKey(seed)
    print(f"\nIntermediate values from key generation:")
    print(f"skX (X25519 secret):  {skX.hex()}")
    print(f"pkX (X25519 public):  {pkX.hex()}")
    print(f"pkM length:           {len(pkM)} bytes")
    print(f"skM length:           {len(skM)} bytes")
    
    # Encapsulate
    ss, ct = EncapsulateDerand(pk, eseed)
    
    print(f"\nEncapsulation:")
    print(f"eseed:      {eseed.hex()}")
    print(f"ct length:  {len(ct)} bytes")
    print(f"ct matches: {ct == expected_ct}")
    print(f"ss:         {ss.hex()}")
    print(f"ss matches: {ss == expected_ss}")
    
    if ct != expected_ct:
        print(f"MISMATCH in ciphertext!")
        return False
    
    if ss != expected_ss:
        print(f"MISMATCH in shared secret!")
        return False
    
    # Extract intermediate values for combiner
    pkM_enc = pk[0:1184]
    pkX_enc = pk[1184:1216]
    ekX = eseed[32:64]
    ctX = x25519_X(ekX, X25519_BASE)  # ephemeral X25519 public key
    ssX = x25519_X(ekX, pkX_enc)  # X25519 shared secret
    ctM, ssM = mlkem_Enc(pkM_enc, eseed[0:32], params768)  # ML-KEM encapsulation
    
    print(f"\nIntermediate values for combiner (encapsulation):")
    print(f"ekX (ephemeral X25519 secret): {ekX.hex()}")
    print(f"ctX (ephemeral X25519 public): {ctX.hex()}")
    print(f"ssX (X25519 shared secret):    {ssX.hex()}")
    print(f"ssM (ML-KEM shared secret):    {ssM.hex()}")
    print(f"ctM length:                    {len(ctM)} bytes")
    print(f"pkX:                           {pkX_enc.hex()}")
    
    # Verify combiner formula
    combiner_input = ssM + ssX + ctX + pkX_enc + XWingLabel
    print(f"\nCombiner input (concatenated):")
    print(f"  ssM:        {ssM.hex()}")
    print(f"  ssX:        {ssX.hex()}")
    print(f"  ctX:        {ctX.hex()}")
    print(f"  pkX:        {pkX_enc.hex()}")
    print(f"  XWingLabel: {XWingLabel.hex()}")
    print(f"  Full input length: {len(combiner_input)} bytes")
    
    ss_computed = Combiner(ssM, ssX, ctX, pkX_enc)
    print(f"\nCombiner output: {ss_computed.hex()}")
    print(f"Expected ss:     {expected_ss.hex()}")
    print(f"Match:           {ss_computed == expected_ss}")
    
    # Decapsulate
    ss_dec = Decapsulate(ct, sk)
    print(f"\nDecapsulation:")
    print(f"ss from decaps: {ss_dec.hex()}")
    print(f"Matches encaps: {ss_dec == ss}")
    
    return ct == expected_ct and ss == expected_ss and ss_dec == ss

def main():
    print("Verifying X-Wing test vectors from draft-connolly-cfrg-xwing-kem-09")
    print()
    
    # Verify the label
    print(f"XWingLabel: {XWingLabel.hex()}")
    print(f"Expected:   5c2e2f2f5e5c")
    assert XWingLabel.hex() == '5c2e2f2f5e5c'
    
    if test_vector_1():
        print("\n" + "=" * 80)
        print("TEST VECTOR 1 PASSED!")
        print("=" * 80)
    else:
        print("\n" + "=" * 80)
        print("TEST VECTOR 1 FAILED!")
        print("=" * 80)

if __name__ == "__main__":
    main()
