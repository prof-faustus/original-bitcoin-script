"""secp256k1 ECDSA as OpenSSL performs it for 0.1.5 (ECDSA_sign / ECDSA_verify).

The digest is the 32 bytes of the uint256 in memory order, read big-endian (BN_bin2bn);
key.h passes (unsigned char*)&hash, sizeof(hash). Public keys: 0x04 || X || Y (65 bytes,
as CKey::GetPubKey returns at 0.1.5) or compressed 0x02/0x03 || X.
"""

P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = (GX, GY)


def on_curve(pt):
    x, y = pt
    return (y * y - x * x * x - 7) % P == 0


def add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0] and (a[1] + b[1]) % P == 0:
        return None
    if a == b:
        lam = 3 * a[0] * a[0] * pow(2 * a[1], -1, P) % P
    else:
        lam = (b[1] - a[1]) * pow(b[0] - a[0], -1, P) % P
    x = (lam * lam - a[0] - b[0]) % P
    return x, (lam * (a[0] - x) - a[1]) % P


def mul(k, pt):
    r = None
    while k:
        if k & 1:
            r = add(r, pt)
        pt = add(pt, pt)
        k >>= 1
    return r


def pubkey_bytes(d):
    x, y = mul(d, G)
    return b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")


def parse_pubkey(b):
    if len(b) == 65 and b[0] == 4:
        pt = (int.from_bytes(b[1:33], "big"), int.from_bytes(b[33:], "big"))
        return pt if on_curve(pt) else None
    if len(b) == 33 and b[0] in (2, 3):
        x = int.from_bytes(b[1:], "big")
        y = pow((x * x * x + 7) % P, (P + 1) // 4, P)
        if (y * y - x * x * x - 7) % P:
            return None
        if (y & 1) != (b[0] & 1):
            y = P - y
        return x, y
    return None


def der_int(v):
    b = v.to_bytes(max(1, (v.bit_length() + 7) // 8), "big")
    if b[0] & 0x80:
        b = b"\x00" + b
    return b"\x02" + bytes([len(b)]) + b


def der_encode(r, s):
    body = der_int(r) + der_int(s)
    return b"\x30" + bytes([len(body)]) + body


def der_decode(sig):
    """Strict DER (r, s); returns None if malformed."""
    try:
        if sig[0] != 0x30 or sig[1] != len(sig) - 2:
            return None
        i = 2
        out = []
        for _ in range(2):
            if sig[i] != 0x02:
                return None
            ln = sig[i + 1]
            v = sig[i + 2:i + 2 + ln]
            if len(v) != ln or ln == 0:
                return None
            out.append(int.from_bytes(v, "big"))
            i += 2 + ln
        return tuple(out) if i == len(sig) else None
    except IndexError:
        return None


def sign(d, z, k):
    R = mul(k, G)
    r = R[0] % N
    s = pow(k, -1, N) * (z + r * d) % N
    return der_encode(r, s)


def verify(pub, z, sig):
    rs = der_decode(sig)
    if rs is None:
        return False
    r, s = rs
    if not (1 <= r < N and 1 <= s < N):
        return False
    w = pow(s, -1, N)
    X = add(mul(z * w % N, G), mul(r * w % N, pub))
    return X is not None and X[0] % N == r
