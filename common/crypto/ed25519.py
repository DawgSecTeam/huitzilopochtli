"""Vendored pure-Python Ed25519. See architecture.md §7.

Source: the original public-domain pure-Python Ed25519 reference
implementation published by the Ed25519 authors (Daniel J. Bernstein, Niels
Duif, Tanja Lange, Peter Schwabe, Bo-Yin Yang) at:

    https://ed25519.cr.yp.to/python/ed25519.py

That file is written for Python 2 (byte strings are `str`, bytes are
manipulated via `ord`/`chr`). This module is a line-for-line-equivalent
transliteration to Python 3 (`bytes`/`bytearray` instead of `str`, no
`ord`/`chr` needed since indexing `bytes` already yields `int` in Python 3).
The field arithmetic, point representation, signing and verification
algorithm are unchanged from the reference — only the byte/string plumbing
was adapted for Python 3. Released into the public domain by the original
authors; this adaptation carries the same public-domain status.

Do not modify the arithmetic below; it is pinned to the reference above.

Public surface (used only by signing.py — nothing else should import this
module directly):

    def keypair() -> tuple[bytes, bytes]: ...        # (private_key, public_key)
    def sign(private_key: bytes, msg: bytes) -> bytes: ...
    def verify(public_key: bytes, msg: bytes, sig: bytes) -> bool: ...
"""

import hashlib
import os

# --- begin transliteration of ed25519.cr.yp.to/python/ed25519.py ---

b = 256
q = 2 ** 255 - 19
l = 2 ** 252 + 27742317777372353535851937790883648493


def H(m):
    return hashlib.sha512(m).digest()


def expmod(base, e, m):
    if e == 0:
        return 1
    t = expmod(base, e // 2, m) ** 2 % m
    if e & 1:
        t = (t * base) % m
    return t


def inv(x):
    return expmod(x, q - 2, q)


d = -121665 * inv(121666) % q
I = expmod(2, (q - 1) // 4, q)


def xrecover(y):
    xx = (y * y - 1) * inv(d * y * y + 1)
    x = expmod(xx, (q + 3) // 8, q)
    if (x * x - xx) % q != 0:
        x = (x * I) % q
    if x % 2 != 0:
        x = q - x
    return x


By = 4 * inv(5)
Bx = xrecover(By)
B = [Bx % q, By % q]


def edwards(P, Q):
    x1 = P[0]
    y1 = P[1]
    x2 = Q[0]
    y2 = Q[1]
    x3 = (x1 * y2 + x2 * y1) * inv(1 + d * x1 * x2 * y1 * y2)
    y3 = (y1 * y2 + x1 * x2) * inv(1 - d * x1 * x2 * y1 * y2)
    return [x3 % q, y3 % q]


def scalarmult(P, e):
    if e == 0:
        return [0, 1]
    Q = scalarmult(P, e // 2)
    Q = edwards(Q, Q)
    if e & 1:
        Q = edwards(Q, P)
    return Q


def encodeint(y):
    bits = [(y >> i) & 1 for i in range(b)]
    return bytes(
        bytearray(
            sum([bits[i * 8 + j] << j for j in range(8)]) for i in range(b // 8)
        )
    )


def encodepoint(P):
    x = P[0]
    y = P[1]
    bits = [(y >> i) & 1 for i in range(b - 1)] + [x & 1]
    return bytes(
        bytearray(
            sum([bits[i * 8 + j] << j for j in range(8)]) for i in range(b // 8)
        )
    )


def bit(h, i):
    return (h[i // 8] >> (i % 8)) & 1


def publickey(sk):
    h = H(sk)
    a = 2 ** (b - 2) + sum(2 ** i * bit(h, i) for i in range(3, b - 2))
    A = scalarmult(B, a)
    return encodepoint(A)


def Hint(m):
    h = H(m)
    return sum(2 ** i * bit(h, i) for i in range(2 * b))


def signature(m, sk, pk):
    h = H(sk)
    a = 2 ** (b - 2) + sum(2 ** i * bit(h, i) for i in range(3, b - 2))
    r = Hint(h[b // 8 : b // 4] + m)
    R = scalarmult(B, r)
    S = (r + Hint(encodepoint(R) + pk + m) * a) % l
    return encodepoint(R) + encodeint(S)


def isoncurve(P):
    x = P[0]
    y = P[1]
    return (-x * x + y * y - 1 - d * x * x * y * y) % q == 0


def decodeint(s):
    return sum(2 ** i * bit(s, i) for i in range(0, b))


def decodepoint(s):
    y = sum(2 ** i * bit(s, i) for i in range(0, b - 1))
    x = xrecover(y)
    if x & 1 != bit(s, b - 1):
        x = q - x
    P = [x, y]
    if not isoncurve(P):
        raise ValueError("decoding point that is not on curve")
    return P


def checkvalid(s, m, pk):
    if len(s) != b // 4:
        raise ValueError("signature length is wrong")
    if len(pk) != b // 8:
        raise ValueError("public-key length is wrong")
    R = decodepoint(s[0 : b // 8])
    A = decodepoint(pk)
    S = decodeint(s[b // 8 : b // 4])
    h = Hint(encodepoint(R) + pk + m)
    (x1, y1) = scalarmult(B, S)
    (x2, y2) = edwards(R, scalarmult(A, h))
    if x1 != x2 or y1 != y2:
        raise ValueError("signature does not pass verification")


# --- end transliteration ---


def keypair() -> tuple:
    """Return (private_key, public_key) as raw bytes.

    private_key is a freshly generated 32-byte seed (`sk` in the reference
    implementation); public_key is the corresponding 32-byte encoded point.
    """
    private_key = os.urandom(b // 8)
    public_key = publickey(private_key)
    return private_key, public_key


def sign(private_key: bytes, msg: bytes) -> bytes:
    """Sign `msg` with `private_key`, returning a 64-byte signature."""
    public_key = publickey(private_key)
    return signature(msg, private_key, public_key)


def verify(public_key: bytes, msg: bytes, sig: bytes) -> bool:
    """Return True iff `sig` is a valid signature over `msg` for `public_key`."""
    try:
        checkvalid(sig, msg, public_key)
    except Exception:
        return False
    return True
