"""One fixed locking script that carries a Turing machine across transactions, every step
enforced by validation, in the 0.1.5 language.

Locking script for state (U, V, h, q) — tape left of the head, tape right of the head, head
symbol, machine state, all byte strings:

    PUSHDATA4(U) PUSHDATA4(V) PUSHDATA4(h) PUSHDATA4(q) CODE

CODE, with the unlocking script supplying the free transaction fields
<version> <outpoint> <sequence> <value> <locktime> <CODE>:

    if q = ACC:  drop the state, require the beneficiary's signature        (payout)
    else:
      re-encode the current state                         -> enc_old   (to alt stack)
      k step blocks on (U, V, h, q)                        -> (U', V', h', q')
      re-encode                                            -> enc_new
      spk_new  = enc_new || CODE
      sc_old   = enc_old || CODE
      preimage = version || 01 || outpoint || cs(sc_old) || sc_old || sequence || 01
                 || value || cs(spk_new) || spk_new || locktime || 01000000
      z  = HASH256(preimage) read big-endian;  s = (z + Gx) mod n
      OP_CHECKSIGVERIFY with signature DER(Gx, s)||01 and public key G  (key 1, nonce 1)
      push TRUE

The signature verifies only if the preimage built in the script equals the preimage of the
actual spending transaction (0.1.5 SignatureHash, SIGHASH_ALL). Equality forces: one input;
the supplied CODE equals the CODE actually being executed; exactly one output whose script is
the successor state followed by the same CODE.
"""

import struct

import script015_v01 as V1
from script015_v01 import (Script, bn_getvch, OP_DUP, OP_EQUAL, OP_IF, OP_ELSE, OP_ENDIF,
                           OP_DROP, OP_2DROP, OP_2OVER, OP_SWAP, OP_CAT, OP_SIZE,
                           OP_0NOTEQUAL, OP_1, OP_LEFT, OP_RIGHT, OP_1SUB, OP_ROT,
                           OP_TOALTSTACK, OP_FROMALTSTACK, OP_OVER, OP_LESSTHAN, OP_SUBSTR,
                           OP_NIP, OP_HASH256, OP_ADD, OP_MOD, OP_CHECKSIG,
                           OP_CHECKSIGVERIFY)
import secp256k1_v01 as EC

R, L, S = "R", "L", "S"


def pd4(x):
    x = bytes(x)
    return b"\x4e" + struct.pack("<I", len(x)) + x


class ByteTM:
    def __init__(self, name, states, symbols, blank, delta, q0, acc, halting):
        self.name, self.states, self.symbols, self.blank = name, states, symbols, blank
        self.delta, self.q0, self.acc, self.halting = delta, q0, acc, halting

    def step(self, st):
        U, V, h, q = st
        if q in self.halting:
            return st
        q2, b, d = self.delta[(q, h)]
        if d == R:
            U = U + b
            h, V = (V[:1], V[1:]) if V else (self.blank, b"")
        elif d == L:
            V = b + V
            h, U = (U[-1:], U[:-1]) if U else (self.blank, b"")
        else:
            h = b
        return U, V, h, q2


# ------------------------------------------------------------------ script fragments
def H(s):
    """[x] -> [PUSHDATA4 header || x]."""
    s.op(OP_SIZE).data(b"\x00\x00\x00\x00").op(OP_CAT).num(4).op(OP_LEFT)
    s.data(b"\x4e").op(OP_SWAP).op(OP_CAT)
    s.op(OP_SWAP).op(OP_CAT)


def ENC4(s):
    """[U V h q] -> [pd4(U) pd4(V) pd4(h) pd4(q)] concatenated."""
    H(s)
    for _ in range(3):
        s.op(OP_SWAP)
        H(s)
        s.op(OP_SWAP).op(OP_CAT)


def CSX(s):
    """[x] -> [compact_size(len x) || x]."""
    s.op(OP_SIZE)
    s.op(OP_DUP).num(253).op(OP_LESSTHAN).op(OP_IF)
    s.data(b"\x00").op(OP_CAT).num(1).op(OP_LEFT)
    s.op(OP_ELSE)
    s.op(OP_DUP).num(65536).op(OP_LESSTHAN).op(OP_IF)
    s.data(b"\x00\x00").op(OP_CAT).num(2).op(OP_LEFT).data(b"\xfd").op(OP_SWAP).op(OP_CAT)
    s.op(OP_ELSE)
    s.data(b"\x00\x00\x00\x00").op(OP_CAT).num(4).op(OP_LEFT).data(b"\xfe").op(OP_SWAP) \
        .op(OP_CAT)
    s.op(OP_ENDIF).op(OP_ENDIF)
    s.op(OP_SWAP).op(OP_CAT)


def REV(s, maxlen):
    """[x] -> [reverse(x)] for len(x) <= maxlen (OP_SUBSTR clamps past the end)."""
    s.data(b"")
    for i in range(maxlen):
        s.op(OP_OVER).num(i).op(OP_1).op(OP_SUBSTR).op(OP_SWAP).op(OP_CAT)
    s.op(OP_NIP)


PUB_G = EC.pubkey_bytes(1)


def SIGN(s):
    """[preimage] -> [] ; fails unless preimage is the spending transaction's."""
    s.op(OP_HASH256)
    REV(s, 32)
    s.data(b"\x00").op(OP_CAT)                       # z, positive
    s.data(bn_getvch(EC.GX)).op(OP_ADD)
    s.data(bn_getvch(EC.N)).op(OP_MOD)               # s = z + r*d with d = 1, k = 1
    REV(s, 33)                                       # DER integer content of s
    s.op(OP_SIZE).op(OP_SWAP).op(OP_CAT)
    s.data(b"\x02").op(OP_SWAP).op(OP_CAT)
    s.data(b"\x02\x20" + EC.GX.to_bytes(32, "big")).op(OP_SWAP).op(OP_CAT)
    s.op(OP_SIZE).op(OP_SWAP).op(OP_CAT)
    s.data(b"\x30").op(OP_SWAP).op(OP_CAT)
    s.data(b"\x01").op(OP_CAT)                       # SIGHASH_ALL
    s.data(PUB_G).op(OP_CHECKSIGVERIFY)


def STEP(s, tm):
    active = [q for q in tm.states if q not in tm.halting]
    for q in active:
        s.op(OP_DUP).data(q).op(OP_EQUAL).op(OP_IF).op(OP_DROP)
        for a in tm.symbols:
            s.op(OP_DUP).data(a).op(OP_EQUAL).op(OP_IF).op(OP_DROP)
            q2, b, d = tm.delta[(q, a)]
            if d == R:
                s.op(OP_SWAP).data(b).op(OP_CAT).op(OP_SWAP)
                s.op(OP_SIZE).op(OP_0NOTEQUAL).op(OP_IF)
                s.op(OP_DUP).op(OP_1).op(OP_LEFT).op(OP_SWAP)
                s.op(OP_SIZE).op(OP_1SUB).op(OP_RIGHT).op(OP_SWAP)
                s.op(OP_ELSE).data(tm.blank).op(OP_ENDIF)
            elif d == L:
                s.data(b).op(OP_SWAP).op(OP_CAT).op(OP_SWAP)
                s.op(OP_SIZE).op(OP_0NOTEQUAL).op(OP_IF)
                s.op(OP_DUP).op(OP_1).op(OP_RIGHT).op(OP_SWAP)
                s.op(OP_SIZE).op(OP_1SUB).op(OP_LEFT).op(OP_SWAP)
                s.op(OP_ELSE).data(tm.blank).op(OP_ENDIF)
                s.op(OP_ROT).op(OP_SWAP)
            else:
                s.data(b)
            s.data(q2)
            s.op(OP_ELSE)
        s.data(q)
        for _ in tm.symbols:
            s.op(OP_ENDIF)
        s.op(OP_ELSE)
    for _ in active:
        s.op(OP_ENDIF)


def build_code(tm, k, beneficiary_pub):
    s = Script()
    s.op(OP_DUP).data(tm.acc).op(OP_EQUAL).op(OP_IF)
    s.op(OP_2DROP).op(OP_2DROP).data(beneficiary_pub).op(OP_CHECKSIG)
    s.op(OP_ELSE)
    s.op(OP_2OVER).op(OP_2OVER)
    ENC4(s)
    s.op(OP_TOALTSTACK)
    for _ in range(k):
        STEP(s, tm)
    ENC4(s)
    s.op(OP_OVER).op(OP_CAT)                         # spk_new
    s.op(OP_FROMALTSTACK).op(OP_ROT).op(OP_CAT)      # sc_old
    CSX(s)
    s.op(OP_TOALTSTACK)
    CSX(s)
    s.op(OP_SWAP).data(b"\x01\x00\x00\x00").op(OP_CAT).op(OP_CAT)
    s.op(OP_CAT)
    s.data(b"\x01").op(OP_SWAP).op(OP_CAT)
    s.op(OP_CAT)
    s.op(OP_FROMALTSTACK).op(OP_SWAP).op(OP_CAT)
    s.op(OP_CAT)
    s.data(b"\x01").op(OP_SWAP).op(OP_CAT)
    s.op(OP_CAT)
    SIGN(s)
    s.op(OP_1)
    s.op(OP_ENDIF)
    return s.bytes()


def locking_script(state, code):
    U, V, h, q = state
    return pd4(U) + pd4(V) + pd4(h) + pd4(q) + code


def unlocking_covenant(version, outpoint, seq, value, locktime, code):
    return Script().data(struct.pack("<i", version)).data(outpoint) \
        .data(struct.pack("<I", seq)).data(struct.pack("<q", value)) \
        .data(struct.pack("<I", locktime)).data(code).bytes()


# ------------------------------------------------------------------ machines
def abc_machine():
    B, a, b, c, X, Y, Z = b"_", b"a", b"b", b"c", b"X", b"Y", b"Z"
    q0, q1, q2, q3, q4, acc, rej = b"0", b"1", b"2", b"3", b"4", b"A", b"R"
    syms = [B, a, b, c, X, Y, Z]
    d = {
        (q0, a): (q1, X, R), (q0, Y): (q4, Y, R), (q0, B): (acc, B, S),
        (q1, a): (q1, a, R), (q1, Y): (q1, Y, R), (q1, b): (q2, Y, R),
        (q2, b): (q2, b, R), (q2, Z): (q2, Z, R), (q2, c): (q3, Z, L),
        (q3, a): (q3, a, L), (q3, b): (q3, b, L), (q3, Y): (q3, Y, L),
        (q3, Z): (q3, Z, L), (q3, X): (q0, X, R),
        (q4, Y): (q4, Y, R), (q4, Z): (q4, Z, R), (q4, B): (acc, B, S),
    }
    for q in (q0, q1, q2, q3, q4):
        for x in syms:
            d.setdefault((q, x), (rej, x, S))
    return ByteTM("a^k b^k c^k", [q0, q1, q2, q3, q4, acc, rej], syms, B, d, q0, acc,
                  {acc, rej})


def counter_machine():
    """Binary counter, least significant bit leftmost; increments forever (never halts)."""
    B, z, o = b"_", b"0", b"1"
    inc, ret, acc = b"i", b"r", b"A"
    d = {
        (inc, o): (inc, z, R), (inc, z): (ret, o, L), (inc, B): (ret, o, L),
        (ret, z): (ret, z, L), (ret, o): (ret, o, L), (ret, B): (inc, B, R),
    }
    return ByteTM("binary counter", [inc, ret, acc], [B, z, o], B, d, inc, acc, {acc})
