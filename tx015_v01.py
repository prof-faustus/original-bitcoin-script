"""Transactions and SignatureHash as at 0.1.5 (bitcoin/bitcoin e071a3f6c06f).

Serialisation (main.h IMPLEMENT_SERIALIZE; serialize.h): CTransaction = nVersion (int,
4 bytes LE), vin, vout, nLockTime (4 bytes LE); CTxIn = prevout (uint256 raw 32 bytes,
unsigned int n), scriptSig (compact size + bytes), nSequence; CTxOut = nValue (int64, 8 bytes
LE), scriptPubKey (compact size + bytes). Compact size: < 253 one byte; <= 0xFFFF 0xFD + 2;
<= 0xFFFFFFFF 0xFE + 4; else 0xFF + 8 (WriteCompactSize).
"""

import copy
import hashlib
import struct

from script015_v01 import get_op, OP_CODESEPARATOR

SIGHASH_ALL, SIGHASH_NONE, SIGHASH_SINGLE, SIGHASH_ANYONECANPAY = 1, 2, 3, 0x80


def sha256d(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def ser_compact(n):
    if n < 253:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    if n <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)


def ser_vec(b):
    return ser_compact(len(b)) + bytes(b)


class TxIn:
    def __init__(self, prev_hash, prev_n, script_sig=b"", seq=0xFFFFFFFF):
        self.prev_hash, self.prev_n = bytes(prev_hash), prev_n
        self.script_sig, self.seq = bytes(script_sig), seq


class TxOut:
    def __init__(self, value, spk):
        self.value, self.spk = value, bytes(spk)


class Tx:
    def __init__(self, version=1, vin=None, vout=None, locktime=0):
        self.version, self.vin, self.vout, self.locktime = version, vin or [], vout or [], locktime


def ser_outpoint(txin):
    return txin.prev_hash + struct.pack("<I", txin.prev_n)


def ser_tx(tx):
    b = struct.pack("<i", tx.version) + ser_compact(len(tx.vin))
    for i in tx.vin:
        b += ser_outpoint(i) + ser_vec(i.script_sig) + struct.pack("<I", i.seq)
    b += ser_compact(len(tx.vout))
    for o in tx.vout:
        b += struct.pack("<q", o.value) + ser_vec(o.spk)
    return b + struct.pack("<I", tx.locktime & 0xFFFFFFFF)


def txid(tx):
    """uint256 GetHash() — raw bytes in memory order."""
    return sha256d(ser_tx(tx))


def find_and_delete(script, pattern):
    """CScript::FindAndDelete at 0.1.5: erase pattern only where it starts at an
    operation boundary, repeatedly."""
    s = bytearray(script)
    pattern = bytes(pattern)
    pc = 0
    while True:
        while len(s) - pc >= len(pattern) and bytes(s[pc:pc + len(pattern)]) == pattern:
            del s[pc:pc + len(pattern)]
        ok, _op, _v, pc2 = get_op(bytes(s), pc)
        if not ok:
            break
        pc = pc2
    return bytes(s)


def signature_hash(script_code, tx, nIn, nHashType):
    """uint256 SignatureHash(CScript scriptCode, const CTransaction& txTo, nIn, nHashType)."""
    one = (1).to_bytes(32, "little")
    if nIn >= len(tx.vin):
        return one
    t = copy.deepcopy(tx)
    script_code = find_and_delete(script_code, bytes([OP_CODESEPARATOR]))
    for i in t.vin:
        i.script_sig = b""
    t.vin[nIn].script_sig = script_code
    if (nHashType & 0x1F) == SIGHASH_NONE:
        t.vout = []
        for k, i in enumerate(t.vin):
            if k != nIn:
                i.seq = 0
    elif (nHashType & 0x1F) == SIGHASH_SINGLE:
        nOut = nIn
        if nOut >= len(t.vout):
            return one
        t.vout = t.vout[:nOut + 1]
        for k in range(nOut):
            t.vout[k] = TxOut(-1, b"")
        for k, i in enumerate(t.vin):
            if k != nIn:
                i.seq = 0
    if nHashType & SIGHASH_ANYONECANPAY:
        t.vin = [t.vin[nIn]]
    return sha256d(ser_tx(t) + struct.pack("<i", nHashType))


def preimage(script_code, tx, nIn, nHashType):
    """The bytes hashed by signature_hash, for SIGHASH_ALL without ANYONECANPAY."""
    assert nHashType == SIGHASH_ALL
    t = copy.deepcopy(tx)
    script_code = find_and_delete(script_code, bytes([OP_CODESEPARATOR]))
    for i in t.vin:
        i.script_sig = b""
    t.vin[nIn].script_sig = script_code
    return ser_tx(t) + struct.pack("<i", nHashType)
