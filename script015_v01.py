"""Executable model of Bitcoin Script as shipped in 0.1.5.

Ported line by line from the official repository at commit e071a3f6c06f (30 August 2009,
SVN trunk@1, serialize.h VERSION = 105):
    script.h   sha256 f905858b5d6d4593a3051b593c45fb5a8dd4cd38b5636c5e4456060b034fa218
    script.cpp sha256 347c7526932d42a4d10ae487150b709e2ead737aa4b05f50aa9e2eefeb05a5b5
    bignum.h   sha256 c946d2678051772a771ec2ba9c33fee64d8c1d0c92b6a791d6637ba673b36fc0

Scope. EvalScript and VerifySignature's evaluation of scriptSig + OP_CODESEPARATOR +
scriptPubKey are modelled exactly for every opcode except OP_CHECKSIG,
OP_CHECKSIGVERIFY, OP_CHECKMULTISIG and OP_CHECKMULTISIGVERIFY, which need a transaction
and ECDSA and raise NotModelled if executed. Where the C++ is undefined behaviour (pop
from an empty vector in OP_2DROP) or throws (stack.at out of range), the model raises
ScriptException; no construction in this project reaches either case.

Numbers. CBigNum::setvch reverses the stack bytes into an OpenSSL MPI (big-endian, sign in
the top bit of the first byte); getvch is the inverse. Hence stack numbers are
little-endian sign-magnitude, zero is the empty vector, and there is no size bound.
"""

import hashlib

VERSION = 105

# ---------------------------------------------------------------- opcodes (script.h)
# The C enum assigns consecutive values; the list below is in header order.
_ENUM = [
    ("OP_0", 0), ("OP_PUSHDATA1", 76), "OP_PUSHDATA2", "OP_PUSHDATA4", "OP_1NEGATE",
    "OP_RESERVED", "OP_1", "OP_2", "OP_3", "OP_4", "OP_5", "OP_6", "OP_7", "OP_8", "OP_9",
    "OP_10", "OP_11", "OP_12", "OP_13", "OP_14", "OP_15", "OP_16",
    # control
    "OP_NOP", "OP_VER", "OP_IF", "OP_NOTIF", "OP_VERIF", "OP_VERNOTIF", "OP_ELSE",
    "OP_ENDIF", "OP_VERIFY", "OP_RETURN",
    # stack ops
    "OP_TOALTSTACK", "OP_FROMALTSTACK", "OP_2DROP", "OP_2DUP", "OP_3DUP", "OP_2OVER",
    "OP_2ROT", "OP_2SWAP", "OP_IFDUP", "OP_DEPTH", "OP_DROP", "OP_DUP", "OP_NIP",
    "OP_OVER", "OP_PICK", "OP_ROLL", "OP_ROT", "OP_SWAP", "OP_TUCK",
    # splice ops
    "OP_CAT", "OP_SUBSTR", "OP_LEFT", "OP_RIGHT", "OP_SIZE",
    # bit logic
    "OP_INVERT", "OP_AND", "OP_OR", "OP_XOR", "OP_EQUAL", "OP_EQUALVERIFY",
    "OP_RESERVED1", "OP_RESERVED2",
    # numeric
    "OP_1ADD", "OP_1SUB", "OP_2MUL", "OP_2DIV", "OP_NEGATE", "OP_ABS", "OP_NOT",
    "OP_0NOTEQUAL", "OP_ADD", "OP_SUB", "OP_MUL", "OP_DIV", "OP_MOD", "OP_LSHIFT",
    "OP_RSHIFT", "OP_BOOLAND", "OP_BOOLOR", "OP_NUMEQUAL", "OP_NUMEQUALVERIFY",
    "OP_NUMNOTEQUAL", "OP_LESSTHAN", "OP_GREATERTHAN", "OP_LESSTHANOREQUAL",
    "OP_GREATERTHANOREQUAL", "OP_MIN", "OP_MAX", "OP_WITHIN",
    # crypto
    "OP_RIPEMD160", "OP_SHA1", "OP_SHA256", "OP_HASH160", "OP_HASH256",
    "OP_CODESEPARATOR", "OP_CHECKSIG", "OP_CHECKSIGVERIFY", "OP_CHECKMULTISIG",
    "OP_CHECKMULTISIGVERIFY",
    # multi-byte opcodes
    ("OP_SINGLEBYTE_END", 0xF0), ("OP_DOUBLEBYTE_BEGIN", 0xF000), "OP_PUBKEY",
    "OP_PUBKEYHASH", ("OP_INVALIDOPCODE", 0xFFFF),
]

OP = {}
_next = 0
for _e in _ENUM:
    if isinstance(_e, tuple):
        _name, _next = _e
    else:
        _name = _e
    OP[_name] = _next
    _next += 1
globals().update(OP)
OP_FALSE = OP_0
OP_TRUE = OP_1
NAME = {v: k for k, v in OP.items()}

# Anchors from independent primary sources. Each is a check that fails if the enum above
# is mis-transcribed.
#   Chronicle specification: OP_VER 98, OP_VERIF 101, OP_VERNOTIF 102, OP_2MUL 141,
#     OP_2DIV 142, OP_SUBSTR originally 127, OP_LEFT originally 128, OP_RIGHT originally 129.
#   November 2018 specification: OP_INVERT 131, OP_MUL 149, OP_LSHIFT 152, OP_RSHIFT 153.
#   May 2018 specification: OP_CAT 126, OP_AND 132, OP_OR 133, OP_XOR 134, OP_DIV 150,
#     OP_MOD 151.
#   Wright (2020, AISC 1037, p. 259, Table 1): OP_TOALTSTACK 107 (0x6b),
#     OP_FROMALTSTACK 108 (0x6c).
ANCHORS = {
    "OP_VER": 98, "OP_VERIF": 101, "OP_VERNOTIF": 102, "OP_2MUL": 141, "OP_2DIV": 142,
    "OP_SUBSTR": 127, "OP_LEFT": 128, "OP_RIGHT": 129, "OP_INVERT": 131, "OP_MUL": 149,
    "OP_LSHIFT": 152, "OP_RSHIFT": 153, "OP_CAT": 126, "OP_AND": 132, "OP_OR": 133,
    "OP_XOR": 134, "OP_DIV": 150, "OP_MOD": 151, "OP_TOALTSTACK": 107,
    "OP_FROMALTSTACK": 108,
}
for _k, _v in ANCHORS.items():
    assert OP[_k] == _v, (_k, OP[_k], _v)


class ScriptException(Exception):
    """C++ undefined behaviour or an uncaught throw in the 0.1.5 source."""


class NotModelled(Exception):
    """Signature opcodes, which need a transaction context."""


# ---------------------------------------------------------------- CBigNum (bignum.h)
def bn_from_vch(vch):
    """CBigNum(vch): setvch -> reverse_copy into MPI -> BN_mpi2bn."""
    if len(vch) == 0:
        return 0
    be = bytes(reversed(vch))
    neg = be[0] & 0x80
    mag = int.from_bytes(bytes([be[0] & 0x7F]) + be[1:], "big")
    return -mag if neg else mag


def bn_getvch(n):
    """CBigNum::getvch: BN_bn2mpi, drop the 4-byte length, reverse."""
    if n == 0:
        return b""
    mag = abs(n)
    be = mag.to_bytes((mag.bit_length() + 7) // 8, "big")
    if be[0] & 0x80:
        be = b"\x00" + be
    if n < 0:
        be = bytes([be[0] | 0x80]) + be[1:]
    return bytes(reversed(be))


INT_MAX = 2**31 - 1
INT_MIN = -(2**31)


def bn_getint(n):
    """CBigNum::getint: BN_get_word, then clamp to int."""
    if n >= 0:
        return n if n <= INT_MAX else INT_MAX
    return n if -n <= INT_MAX else INT_MIN


def cast_to_bool(vch):
    """0.1.5 CastToBool: CBigNum(vch) != 0."""
    return bn_from_vch(vch) != 0


VCH_FALSE = b""
VCH_TRUE = b"\x01"


# ---------------------------------------------------------------- CScript::GetOp
def get_op(script, pc):
    """Returns (ok, opcode, pushvalue, new_pc). Mirrors CScript::GetOp."""
    if pc >= len(script):
        return False, OP_INVALIDOPCODE, b"", pc
    opcode = script[pc]
    pc += 1
    if opcode >= OP_SINGLEBYTE_END:
        if pc + 1 > len(script):
            return False, OP_INVALIDOPCODE, b"", pc
        opcode = (opcode << 8) | script[pc]
        pc += 1
    vch = b""
    if opcode <= OP_PUSHDATA4:
        n = opcode
        if opcode == OP_PUSHDATA1:
            if pc + 1 > len(script):
                return False, OP_INVALIDOPCODE, b"", pc
            n = script[pc]
            pc += 1
        elif opcode == OP_PUSHDATA2:
            if pc + 2 > len(script):
                return False, OP_INVALIDOPCODE, b"", pc
            n = int.from_bytes(script[pc:pc + 2], "little")
            pc += 2
        elif opcode == OP_PUSHDATA4:
            if pc + 4 > len(script):
                return False, OP_INVALIDOPCODE, b"", pc
            n = int.from_bytes(script[pc:pc + 4], "little")
            pc += 4
        if pc + n > len(script):
            return False, OP_INVALIDOPCODE, b"", pc
        vch = bytes(script[pc:pc + n])
        pc += n
    return True, opcode, vch, pc


# ---------------------------------------------------------------- CScript builder
class Script:
    """Assembles bytes exactly as CScript's operator<< does."""

    def __init__(self):
        self.b = bytearray()

    def op(self, opcode):
        assert opcode <= OP_SINGLEBYTE_END
        self.b.append(opcode)
        return self

    def num(self, n):
        # CScript::push_int64
        if n == -1 or 1 <= n <= 16:
            self.b.append(n + (OP_1 - 1))
        else:
            self.data(bn_getvch(n))
        return self

    def data(self, v):
        # CScript::operator<<(const vector<unsigned char>&)
        v = bytes(v)
        if len(v) < OP_PUSHDATA1:
            self.b.append(len(v))
        elif len(v) <= 0xFF:
            self.b.append(OP_PUSHDATA1)
            self.b.append(len(v))
        else:
            self.b.append(OP_PUSHDATA2)
            self.b += len(v).to_bytes(2, "little")
        self.b += v
        return self

    def extend(self, other):
        self.b += other.b
        return self

    def bytes(self):
        return bytes(self.b)


def disassemble(script):
    out, pc = [], 0
    while pc < len(script):
        ok, opcode, vch, pc = get_op(script, pc)
        if not ok:
            out.append("<truncated>")
            break
        if opcode <= OP_PUSHDATA4:
            out.append(str(bn_from_vch(vch)) if len(vch) <= 4 else vch.hex())
        else:
            out.append(NAME.get(opcode, "UNKNOWN_OPCODE"))
    return " ".join(out)


# ---------------------------------------------------------------- EvalScript
class Trace:
    def __init__(self):
        self.ops = 0          # executed non-push operations
        self.max_main = 0
        self.max_alt = 0
        self.max_elem = 0
        self.max_ifdepth = 0
        self.opcodes_used = set()


def eval_script(script, trace=None):
    """bool EvalScript(script, txTo, nIn, nHashType, pvStackRet) at e071a3f6c06f.

    Returns (result, stack, altstack). result is the function's return value.
    """
    stack, altstack, vfExec = [], [], []
    pc, pend = 0, len(script)

    def top(i):
        idx = len(stack) + i
        if idx < 0 or idx >= len(stack):
            raise ScriptException("stack.at out of range")
        return stack[idx]

    def pop():
        if not stack:
            raise ScriptException("pop_back on empty vector")
        return stack.pop()

    while pc < pend:
        fExec = all(vfExec)
        ok, opcode, vch, pc = get_op(script, pc)
        if not ok:
            return False, stack, altstack

        if fExec and opcode <= OP_PUSHDATA4:
            stack.append(vch)
        elif fExec or (OP_IF <= opcode <= OP_ENDIF):
            if trace is not None and fExec:
                trace.ops += 1
                trace.opcodes_used.add(NAME.get(opcode, hex(opcode)))

            if OP_1NEGATE == opcode or OP_1 <= opcode <= OP_16:
                stack.append(bn_getvch(opcode - (OP_1 - 1)))

            elif opcode == OP_NOP:
                pass
            elif opcode == OP_VER:
                stack.append(bn_getvch(VERSION))
            elif opcode in (OP_IF, OP_NOTIF, OP_VERIF, OP_VERNOTIF):
                fValue = False
                if fExec:
                    if len(stack) < 1:
                        return False, stack, altstack
                    v = top(-1)
                    if opcode in (OP_VERIF, OP_VERNOTIF):
                        fValue = VERSION >= bn_from_vch(v)
                    else:
                        fValue = cast_to_bool(v)
                    if opcode in (OP_NOTIF, OP_VERNOTIF):
                        fValue = not fValue
                    stack.pop()
                vfExec.append(fValue)
            elif opcode == OP_ELSE:
                if not vfExec:
                    return False, stack, altstack
                vfExec[-1] = not vfExec[-1]
            elif opcode == OP_ENDIF:
                if not vfExec:
                    return False, stack, altstack
                vfExec.pop()
            elif opcode == OP_VERIFY:
                if len(stack) < 1:
                    return False, stack, altstack
                if cast_to_bool(top(-1)):
                    stack.pop()
                else:
                    pc = pend
            elif opcode == OP_RETURN:
                pc = pend

            # stack ops
            elif opcode == OP_TOALTSTACK:
                if len(stack) < 1:
                    return False, stack, altstack
                altstack.append(top(-1))
                stack.pop()
            elif opcode == OP_FROMALTSTACK:
                if len(altstack) < 1:
                    return False, stack, altstack
                stack.append(altstack[-1])
                altstack.pop()
            elif opcode == OP_2DROP:
                pop()
                pop()
            elif opcode == OP_2DUP:
                if len(stack) < 2:
                    return False, stack, altstack
                a, b = top(-2), top(-1)
                stack += [a, b]
            elif opcode == OP_3DUP:
                if len(stack) < 3:
                    return False, stack, altstack
                a, b, c = top(-3), top(-2), top(-1)
                stack += [a, b, c]
            elif opcode == OP_2OVER:
                if len(stack) < 4:
                    return False, stack, altstack
                a, b = top(-4), top(-3)
                stack += [a, b]
            elif opcode == OP_2ROT:
                if len(stack) < 6:
                    return False, stack, altstack
                a, b = top(-6), top(-5)
                del stack[-6:-4]
                stack += [a, b]
            elif opcode == OP_2SWAP:
                if len(stack) < 4:
                    return False, stack, altstack
                stack[-4], stack[-2] = stack[-2], stack[-4]
                stack[-3], stack[-1] = stack[-1], stack[-3]
            elif opcode == OP_IFDUP:
                if len(stack) < 1:
                    return False, stack, altstack
                v = top(-1)
                if cast_to_bool(v):
                    stack.append(v)
            elif opcode == OP_DEPTH:
                stack.append(bn_getvch(len(stack)))
            elif opcode == OP_DROP:
                if len(stack) < 1:
                    return False, stack, altstack
                stack.pop()
            elif opcode == OP_DUP:
                if len(stack) < 1:
                    return False, stack, altstack
                stack.append(top(-1))
            elif opcode == OP_NIP:
                if len(stack) < 2:
                    return False, stack, altstack
                del stack[-2]
            elif opcode == OP_OVER:
                if len(stack) < 2:
                    return False, stack, altstack
                stack.append(top(-2))
            elif opcode in (OP_PICK, OP_ROLL):
                if len(stack) < 2:
                    return False, stack, altstack
                n = bn_getint(bn_from_vch(top(-1)))
                stack.pop()
                if n < 0 or n >= len(stack):
                    return False, stack, altstack
                v = top(-n - 1)
                if opcode == OP_ROLL:
                    del stack[len(stack) - n - 1]
                stack.append(v)
            elif opcode == OP_ROT:
                if len(stack) < 3:
                    return False, stack, altstack
                stack[-3], stack[-2] = stack[-2], stack[-3]
                stack[-2], stack[-1] = stack[-1], stack[-2]
            elif opcode == OP_SWAP:
                if len(stack) < 2:
                    return False, stack, altstack
                stack[-2], stack[-1] = stack[-1], stack[-2]
            elif opcode == OP_TUCK:
                if len(stack) < 2:
                    return False, stack, altstack
                v = top(-1)
                stack.insert(len(stack) - 2, v)

            # splice ops
            elif opcode == OP_CAT:
                if len(stack) < 2:
                    return False, stack, altstack
                a, b = top(-2), top(-1)
                stack[-2] = a + b
                stack.pop()
            elif opcode == OP_SUBSTR:
                if len(stack) < 3:
                    return False, stack, altstack
                v = top(-3)
                nBegin = bn_getint(bn_from_vch(top(-2)))
                nEnd = nBegin + bn_getint(bn_from_vch(top(-1)))
                if nBegin < 0 or nEnd < nBegin:
                    return False, stack, altstack
                nBegin = min(nBegin, len(v))
                nEnd = min(nEnd, len(v))
                stack[-3] = v[nBegin:nEnd]
                stack.pop()
                stack.pop()
            elif opcode in (OP_LEFT, OP_RIGHT):
                if len(stack) < 2:
                    return False, stack, altstack
                v = top(-2)
                nSize = bn_getint(bn_from_vch(top(-1)))
                if nSize < 0:
                    return False, stack, altstack
                nSize = min(nSize, len(v))
                stack[-2] = v[:nSize] if opcode == OP_LEFT else v[len(v) - nSize:]
                stack.pop()
            elif opcode == OP_SIZE:
                if len(stack) < 1:
                    return False, stack, altstack
                stack.append(bn_getvch(len(top(-1))))

            # bitwise logic
            elif opcode == OP_INVERT:
                if len(stack) < 1:
                    return False, stack, altstack
                stack[-1] = bytes((~x) & 0xFF for x in top(-1))
            elif opcode in (OP_AND, OP_OR, OP_XOR):
                if len(stack) < 2:
                    return False, stack, altstack
                a, b = bytearray(top(-2)), bytearray(top(-1))
                # MakeSameSize lengthens the shorter with zeros
                m = max(len(a), len(b))
                a += bytes(m - len(a))
                b += bytes(m - len(b))
                if opcode == OP_AND:
                    r = bytes(x & y for x, y in zip(a, b))
                elif opcode == OP_OR:
                    r = bytes(x | y for x, y in zip(a, b))
                else:
                    r = bytes(x ^ y for x, y in zip(a, b))
                stack[-2] = r
                stack.pop()
            elif opcode in (OP_EQUAL, OP_EQUALVERIFY):
                if len(stack) < 2:
                    return False, stack, altstack
                fEqual = top(-2) == top(-1)
                stack.pop()
                stack.pop()
                stack.append(VCH_TRUE if fEqual else VCH_FALSE)
                if opcode == OP_EQUALVERIFY:
                    if fEqual:
                        stack.pop()
                    else:
                        pc = pend

            # numeric
            elif opcode in (OP_1ADD, OP_1SUB, OP_2MUL, OP_2DIV, OP_NEGATE, OP_ABS,
                            OP_NOT, OP_0NOTEQUAL):
                if len(stack) < 1:
                    return False, stack, altstack
                bn = bn_from_vch(top(-1))
                if opcode == OP_1ADD:
                    bn += 1
                elif opcode == OP_1SUB:
                    bn -= 1
                elif opcode == OP_2MUL:
                    # BN_lshift shifts the magnitude and keeps the sign
                    bn = -((-bn) << 1) if bn < 0 else bn << 1
                elif opcode == OP_2DIV:
                    # BN_rshift shifts the magnitude and keeps the sign
                    bn = -((-bn) >> 1) if bn < 0 else bn >> 1
                elif opcode == OP_NEGATE:
                    bn = -bn
                elif opcode == OP_ABS:
                    bn = abs(bn)
                elif opcode == OP_NOT:
                    bn = 1 if bn == 0 else 0
                elif opcode == OP_0NOTEQUAL:
                    bn = 1 if bn != 0 else 0
                stack.pop()
                stack.append(bn_getvch(bn))
            elif OP_ADD <= opcode <= OP_MAX:
                if len(stack) < 2:
                    return False, stack, altstack
                bn1, bn2 = bn_from_vch(top(-2)), bn_from_vch(top(-1))
                if opcode == OP_ADD:
                    bn = bn1 + bn2
                elif opcode == OP_SUB:
                    bn = bn1 - bn2
                elif opcode == OP_MUL:
                    bn = bn1 * bn2
                elif opcode in (OP_DIV, OP_MOD):
                    if bn2 == 0:
                        return False, stack, altstack   # BN_div fails on zero divisor
                    q = abs(bn1) // abs(bn2)             # OpenSSL truncates toward zero
                    q = q if (bn1 >= 0) == (bn2 >= 0) else -q
                    bn = q if opcode == OP_DIV else bn1 - q * bn2
                elif opcode in (OP_LSHIFT, OP_RSHIFT):
                    if bn2 < 0:
                        return False, stack, altstack
                    if bn2 > 1 << 20:
                        raise ScriptException("shift beyond modelled range")
                    mag = abs(bn1)
                    mag = mag << bn2 if opcode == OP_LSHIFT else mag >> bn2
                    bn = -mag if bn1 < 0 else mag
                elif opcode == OP_BOOLAND:
                    bn = int(bn1 != 0 and bn2 != 0)
                elif opcode == OP_BOOLOR:
                    bn = int(bn1 != 0 or bn2 != 0)
                elif opcode in (OP_NUMEQUAL, OP_NUMEQUALVERIFY):
                    bn = int(bn1 == bn2)
                elif opcode == OP_NUMNOTEQUAL:
                    bn = int(bn1 != bn2)
                elif opcode == OP_LESSTHAN:
                    bn = int(bn1 < bn2)
                elif opcode == OP_GREATERTHAN:
                    bn = int(bn1 > bn2)
                elif opcode == OP_LESSTHANOREQUAL:
                    bn = int(bn1 <= bn2)
                elif opcode == OP_GREATERTHANOREQUAL:
                    bn = int(bn1 >= bn2)
                elif opcode == OP_MIN:
                    bn = min(bn1, bn2)
                elif opcode == OP_MAX:
                    bn = max(bn1, bn2)
                stack.pop()
                stack.pop()
                stack.append(bn_getvch(bn))
                if opcode == OP_NUMEQUALVERIFY:
                    if cast_to_bool(top(-1)):
                        stack.pop()
                    else:
                        pc = pend
            elif opcode == OP_WITHIN:
                if len(stack) < 3:
                    return False, stack, altstack
                b1, b2, b3 = (bn_from_vch(top(-3)), bn_from_vch(top(-2)),
                              bn_from_vch(top(-1)))
                stack.pop()
                stack.pop()
                stack.pop()
                stack.append(VCH_TRUE if (b2 <= b1 < b3) else VCH_FALSE)

            # crypto
            elif opcode in (OP_RIPEMD160, OP_SHA1, OP_SHA256, OP_HASH160, OP_HASH256):
                if len(stack) < 1:
                    return False, stack, altstack
                v = top(-1)
                if opcode == OP_RIPEMD160:
                    h = hashlib.new("ripemd160", v).digest()
                elif opcode == OP_SHA1:
                    h = hashlib.sha1(v).digest()
                elif opcode == OP_SHA256:
                    h = hashlib.sha256(v).digest()
                elif opcode == OP_HASH160:
                    h = hashlib.new("ripemd160", hashlib.sha256(v).digest()).digest()
                else:
                    h = hashlib.sha256(hashlib.sha256(v).digest()).digest()
                stack.pop()
                stack.append(h)
            elif opcode == OP_CODESEPARATOR:
                pass
            elif opcode in (OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_CHECKMULTISIG,
                            OP_CHECKMULTISIGVERIFY):
                raise NotModelled(NAME[opcode])
            else:
                return False, stack, altstack

            if trace is not None:
                trace.max_ifdepth = max(trace.max_ifdepth, len(vfExec))
        if trace is not None:
            trace.max_main = max(trace.max_main, len(stack))
            trace.max_alt = max(trace.max_alt, len(altstack))
            if stack:
                trace.max_elem = max(trace.max_elem, len(stack[-1]))

    result = False if not stack else cast_to_bool(stack[-1])
    return result, stack, altstack


def verify(script_sig, script_pubkey, trace=None):
    """VerifySignature at 0.1.5: one evaluation of scriptSig + OP_CODESEPARATOR +
    scriptPubKey."""
    return eval_script(bytes(script_sig) + bytes([OP_CODESEPARATOR]) + bytes(script_pubkey),
                       trace)[0]
