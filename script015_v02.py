"""Executable model of 0.1.5 Script with transaction context.

Same evaluator as script015_v01.eval_script (ported from e071a3f6c06f script.cpp), extended
with what v01 left out: pbegincodehash tracking for OP_CODESEPARATOR, and OP_CHECKSIG,
OP_CHECKSIGVERIFY, OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY with CheckSig and SignatureHash
as in the source. VerifySignature evaluates scriptSig + OP_CODESEPARATOR + scriptPubKey.
"""

import hashlib

import script015_v01 as V1
from script015_v01 import *  # noqa: F401,F403  (opcodes, Script, number helpers)
from script015_v01 import (bn_from_vch, bn_getvch, bn_getint, cast_to_bool, get_op,
                           VCH_TRUE, VCH_FALSE, ScriptException, NAME, VERSION, Trace)
import secp256k1_v01 as EC
import tx015_v01 as TX


def check_sig(vchSig, vchPubKey, script_code, tx, nIn, nHashType):
    """CheckSig at 0.1.5."""
    pub = EC.parse_pubkey(bytes(vchPubKey))
    if pub is None:
        return False
    if len(vchSig) == 0:
        return False
    if nHashType == 0:
        nHashType = vchSig[-1]
    elif nHashType != vchSig[-1]:
        return False
    sig = bytes(vchSig[:-1])
    h = TX.signature_hash(script_code, tx, nIn, nHashType)
    return EC.verify(pub, int.from_bytes(h, "big"), sig)


def push_encoding(v):
    return V1.Script().data(v).bytes()


def eval_script(script, tx=None, nIn=0, nHashType=0, trace=None):
    stack, altstack, vfExec = [], [], []
    pc, pend = 0, len(script)
    pbegincodehash = 0

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
            if opcode == OP_1NEGATE or OP_1 <= opcode <= OP_16:
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
            elif opcode == OP_INVERT:
                if len(stack) < 1:
                    return False, stack, altstack
                stack[-1] = bytes((~x) & 0xFF for x in top(-1))
            elif opcode in (OP_AND, OP_OR, OP_XOR):
                if len(stack) < 2:
                    return False, stack, altstack
                a, b = bytearray(top(-2)), bytearray(top(-1))
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
                    bn = -((-bn) << 1) if bn < 0 else bn << 1
                elif opcode == OP_2DIV:
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
                        return False, stack, altstack
                    q = abs(bn1) // abs(bn2)
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
                pbegincodehash = pc
            elif opcode in (OP_CHECKSIG, OP_CHECKSIGVERIFY):
                if len(stack) < 2:
                    return False, stack, altstack
                vchSig, vchPubKey = top(-2), top(-1)
                script_code = TX.find_and_delete(script[pbegincodehash:], push_encoding(vchSig))
                fSuccess = tx is not None and check_sig(vchSig, vchPubKey, script_code,
                                                        tx, nIn, nHashType)
                stack.pop()
                stack.pop()
                stack.append(VCH_TRUE if fSuccess else VCH_FALSE)
                if opcode == OP_CHECKSIGVERIFY:
                    if fSuccess:
                        stack.pop()
                    else:
                        pc = pend
            elif opcode in (OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY):
                i = 1
                if len(stack) < i:
                    return False, stack, altstack
                nKeysCount = bn_getint(bn_from_vch(top(-i)))
                if nKeysCount < 0:
                    return False, stack, altstack
                i += 1
                ikey = i
                i += nKeysCount
                if len(stack) < i:
                    return False, stack, altstack
                nSigsCount = bn_getint(bn_from_vch(top(-i)))
                if nSigsCount < 0 or nSigsCount > nKeysCount:
                    return False, stack, altstack
                i += 1
                isig = i
                i += nSigsCount
                if len(stack) < i:
                    return False, stack, altstack
                script_code = script[pbegincodehash:]
                for k in range(nSigsCount):
                    script_code = TX.find_and_delete(script_code, push_encoding(top(-isig - k)))
                fSuccess = True
                while fSuccess and nSigsCount > 0:
                    if tx is not None and check_sig(top(-isig), top(-ikey), script_code,
                                                    tx, nIn, nHashType):
                        isig += 1
                        nSigsCount -= 1
                    ikey += 1
                    nKeysCount -= 1
                    if nSigsCount > nKeysCount:
                        fSuccess = False
                # "while (i-- > 0) stack.pop_back();" pops i items: one more than the
                # operands, the original off-by-one that consumes an extra element.
                for _ in range(i):
                    stack.pop()
                stack.append(VCH_TRUE if fSuccess else VCH_FALSE)
                if opcode == OP_CHECKMULTISIGVERIFY:
                    if fSuccess:
                        stack.pop()
                    else:
                        pc = pend
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


def verify_signature(tx_from, tx_to, nIn, trace=None):
    """VerifySignature at 0.1.5."""
    txin = tx_to.vin[nIn]
    if txin.prev_n >= len(tx_from.vout):
        return False
    if txin.prev_hash != TX.txid(tx_from):
        return False
    spk = tx_from.vout[txin.prev_n].spk
    return eval_script(txin.script_sig + bytes([OP_CODESEPARATOR]) + spk, tx_to, nIn, 0,
                       trace)[0]
