"""Checks for the covenant chain in the 0.1.5 language (covenant_v02). Every check can fail.

Run from this directory:  python run_covenant_checks_v02.py
Writes covenant_results_v02.json and covenant_results_v02.txt.

v02 (3 November 2026) runs the chains on covenant_v02, whose CODE requires the five fixed
transaction fields to have their serialised widths, and adds forged spends as negative
controls: a second output, a substituted CODE, and the covenant as the second of two inputs.
Each forged spend is built by searching every way of cutting the spending transaction's
real preimage into the fields CODE concatenates; against covenant_v01 the search finds a
cut and the forged spend validates (so the control can fail), against covenant_v02 it must
find none and the forged spend must be refused.
"""

import hashlib
import json
import os
import struct
import sys
import time

import script015_v01 as V1
import script015_v02 as M
import tx015_v01 as TX
import secp256k1_v01 as EC
import constructions_v01 as C
import covenant_v01 as CV1
import covenant_v02 as CV

HERE = os.path.dirname(os.path.abspath(__file__))
out = {"checks": [], "runs": [], "files": {}}
failures = 0


def check(name, cond, detail=""):
    global failures
    out["checks"].append({"name": name, "pass": bool(cond), "detail": detail})
    if not cond:
        failures += 1
    print(("PASS " if cond else "FAIL ") + name + (" | " + detail if detail else ""), flush=True)


DISABLED_2010 = {"OP_CAT", "OP_SUBSTR", "OP_LEFT", "OP_RIGHT", "OP_INVERT", "OP_AND", "OP_OR",
                 "OP_XOR", "OP_2MUL", "OP_2DIV", "OP_MUL", "OP_DIV", "OP_MOD", "OP_LSHIFT",
                 "OP_RSHIFT"}
VALUE = 100_000_000

# ------------------------------------------------------------- 1. curve and signatures
check("secp256k1: G is on the curve", EC.on_curve(EC.G))
check("secp256k1: n*G is the point at infinity", EC.mul(EC.N, EC.G) is None)
z = int.from_bytes(hashlib.sha256(b"test").digest(), "big")
sig = EC.sign(0xC0FFEE, z, 0x1234567)
pub = EC.parse_pubkey(EC.pubkey_bytes(0xC0FFEE))
check("ECDSA sign/verify round trip", EC.verify(pub, z, sig))
check("ECDSA rejects a different digest", not EC.verify(pub, z + 1, sig))
check("ECDSA rejects a different key", not EC.verify(EC.parse_pubkey(EC.pubkey_bytes(7)), z, sig))

# ------------------------------------------------------------- 2. 0.1.5 transaction model
d_a = 0xA11CE
p2pk = V1.Script().data(EC.pubkey_bytes(d_a)).op(V1.OP_CHECKSIG).bytes()
t0 = TX.Tx(1, [TX.TxIn(b"\x00" * 32, 0xFFFFFFFF, b"\x01\x01")], [TX.TxOut(VALUE, p2pk)])
t1 = TX.Tx(1, [TX.TxIn(TX.txid(t0), 0)], [TX.TxOut(VALUE, p2pk)])
h = TX.signature_hash(p2pk, t1, 0, TX.SIGHASH_ALL)
t1.vin[0].script_sig = V1.Script().data(EC.sign(d_a, int.from_bytes(h, "big"), 99) + b"\x01").bytes()
check("0.1.5 pay-to-pubkey spend with an honest signature validates",
      M.verify_signature(t0, t1, 0))
h_bad = TX.signature_hash(p2pk, t1, 0, TX.SIGHASH_ALL)
t1.vin[0].script_sig = V1.Script().data(EC.sign(d_a + 1, int.from_bytes(h_bad, "big"), 99)
                                       + b"\x01").bytes()
check("0.1.5 pay-to-pubkey spend signed with the wrong key fails",
      not M.verify_signature(t0, t1, 0))
t1.vin[0].script_sig = bytes([V1.OP_1, V1.OP_RETURN])
check("v02 model also reproduces the OP_1 OP_RETURN defect", M.verify_signature(t0, t1, 0))

# regression: v01 constructions behave identically under v02
tm, sigma, member = C.tm_abc()
agree = 0
import itertools
inputs = [list(w) for w in itertools.product(sigma, repeat=5)]
T = max(tm.run(w)[1] for w in inputs)
lock = C.compile_tm(tm, 5, T)
for w in inputs:
    a = V1.verify(C.unlock_tm(w), lock)
    b = M.eval_script(C.unlock_tm(w) + bytes([V1.OP_CODESEPARATOR]) + lock)[0]
    agree += (a == b == member(w))
check("v02 evaluator agrees with v01 on all 243 a^k b^k c^k inputs at n=5", agree == 243)
val, steps = C.ackermann(3, 2)
check("v02 evaluator verifies A(3,2)=29",
      M.eval_script(C.ackermann_unlock(val, 3, 2) + bytes([V1.OP_CODESEPARATOR])
                    + C.ackermann_lock(steps))[0])


# ------------------------------------------------------------- 3. covenant chains
def successor(tm, st, k):
    for _ in range(k):
        st = tm.step(st)
    return st


def spend(prev, state_next, code, unlock_fields=None, extra_out=None, code_supplied=None,
          version=1):
    tx = TX.Tx(version, [TX.TxIn(TX.txid(prev), 0, b"", 0xFFFFFFFF)],
               [TX.TxOut(VALUE, CV.locking_script(state_next, code))], 0)
    if extra_out is not None:
        tx.vout.append(extra_out)
    f = unlock_fields or {}
    tx.vin[0].script_sig = CV.unlocking_covenant(
        f.get("version", version), TX.txid(prev) + struct.pack("<I", 0), 0xFFFFFFFF,
        f.get("value", VALUE), 0, code_supplied if code_supplied is not None else code)
    return tx


def at(m, i, x):
    """True if the bytes x occur in m at position i."""
    return m[i:i + len(x)] == x


def cuts(m, sc, spk, widths):
    """Every cut of the preimage m into ver' 01 out' cs(sc) sc seq' 01 val' cs(spk) spk lt' HT
    (HT the last four bytes). With widths=True only cuts whose five free fields have the
    serialised widths (4, 36, 4, 8, 4) are returned. Each cut is (ver, out, seq, val, lt)."""
    A, B = TX.ser_vec(sc), TX.ser_vec(spk)
    found = []
    for i in range(len(m) - len(A) + 1):
        if not at(m, i, A):
            continue
        for j in range(i + len(A), len(m) - len(B) - 4 + 1):
            if not at(m, j, B):
                continue
            for p in range(0, i):
                if m[p] != 1:
                    continue
                for r in range(i + len(A), j):
                    if m[r] != 1:
                        continue
                    f = (m[:p], m[p + 1:i], m[i + len(A):r], m[r + 1:j], m[j + len(B):len(m) - 4])
                    if widths and tuple(len(x) for x in f) != (4, 36, 4, 8, 4):
                        continue
                    found.append(f)
    return found


def forged(tx, idx, L, code_s, enc_old, enc_new):
    """Fill input idx of tx with an unlocking script that supplies a cut of its real preimage
    (any widths); returns (number of cuts, number of cuts with serialised widths)."""
    m = TX.preimage(L, tx, idx, TX.SIGHASH_ALL)
    c = cuts(m, enc_old + code_s, enc_new + code_s, False)
    if c:
        ver, outp, seq, val, lt = c[0]
        tx.vin[idx].script_sig = V1.Script().data(ver).data(outp).data(seq).data(val) \
            .data(lt).data(code_s).bytes()
    return len(c), len(cuts(m, enc_old + code_s, enc_new + code_s, True))


def forgery_controls(tm, prev, state, nxt, code, cvmod, label, expect_valid):
    """The three forged spends of prev's covenant output, each supplying a cut of the real
    preimage; each validates under covenant_v01 (expect_valid True) and must be refused under
    covenant_v02 (expect_valid False), where no cut has the serialised field widths."""
    L = prev.vout[0].spk
    enc_old = L[:len(L) - len(code)]
    enc_new = cvmod.locking_script(nxt, b"")
    thief = V1.Script().data(EC.pubkey_bytes(5)).op(V1.OP_CHECKSIG).bytes()
    # (a) the honest successor plus a second output; sequence chosen with low byte 0x01
    ta = TX.Tx(1, [TX.TxIn(TX.txid(prev), 0, b"", 0xFFFFFF01)],
               [TX.TxOut(VALUE // 2, cvmod.locking_script(nxt, code)),
                TX.TxOut(VALUE // 2, thief)], 0)
    na = forged(ta, 0, L, code, enc_old, enc_new)
    # (b) successor carrying substituted code OP_1; a first output carries enc_old || OP_1
    code_s = bytes([V1.OP_1])
    tb = TX.Tx(1, [TX.TxIn(TX.txid(prev), 0, b"", 0xFFFFFFFF)],
               [TX.TxOut(1000, enc_old + code_s), TX.TxOut(VALUE + 1, enc_new + code_s)], 0)
    nb = forged(tb, 0, L, code_s, enc_old, enc_new)
    # (c) the covenant as the second of two inputs; the first spends output 1 of another tx
    other = TX.Tx(1, [TX.TxIn(b"\x11" * 32, 0xFFFFFFFF, b"\x01\x02")],
                  [TX.TxOut(1, thief), TX.TxOut(5_000, thief)])
    tc = TX.Tx(1, [TX.TxIn(TX.txid(other), 1, b"", 0xFFFFFFFF),
                   TX.TxIn(TX.txid(prev), 0, b"", 0xFFFFFFFF)],
               [TX.TxOut(VALUE, cvmod.locking_script(nxt, code))], 0)
    nc = forged(tc, 1, L, code, enc_old, enc_new)
    for name, tx, idx, (n, nw) in (("a second output", ta, 0, na),
                                    ("a successor carrying substituted code", tb, 0, nb),
                                    ("the covenant as the second of two inputs", tc, 1, nc)):
        if expect_valid:
            check("%s, covenant_v01: forged spend with %s found and validates" % (label, name),
                  n > 0 and M.verify_signature(prev, tx, idx), "%d cuts" % n)
        else:
            check("%s control: forged spend with %s is rejected" % (label, name),
                  n > 0 and nw == 0 and not M.verify_signature(prev, tx, idx),
                  "%d cuts, none with serialised field widths" % n)


def run_chain(tm, state, k, max_tx, d_b, label, controls=True):
    code = CV.build_code(tm, k, EC.pubkey_bytes(d_b))
    funding = TX.Tx(1, [TX.TxIn(b"\x00" * 32, 0xFFFFFFFF, b"\x01\x01")],
                    [TX.TxOut(VALUE, CV.locking_script(state, code))])
    prev, n, sizes = funding, 0, []
    tr = V1.Trace()
    all_ok = True
    t_start = time.time()
    while state[3] not in tm.halting and n < max_tx:
        nxt = successor(tm, state, k)
        if controls and n == 0:
            wrong = (nxt[0], nxt[1], nxt[2], tm.states[0] if nxt[3] != tm.states[0]
                     else tm.states[1])
            check("%s control: successor with a wrong machine state is rejected" % label,
                  not M.verify_signature(prev, spend(prev, wrong, code), 0))
            tape = nxt[1] if nxt[1] else nxt[0]
            if tape:
                flipped = bytes([tape[0] ^ 0x01]) + tape[1:]
                wrong2 = (nxt[0], flipped, nxt[2], nxt[3]) if nxt[1] else \
                    (flipped, nxt[1], nxt[2], nxt[3])
                check("%s control: successor with one tape cell altered is rejected" % label,
                      not M.verify_signature(prev, spend(prev, wrong2, code), 0))
            p2pk_b = V1.Script().data(EC.pubkey_bytes(5)).op(V1.OP_CHECKSIG).bytes()
            check("%s control: a second output is rejected" % label,
                  not M.verify_signature(prev, spend(prev, nxt, code,
                                                     extra_out=TX.TxOut(1, p2pk_b)), 0))
            check("%s control: unlocking script supplying different CODE is rejected" % label,
                  not M.verify_signature(prev, spend(prev, nxt, code,
                                                     code_supplied=code + bytes([V1.OP_NOP])), 0))
            check("%s control: a misstated transaction field is rejected" % label,
                  not M.verify_signature(prev, spend(prev, nxt, code,
                                                     unlock_fields={"value": VALUE - 1}), 0))
            pay = TX.Tx(1, [TX.TxIn(TX.txid(prev), 0)],
                        [TX.TxOut(VALUE, V1.Script().data(EC.pubkey_bytes(d_b))
                                  .op(V1.OP_CHECKSIG).bytes())])
            hp = TX.signature_hash(prev.vout[0].spk, pay, 0, TX.SIGHASH_ALL)
            pay.vin[0].script_sig = V1.Script().data(
                EC.sign(d_b, int.from_bytes(hp, "big"), 77) + b"\x01").bytes()
            check("%s control: beneficiary cannot take the funds before acceptance" % label,
                  not M.verify_signature(prev, pay, 0))
            forgery_controls(tm, prev, state, nxt, code, CV, label, expect_valid=False)
            code1 = CV1.build_code(tm, k, EC.pubkey_bytes(d_b))
            fund1 = TX.Tx(1, [TX.TxIn(b"\x00" * 32, 0xFFFFFFFF, b"\x01\x01")],
                          [TX.TxOut(VALUE, CV1.locking_script(state, code1))])
            forgery_controls(tm, fund1, state, nxt, code1, CV1, label, expect_valid=True)
        tx = spend(prev, nxt, code)
        ok = M.verify_signature(prev, tx, 0, tr)
        all_ok &= ok
        sizes.append(len(tx.vout[0].spk))
        if not ok:
            break
        prev, state, n = tx, nxt, n + 1
    secs = time.time() - t_start
    return code, prev, state, n, all_ok, sizes, tr, secs


def payout(prev, d_b, d_sign):
    pay = TX.Tx(1, [TX.TxIn(TX.txid(prev), 0)],
                [TX.TxOut(VALUE, V1.Script().data(EC.pubkey_bytes(d_b)).op(V1.OP_CHECKSIG)
                          .bytes())])
    hp = TX.signature_hash(prev.vout[0].spk, pay, 0, TX.SIGHASH_ALL)
    pay.vin[0].script_sig = V1.Script().data(
        EC.sign(d_sign, int.from_bytes(hp, "big"), 4242) + b"\x01").bytes()
    return M.verify_signature(prev, pay, 0)


D_B = 0xBEEF
abc = CV.abc_machine()
for word, expect in ((b"aabbcc", True), (b"aabbc", False), (b"abc", True), (b"aabcc", False)):
    st0 = (b"", word[1:], word[:1], abc.q0)
    code, last, st, n, ok, sizes, tr, secs = run_chain(abc, st0, 2, 400, D_B,
                                                       "a^k b^k c^k on %s" % word.decode(),
                                                       controls=(word == b"aabbcc"))
    ref = st0
    while ref[3] not in abc.halting:
        ref = abc.step(ref)
    check("covenant chain on %s: every transaction validates, %d transactions" %
          (word.decode(), n), ok)
    check("covenant chain on %s: final state equals the reference machine's" % word.decode(),
          st == ref, "state %s" % st[3].decode())
    accepted = st[3] == abc.acc
    check("covenant chain on %s: machine %s as membership requires" %
          (word.decode(), "accepts" if expect else "rejects"), accepted == expect)
    if accepted:
        check("covenant on %s: beneficiary spends after acceptance" % word.decode(),
              payout(last, D_B, D_B))
        check("covenant on %s: a different key cannot spend after acceptance" % word.decode(),
              not payout(last, D_B, D_B + 1))
    else:
        check("covenant on %s: beneficiary cannot spend after rejection" % word.decode(),
              not payout(last, D_B, D_B))
    used = sorted(tr.opcodes_used)
    out["runs"].append({"machine": abc.name, "input": word.decode(), "k": 2,
                        "transactions": n, "code_bytes": len(code),
                        "spk_bytes_first_last": [sizes[0], sizes[-1]] if sizes else [],
                        "final_state": st[3].decode(), "seconds": round(secs, 1),
                        "opcodes_used": used,
                        "disabled_in_2010_used": sorted(set(used) & DISABLED_2010)})

cnt = CV.counter_machine()
st0 = (b"", b"", b"_", cnt.q0)
code, last, st, n, ok, sizes, tr, secs = run_chain(cnt, st0, 4, 250, D_B, "binary counter")
ref = successor(cnt, st0, 4 * 250)
check("counter covenant: 250 consecutive transactions validate (1,000 machine steps)",
      ok and n == 250)
check("counter covenant: state after 250 transactions equals the reference machine's",
      st == ref)
tape = (st[0] + st[2] + st[1]).replace(b"_", b"")
value = int(tape[::-1].decode() or "0", 2)
check("counter covenant: tape holds a binary count and has grown",
      len(tape) >= 7 and value > 100, "count %d, %d bits" % (value, len(tape)))
used = sorted(tr.opcodes_used)
out["runs"].append({"machine": cnt.name, "input": "", "k": 4, "transactions": n,
                    "code_bytes": len(code), "spk_bytes_first_last": [sizes[0], sizes[-1]],
                    "count": value, "seconds": round(secs, 1), "opcodes_used": used,
                    "disabled_in_2010_used": sorted(set(used) & DISABLED_2010)})
check("covenant executes opcodes disabled on 15 August 2010",
      bool(set(used) & DISABLED_2010), ",".join(sorted(set(used) & DISABLED_2010)))

for f in ("script015_v01.py", "script015_v02.py", "secp256k1_v01.py", "tx015_v01.py",
          "constructions_v01.py", "covenant_v01.py", "covenant_v02.py",
          "run_covenant_checks_v02.py"):
    with open(os.path.join(HERE, f), "rb") as fh:
        out["files"][f] = hashlib.sha256(fh.read()).hexdigest()
out["python"] = sys.version
out["time_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
out["failures"] = failures
with open(os.path.join(HERE, "covenant_results_v02.json"), "w", encoding="utf-8") as fh:
    json.dump(out, fh, indent=1)
with open(os.path.join(HERE, "covenant_results_v02.txt"), "w", encoding="utf-8") as fh:
    for c in out["checks"]:
        fh.write(("PASS " if c["pass"] else "FAIL ") + c["name"]
                 + (" | " + c["detail"] if c["detail"] else "") + "\n")
    fh.write("\nfailures: %d\n" % failures)
print("\nfailures:", failures)
