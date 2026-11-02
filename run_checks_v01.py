"""Checks for the appendix. Every check reports PASS or FAIL and can fail.

Run from this directory:  python run_checks_v01.py
Writes results_v01.json and results_v01.txt beside this file.
"""

import hashlib
import itertools
import json
import os
import random
import sys
import time

import script015_v01 as S
import constructions_v01 as C

HERE = os.path.dirname(os.path.abspath(__file__))
results = {"checks": [], "tm": [], "ackermann": [], "files": {}}
failures = 0


def check(name, cond, detail=""):
    global failures
    results["checks"].append({"name": name, "pass": bool(cond), "detail": detail})
    if not cond:
        failures += 1
    print(("PASS " if cond else "FAIL ") + name + (" | " + detail if detail else ""))


# ----------------------------------------------------------- 1. number encoding
vectors = {0: "", 1: "01", -1: "81", 127: "7f", 128: "8000", -128: "8080", 255: "ff00",
           256: "0001", -256: "0081", 32767: "ff7f", 32768: "008000", -32768: "008080"}
ok = all(S.bn_getvch(k).hex() == v for k, v in vectors.items())
check("CBigNum getvch matches known little-endian sign-magnitude vectors", ok)
ok = all(S.bn_from_vch(S.bn_getvch(k)) == k for k in range(-70000, 70001))
check("CBigNum round trip for -70000..70000", ok)
big = 3**400
check("CBigNum has no size bound (3^400 round trip)",
      S.bn_from_vch(S.bn_getvch(big)) == big and S.bn_from_vch(S.bn_getvch(-big)) == -big)

# ----------------------------------------------------------- 2. historical behaviour
# The 0.1.5 evaluator ran scriptSig + OP_CODESEPARATOR + scriptPubKey as one script and
# OP_RETURN ended evaluation, so an unlocking script "OP_1 OP_RETURN" satisfied any
# locking script. The model must reproduce this or it is not the 0.1.5 evaluator.
p2pkh_like = S.Script().op(S.OP_DUP).op(S.OP_HASH160).data(bytes(20)) \
    .op(S.OP_EQUALVERIFY).op(S.OP_CHECKSIG).bytes()
check("0.1.5 model reproduces the OP_1 OP_RETURN acceptance defect",
      S.verify(bytes([S.OP_1, S.OP_RETURN]), p2pkh_like) is True)
check("an empty unlocking script does not satisfy the same locking script",
      S.verify(b"", S.Script().op(S.OP_0).bytes()) is False)

# arbitrary-precision arithmetic, live in 0.1.5
mul = S.Script().data(S.bn_getvch(2**200)).data(S.bn_getvch(3**100)).op(S.OP_MUL) \
    .data(S.bn_getvch(2**200 * 3**100)).op(S.OP_EQUAL).bytes()
check("OP_MUL on 200-bit and 159-bit operands is exact in the 0.1.5 model",
      S.eval_script(mul)[0] is True)
cat = S.Script().data(b"ab").data(b"cd").op(S.OP_CAT).data(b"abcd").op(S.OP_EQUAL).bytes()
check("OP_CAT concatenates in the 0.1.5 model", S.eval_script(cat)[0] is True)

NEVER_DISABLED = {"OP_DUP", "OP_EQUAL", "OP_IF", "OP_ELSE", "OP_ENDIF", "OP_DROP",
                  "OP_TOALTSTACK", "OP_FROMALTSTACK", "OP_1NEGATE", "OP_NOT", "OP_1ADD",
                  "OP_1SUB", "OP_OVER", "OP_SWAP", "OP_EQUALVERIFY", "OP_CODESEPARATOR",
                  "OP_1", "OP_2", "OP_3", "OP_4", "OP_5", "OP_6", "OP_7", "OP_8", "OP_9",
                  "OP_10", "OP_11", "OP_12", "OP_13", "OP_14", "OP_15", "OP_16"}


# ----------------------------------------------------------- 3. Turing machines
def tm_case(tm, sigma, member, lengths_exhaustive, lengths_sampled, sample, seed):
    rng = random.Random(seed)
    for n in lengths_exhaustive + lengths_sampled:
        if n in lengths_exhaustive:
            inputs = [list(w) for w in itertools.product(sigma, repeat=n)]
            mode = "exhaustive"
        else:
            sorted_forms = set()
            for cut in itertools.combinations_with_replacement(range(n + 1), len(sigma) - 1):
                bounds = (0,) + cut + (n,)
                w = []
                for i, a in enumerate(sigma):
                    w += [a] * (bounds[i + 1] - bounds[i])
                sorted_forms.add(tuple(w))
            rand = {tuple(rng.choice(sigma) for _ in range(n)) for _ in range(sample)}
            inputs = [list(w) for w in sorted(sorted_forms | rand)]
            mode = "sorted forms + %d random" % sample
        steps = [tm.run(w)[1] for w in inputs]
        T = max(steps)
        lock = C.compile_tm(tm, n, T)
        agree, accepted, worst = 0, 0, None
        tr = S.Trace()
        for w, st in zip(inputs, steps):
            got = S.verify(C.unlock_tm(w), lock, tr)
            ref = tm.run(w)[0]
            want = member(w)
            if got == ref == want:
                agree += 1
            accepted += want
            if want and (worst is None or st > worst[1]):
                worst = (w, st)
        row = {"machine": tm.name, "n": n, "mode": mode, "inputs": len(inputs),
               "agree": agree, "accepted": accepted, "T": T,
               "lock_bytes": len(lock), "max_main": tr.max_main, "max_alt": tr.max_alt,
               "max_if_depth": tr.max_ifdepth,
               "opcodes_used": sorted(tr.opcodes_used)}
        results["tm"].append(row)
        check("%s n=%d: script = reference TM = membership on all %d inputs (%s)"
              % (tm.name, n, len(inputs), mode), agree == len(inputs),
              "T=%d, %d bytes" % (T, len(lock)))
        check("%s n=%d: only never-disabled opcodes executed" % (tm.name, n),
              set(tr.opcodes_used) <= NEVER_DISABLED, ",".join(sorted(tr.opcodes_used)))
        # control: one step short must lose the slowest accepted input
        if worst is not None and worst[1] >= 1:
            w, st = worst
            short = C.compile_tm(tm, n, st - 1)
            check("%s n=%d control: T-1 steps rejects the slowest accepted input"
                  % (tm.name, n), S.verify(C.unlock_tm(w), short) is False)


tm, sigma, member = C.tm_abc()
tm_case(tm, sigma, member, [0, 1, 2, 3, 4, 5, 6, 7], [9, 12, 15], 300, 1)
tm2, sigma2, member2 = C.tm_pow2()
tm_case(tm2, sigma2, member2, list(range(0, 41)) + [64, 128], [], 0, 2)

# control: a mutated machine must be caught by the same comparison
bad = C.TM(tm.name + " (mutated)", tm.states, tm.symbols, tm.blank,
           dict(tm.delta), tm.q0, tm.q_acc, tm.q_rej)
bad.delta[(4, 3)] = (4, 3, "L")  # q3 on c: move left instead of rejecting (harmless)
bad.delta[(3, 0)] = (6, 0, "S")  # q2 on blank: accept instead of reject
n = 5
inputs = [list(w) for w in itertools.product(sigma, repeat=n)]
T = max(max(tm.run(w)[1] for w in inputs), max(bad.run(w)[1] for w in inputs))
lock_bad = C.compile_tm(bad, n, T)
mismatch = sum(S.verify(C.unlock_tm(w), lock_bad) != member(w) for w in inputs)
check("control: mutated a^k b^k c^k machine disagrees with membership", mismatch > 0,
      "%d of %d inputs" % (mismatch, len(inputs)))

# ----------------------------------------------------------- 4. Ackermann
for m in range(4):
    for n in range(5):
        val, steps = C.ackermann(m, n)
        lock = C.ackermann_lock(steps)
        tr = S.Trace()
        good = S.verify(C.ackermann_unlock(val, m, n), lock, tr)
        wrong = S.verify(C.ackermann_unlock(val + 1, m, n), lock)
        short = S.verify(C.ackermann_unlock(val, m, n), C.ackermann_lock(steps - 1)) \
            if steps > 1 else False
        results["ackermann"].append({"m": m, "n": n, "A": val, "T": steps,
                                     "lock_bytes": len(lock), "valid": good,
                                     "wrong_value_rejected": not wrong,
                                     "short_T_rejected": not short,
                                     "max_alt": tr.max_alt,
                                     "opcodes_used": sorted(tr.opcodes_used)})
        check("Ackermann A(%d,%d)=%d verified in %d unrolled iterations" % (m, n, val, steps),
              good and not wrong and not short and set(tr.opcodes_used) <= NEVER_DISABLED,
              "%d bytes, alt depth %d" % (len(lock), tr.max_alt))

# ----------------------------------------------------------- provenance
for f in ("script015_v01.py", "constructions_v01.py", "run_checks_v01.py"):
    with open(os.path.join(HERE, f), "rb") as fh:
        results["files"][f] = hashlib.sha256(fh.read()).hexdigest()
results["python"] = sys.version
results["time_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
results["failures"] = failures
with open(os.path.join(HERE, "results_v01.json"), "w", encoding="utf-8") as fh:
    json.dump(results, fh, indent=1)
with open(os.path.join(HERE, "results_v01.txt"), "w", encoding="utf-8") as fh:
    for c in results["checks"]:
        fh.write(("PASS " if c["pass"] else "FAIL ") + c["name"]
                 + (" | " + c["detail"] if c["detail"] else "") + "\n")
    fh.write("\nfailures: %d\n" % failures)
print("\nfailures:", failures)
