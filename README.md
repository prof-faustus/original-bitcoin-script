# Original Bitcoin Script

**An executable model of the Bitcoin Script interpreter as shipped in version 0.1.5, with
machine-checked constructions establishing its computational class.**

Craig Steven Wright · ORCID [0000-0001-9374-0507](https://orcid.org/0000-0001-9374-0507) ·
University of Exeter Business School

---

## Summary

The evaluator in this repository is a line-by-line port of `EvalScript`, `VerifySignature`,
`SignatureHash` and `CBigNum` from the earliest source in the official repository
([bitcoin/bitcoin](https://github.com/bitcoin/bitcoin) commit `e071a3f6c06f`, 30 August 2009,
version 0.1.5). Against that model, four results are constructed and checked mechanically:

1. **Every evaluation terminates.** No operation moves the instruction pointer backwards, so
   one evaluation is a decision procedure — what the source itself describes as "a stack
   machine (like Forth) that evaluates a predicate returning a bool… There are no loops."
2. **Any Turing machine runs on the two stacks.** A compiler maps a one-tape machine *M* and a
   step bound *T* to a script of size linear in *T* that simulates *M* exactly: the alternate
   stack holds the tape left of the head, the main stack the head and the tape to its right.
   It uses no arithmetic, only `OP_DUP OP_EQUAL OP_IF OP_ELSE OP_ENDIF OP_DROP OP_TOALTSTACK
   OP_FROMALTSTACK` and constants — none of which has ever been disabled. Checked on a decider
   for {aᵏbᵏcᵏ}, a language no pushdown automaton recognises, and on unary powers of two.
3. **Ackermann's function**, which is total and computable but not primitive recursive, is
   computed with the alternate stack as its recursion stack, for every *A*(*m*, *n*) with
   *m* ≤ 3 and *n* ≤ 4, up to *A*(3, 4) = 125 in 10,307 iterations.
4. **One fixed locking script carries a Turing machine across a chain of transactions, with
   every step enforced by transaction validation.** The script advances the machine *k* steps
   on a tape of unbounded length using the splice operations, requires the transaction fields
   it is given to have their serialised widths, reconstructs the signature-hash
   preimage of the spending transaction with the successor state in its single output, signs
   that preimage inside the script with 256-bit modular arithmetic, and verifies the signature
   with `OP_CHECKSIGVERIFY`. The signature verifies only if the reconstructed preimage is the
   preimage of the actual spending transaction. A binary counter that never halts was carried
   through **250 consecutive transactions (1,000 machine steps)**; a decider for {aᵏbᵏcᵏ} was
   carried to acceptance or rejection, with funds released only on acceptance. A wrong
   successor state, a single altered tape cell, a second output, substituted code, a misstated
   transaction field, a premature payout, and three spends forged by cutting the real preimage
   of a different transaction into fields of other widths are each rejected.

Result 4 requires `OP_CAT`, `OP_SUBSTR`, `OP_LEFT`, `OP_RIGHT` and `OP_MOD` on 256-bit
operands — operations present in the 0.1.5 interpreter and disabled on 15 August 2010.

---

## Reproducing every result

Requires Python 3.8 or later and nothing else.

```
python run_checks_v01.py            # results 1–3: 150 checks
python run_covenant_checks_v02.py   # result 4 and the transaction model: 56 checks
python fetch_sources.py             # fetch and hash-verify the original source files
```

Each run ends with `failures: 0` and writes its results (`results_v01.*`,
`covenant_results_v02.*`), including the SHA-256 of every source file that produced them.
Every check is able to fail; the negative controls are listed below.

`covenant_v01.py`, `run_covenant_checks_v01.py` and `covenant_results_v01.*` are kept as
released in version 1.0.0. The covenant of version 1.0.0 (`covenant_v01.py`) does not test the
widths of the fields it is given, and a spender can supply fields of other widths whose
concatenation equals the preimage of a different transaction; `run_covenant_checks_v02.py`
builds three such spends and records that they validate against `covenant_v01.py` and are
refused by `covenant_v02.py`.

---

## Results

### Fidelity of the model

| Check | Outcome |
|---|---|
| Opcode numbering against 20 independently published values | all agree |
| `CBigNum` encoding against known vectors; round trip −70,000…70,000 and 3⁴⁰⁰ | exact |
| The 2010 defect: unlocking script `OP_1 OP_RETURN` satisfies an arbitrary locking script | reproduced, as a model of 0.1.5 must |
| 201-bit × 159-bit `OP_MUL`; `OP_CAT` | exact |
| secp256k1: *G* on the curve; *n*·*G* = ∞; sign/verify; wrong digest; wrong key | as required |
| Pay-to-public-key spend: honest signature validates, wrong key fails | as required |
| Transaction-aware evaluator agrees with the plain evaluator on all 243 inputs of length 5 | agrees |

### Two-stack simulation (result 2)

| Language | *n* | inputs | mode | steps *T* | script bytes | max main | max alt |
|---|---|---|---|---|---|---|---|
| aᵏbᵏcᵏ | 5 | 243 | exhaustive | 14 | 5,235 | 22 | 19 |
| aᵏbᵏcᵏ | 7 | 2,187 | exhaustive | 26 | 9,715 | 36 | 33 |
| aᵏbᵏcᵏ | 9 | 352 | all sorted forms + 300 random | 46 | 17,179 | 58 | 55 |
| aᵏbᵏcᵏ | 15 | 436 | all sorted forms + 300 random | 116 | 43,301 | 134 | 131 |
| 0^(2^k) | 32 | 1 | — | 353 | 67,490 | 388 | 386 |
| 0^(2^k) | 128 | 1 | — | 1,921 | 367,170 | 2,052 | 2,050 |

Lengths 0–7 of aᵏbᵏcᵏ are exhaustive, and every length 0–40, 64 and 128 of 0^(2^k) is checked.
At every length the script, the reference machine and the membership predicate agree on every
input. Controls: for every length with an accepted input, the script built one step short
rejects the slowest accepted input; a machine with two transitions altered is detected (5 of 243
inputs disagree at *n* = 5).

### Ackermann's function (result 3)

| (*m*, *n*) | *A*(*m*, *n*) | iterations | script bytes | alt-stack depth |
|---|---|---|---|---|
| (2, 3) | 9 | 44 | 1,284 | 9 |
| (3, 2) | 29 | 541 | 15,697 | 29 |
| (3, 3) | 61 | 2,432 | 70,536 | 61 |
| (3, 4) | 125 | 10,307 | 298,911 | 125 |

All twenty pairs 0 ≤ *m* ≤ 3, 0 ≤ *n* ≤ 4 are accepted with the correct value, rejected with
the value plus one, and rejected with one iteration fewer.

### The covenant chain (result 4)

| Machine | input | steps per transaction | transactions | locking-script code | outcome |
|---|---|---|---|---|---|
| aᵏbᵏcᵏ decider | `aabbcc` | 2 | 12 | 2,491 bytes | accepts; beneficiary paid; other keys refused |
| aᵏbᵏcᵏ decider | `abc` | 2 | 4 | 2,491 bytes | accepts; beneficiary paid; other keys refused |
| aᵏbᵏcᵏ decider | `aabbc` | 2 | 7 | 2,491 bytes | rejects; payout refused |
| aᵏbᵏcᵏ decider | `aabcc` | 2 | 5 | 2,491 bytes | rejects; payout refused |
| binary counter (never halts) | — | 4 | 250 | 1,823 bytes | count 254 after 1,000 steps |

In every run the final state equals the reference machine's. The locking-script code is the
same in every output; only the encoded state changes. Controls, each rejected: a successor with
the wrong machine state; a successor with one tape cell altered; a second output; an unlocking
script supplying different code; a misstated transaction field; a payout before acceptance; and
three forged spends (a second output, a successor carrying the code `OP_1`, the covenant as the
second of two inputs), each built by searching every cut of the real preimage into the fields
`CODE` concatenates. The same three forged spends validate against `covenant_v01.py`, which has
no width test, so the controls can fail.

**How the covenant works.** The locking script is `PUSHDATA4(U) PUSHDATA4(V) PUSHDATA4(h)
PUSHDATA4(q) CODE`, the state being the tape left of the head, the tape right of the head, the
head symbol and the machine state. The unlocking script supplies the transaction's free fields
(version, outpoint, sequence, value, lock time) and `CODE`. `CODE` first requires those five
fields to be 4, 36, 4, 8 and 4 bytes long, so that the preimage it assembles can be read as a
transaction in one way only; it then re-encodes the current state, runs *k* steps — each a constant number of splice operations, whatever the tape length —
encodes the successor, and assembles the 0.1.5 `SIGHASH_ALL` preimage of a one-input,
one-output transaction whose output is the successor state followed by `CODE`. It hashes the
preimage with `OP_HASH256`, reverses the digest into a number *z*, computes
*s* = (*z* + *G*ₓ) mod *n* — an ECDSA signature under private key 1 with nonce 1, both public —
builds the DER encoding, and checks it with `OP_CHECKSIGVERIFY` against the public key *G*.
Because the interpreter computes the true signature hash of the spending transaction, the check
passes only if the reconstructed preimage is that transaction's: one input, the same `CODE`,
and exactly one output carrying the correct successor. Publishing the key and the nonce costs
nothing: the script computes the signature itself from the preimage it is given, so the check
can pass only when that preimage is the true one.

---

## Provenance

| Commit | Date | Author | What it shows |
|---|---|---|---|
| `e071a3f6c06f` | 30 Aug 2009 | sirius-m (SVN trunk@1) | the 0.1.5 interpreter modelled here: no size limits; arbitrary-precision arithmetic; `OP_CAT`, `OP_SUBSTR`, `OP_MUL`, `OP_MOD`, shifts live; template matching only in wallet code |
| `dd519206a684` | 29 Oct 2009 | Nakamoto | time-based `nLockTime` ("implemented in 0.1.6"); blocks containing a non-final transaction rejected once the chain passes height 31,000 |
| `757f0769d836` | 29 Jul 2010 | Nakamoto | 0.3.6: `OP_RETURN` fails the script; size limits in force (script 20,000 bytes; push 5,000; numbers 258 bytes; stack 1,000) |
| `6ff5f718b6a6` | 31 Jul 2010 | Nakamoto | 0.3.7: right-shift fault guarded; script 10,000 bytes; 201 non-push operations; separate evaluation of the two scripts |
| `4bd188c4383d` | 15 Aug 2010 | Nakamoto | fifteen opcodes temporarily disabled (`OP_CAT OP_SUBSTR OP_LEFT OP_RIGHT OP_INVERT OP_AND OP_OR OP_XOR OP_2MUL OP_2DIV OP_MUL OP_DIV OP_MOD OP_LSHIFT OP_RSHIFT`), their code kept behind the gate; numbers 4 bytes; pushes 520 bytes |
| `a206a23980c1` | 7 Dec 2010 | Andresen | `IsStandard()` applied when accepting transactions to the memory pool |

`fetch_sources.py` retrieves every one of these files from the official repository and checks
its SHA-256.

The BSV node restored the disabled operations in stages, documented in its protocol
specifications ([bitcoin-sv-specs/protocol](https://github.com/bitcoin-sv-specs/protocol),
`updates/`): `OP_CAT`, `OP_AND`, `OP_OR`, `OP_XOR`, `OP_DIV`, `OP_MOD` (May 2018, in the chain
from which BSV separated in November 2018); `OP_MUL`,
`OP_INVERT`, `OP_LSHIFT`, `OP_RSHIFT` (November 2018); removal of the script-size, element-size,
stack-size and operation-count limits, the original `OP_RETURN`, and the original purpose of
`nLockTime` and `nSequence` (Genesis, 2020); `OP_SUBSTR`, `OP_LEFT`, `OP_RIGHT`, `OP_2MUL`,
`OP_2DIV`, `OP_VER`, `OP_VERIF`, `OP_VERNOTIF` and the original transaction digest algorithm
(Chronicle, BSV node 1.2.0, January 2026).

---

## Scope of the model

Modelled exactly: every opcode of 0.1.5, including the signature operations with the 0.1.5
`SignatureHash` (all hash types), `FindAndDelete`, compact-size serialisation, and the
concatenated evaluation of `scriptSig ‖ OP_CODESEPARATOR ‖ scriptPubKey`; `CBigNum` encoding.

Not modelled: block assembly, proof of work, the memory pool, and lock-time finality (the
covenant transactions are final); OpenSSL's tolerance of non-DER signature encodings (the model
parses strict DER, and every signature produced here is strict DER); behaviour that is undefined
in the C++ source (`OP_2DROP` on fewer than two items, and out-of-range stack access), which
the model reports as an exception and which no construction reaches. `OP_RIPEMD160` and
`OP_HASH160` use the RIPEMD-160 of the local Python's OpenSSL; no check here executes either.

---

## Files

| File | Contents |
|---|---|
| `script015_v01.py` | the 0.1.5 evaluator without transaction context; opcode table with anchors |
| `script015_v02.py` | the same evaluator with transaction context and signature operations |
| `tx015_v01.py` | 0.1.5 transaction serialisation, `FindAndDelete`, `SignatureHash` |
| `secp256k1_v01.py` | secp256k1 ECDSA as OpenSSL performs it for 0.1.5 |
| `constructions_v01.py` | Turing-machine compiler (two stacks); Ackermann on the alternate stack |
| `covenant_v02.py` | the covenant locking script, with the field-width test, and the machines it carries |
| `covenant_v01.py` | the covenant of version 1.0.0, without the field-width test (kept for the controls) |
| `run_checks_v01.py`, `run_covenant_checks_v02.py` | every check, with controls |
| `results_v01.*`, `covenant_results_v02.*` | results of the runs committed here |
| `run_covenant_checks_v01.py`, `covenant_results_v01.*` | the covenant checks and results of version 1.0.0 |
| `fetch_sources.py` | retrieval and verification of the original sources |

## Licence

MIT. The evaluator, serialisation and signature-hash code are ports of the Bitcoin 0.1.5 source,
Copyright (c) 2009–2010 Satoshi Nakamoto, MIT/X11 licence. See `LICENSE`.
