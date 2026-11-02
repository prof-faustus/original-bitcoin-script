"""Constructions in the 0.1.5 opcode set.

1. compile_tm: a one-tape Turing machine M and a step bound T become a locking script
   that simulates T steps of M on the two stacks. The alt stack holds the tape to the left
   of the head; the main stack holds the head cell and the tape to its right, with the
   state on top. Only OP_DUP, OP_EQUAL, OP_IF, OP_ELSE, OP_ENDIF, OP_DROP, OP_TOALTSTACK,
   OP_FROMALTSTACK and constant pushes are used, none of which has been disabled in any
   Bitcoin client.

2. ackermann_lock: Ackermann's function by the explicit-stack algorithm, the recursion
   stack held on the alt stack with a sentinel, unrolled to a step bound.
"""

from script015_v01 import (Script, OP_DUP, OP_EQUAL, OP_IF, OP_ELSE, OP_ENDIF, OP_DROP,
                           OP_TOALTSTACK, OP_FROMALTSTACK, OP_1NEGATE, OP_NOT, OP_1ADD,
                           OP_1SUB, OP_OVER, OP_SWAP, OP_EQUALVERIFY, OP_1)

R, L, S = "R", "L", "S"


class TM:
    """Deterministic one-tape Turing machine; symbols and states are small integers."""

    def __init__(self, name, states, symbols, blank, delta, q0, q_acc, q_rej):
        self.name, self.states, self.symbols = name, states, symbols
        self.blank, self.delta, self.q0 = blank, delta, q0
        self.q_acc, self.q_rej = q_acc, q_rej

    def run(self, w, limit=10**7):
        """Reference run. Returns (accepted, steps)."""
        tape = dict(enumerate(w))
        head, q, steps = 0, self.q0, 0
        while q not in (self.q_acc, self.q_rej):
            a = tape.get(head, self.blank)
            q, b, d = self.delta.get((q, a), (self.q_rej, a, S))
            tape[head] = b
            head += 1 if d == R else -1 if d == L else 0
            steps += 1
            if steps > limit:
                raise RuntimeError("step limit")
        return q == self.q_acc, steps


def _step_block(tm):
    """One simulated step. Stack on entry and exit: [... right-part, head, state]."""
    s = Script()
    active = [q for q in tm.states if q not in (tm.q_acc, tm.q_rej)]
    for q in active:
        s.op(OP_DUP).num(q).op(OP_EQUAL).op(OP_IF)
        s.op(OP_DROP)                                   # [... right, head]
        for a in tm.symbols:
            s.op(OP_DUP).num(a).op(OP_EQUAL).op(OP_IF)
            q2, b, d = tm.delta.get((q, a), (tm.q_rej, a, S))
            s.op(OP_DROP).num(b)                        # write b in place of the head
            if d == R:
                s.op(OP_TOALTSTACK)                     # written cell joins the left part
            elif d == L:
                s.op(OP_FROMALTSTACK)                   # left neighbour becomes the head
            s.num(q2)
            s.op(OP_ELSE)
        s.num(q)                                        # unmatched symbol: restore state
        for _ in tm.symbols:
            s.op(OP_ENDIF)
        s.op(OP_ELSE)
    # halting state: configuration unchanged
    for _ in active:
        s.op(OP_ENDIF)
    return s


def compile_tm(tm, n, T):
    """Locking script deciding inputs of length n within T steps.

    The unlocking script pushes w_n, ..., w_1, so that w_1 is on top.
    """
    s = Script()
    for _ in range(n):                    # park the input on the alt stack
        s.op(OP_TOALTSTACK)
    for _ in range(T):                    # right padding beneath the input
        s.num(tm.blank)
    for _ in range(n):                    # input back, w_1 on top
        s.op(OP_FROMALTSTACK)
    for _ in range(T):                    # left padding on the alt stack
        s.num(tm.blank).op(OP_TOALTSTACK)
    s.num(tm.q0)
    block = _step_block(tm)
    for _ in range(T):
        s.extend(block)
    s.num(tm.q_acc).op(OP_EQUAL)
    return s.bytes()


def unlock_tm(w):
    s = Script()
    for a in reversed(w):
        s.num(a)
    return s.bytes()


# ------------------------------------------------------------------ machines
def tm_abc():
    """{ a^k b^k c^k : k >= 0 }, which no pushdown automaton recognises."""
    B, a, b, c, X, Y, Z = 0, 1, 2, 3, 4, 5, 6
    q0, q1, q2, q3, q4, acc, rej = 1, 2, 3, 4, 5, 6, 7
    d = {
        (q0, a): (q1, X, R), (q0, Y): (q4, Y, R), (q0, B): (acc, B, S),
        (q1, a): (q1, a, R), (q1, Y): (q1, Y, R), (q1, b): (q2, Y, R),
        (q2, b): (q2, b, R), (q2, Z): (q2, Z, R), (q2, c): (q3, Z, L),
        (q3, a): (q3, a, L), (q3, b): (q3, b, L), (q3, Y): (q3, Y, L),
        (q3, Z): (q3, Z, L), (q3, X): (q0, X, R),
        (q4, Y): (q4, Y, R), (q4, Z): (q4, Z, R), (q4, B): (acc, B, S),
    }
    return TM("a^k b^k c^k", [q0, q1, q2, q3, q4, acc, rej], [B, a, b, c, X, Y, Z], B,
              d, q0, acc, rej), [a, b, c], \
        lambda w: (len(w) % 3 == 0 and w == [a] * (len(w) // 3) + [b] * (len(w) // 3)
                   + [c] * (len(w) // 3))


def tm_pow2():
    """{ 0^(2^k) : k >= 0 }: halve by crossing off every other 0."""
    B, z, x = 0, 1, 2
    q1, q2, q3, q4, q5, acc, rej = 1, 2, 3, 4, 5, 6, 7
    d = {
        (q1, z): (q2, B, R),
        (q2, x): (q2, x, R), (q2, z): (q3, x, R), (q2, B): (acc, B, R),
        (q3, x): (q3, x, R), (q3, z): (q4, z, R), (q3, B): (q5, B, L),
        (q4, x): (q4, x, R), (q4, z): (q3, x, R), (q4, B): (rej, B, R),
        (q5, z): (q5, z, L), (q5, x): (q5, x, L), (q5, B): (q2, B, R),
    }

    def member(w):
        k = len(w)
        return k > 0 and (k & (k - 1)) == 0
    return TM("0^(2^k)", [q1, q2, q3, q4, q5, acc, rej], [B, z, x], B, d, q1, acc, rej), \
        [z], member


# ------------------------------------------------------------------ Ackermann
def ackermann(m, n):
    """Reference value and number of loop iterations of the explicit-stack algorithm."""
    st, steps = [m], 0
    while st:
        m = st.pop()
        steps += 1
        if m == 0:
            n += 1
        elif n == 0:
            st.append(m - 1)
            n = 1
        else:
            st.append(m - 1)
            st.append(m)
            n -= 1
    return n, steps


def _ack_block():
    """One iteration. Main: [r, n]. Alt: [-1 sentinel, ..., top]."""
    s = Script()
    s.op(OP_FROMALTSTACK)                              # [r n m]
    s.op(OP_DUP).op(OP_1NEGATE).op(OP_EQUAL).op(OP_IF)
    s.op(OP_TOALTSTACK)                                # sentinel back: finished
    s.op(OP_ELSE)
    s.op(OP_DUP).op(OP_NOT).op(OP_IF)                  # m == 0
    s.op(OP_DROP).op(OP_1ADD)                          #   n := n + 1
    s.op(OP_ELSE)
    s.op(OP_OVER).op(OP_NOT).op(OP_IF)                 # n == 0
    s.op(OP_1SUB).op(OP_TOALTSTACK)                    #   push m - 1
    s.op(OP_DROP).op(OP_1)                             #   n := 1
    s.op(OP_ELSE)                                      # otherwise
    s.op(OP_DUP).op(OP_1SUB).op(OP_TOALTSTACK)         #   push m - 1
    s.op(OP_TOALTSTACK)                                #   push m
    s.op(OP_1SUB)                                      #   n := n - 1
    s.op(OP_ENDIF).op(OP_ENDIF).op(OP_ENDIF)
    return s


def ackermann_lock(T):
    """Unlocking script pushes <r> <m> <n>. Valid iff the computation finishes within T
    iterations and its value equals r."""
    s = Script()
    s.op(OP_SWAP)                                      # [r n m]
    s.op(OP_1NEGATE).op(OP_TOALTSTACK)                 # sentinel
    s.op(OP_TOALTSTACK)                                # m onto the recursion stack
    block = _ack_block()
    for _ in range(T):
        s.extend(block)
    s.op(OP_FROMALTSTACK).op(OP_1NEGATE).op(OP_EQUALVERIFY)   # must have finished
    s.op(OP_EQUAL)                                     # r == n
    return s.bytes()


def ackermann_unlock(r, m, n):
    return Script().num(r).num(m).num(n).bytes()
