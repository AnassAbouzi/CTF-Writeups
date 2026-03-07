#!/usr/bin/env python3
from __future__ import annotations

import argparse

from pwn import PIPE, context, log, process, remote

context.log_level = "info"

MASK64 = 0xFFFFFFFFFFFFFFFF
MAX_QUERIES = 1 << 16
RECORD_SIZE = 99  # 3 lines of 32 hex chars + '\n'
COL_START = 8
COL_END = 64

NROUNDS = 4
IV = 0x7372646E6C656E21
RC = [
    0x0000000000000073,
    0x0000000000000072,
    0x0000000000000064,
    0x000000000000006E,
    0x000000000000006C,
    0x0000000000000065,
    0x000000000000006E,
    0x0000000000000032,
    0x0000000000000030,
    0x0000000000000032,
    0x0000000000000036,
    0x0000000000000021,
]

TARGET_BIASES = {
    (0, 0): +0.155,
    (0, 1): -0.078,
    (1, 0): +0.101,
    (1, 1): -0.203,
}

UNDO_MIX_ROTS = [
    3,
    6,
    9,
    11,
    12,
    14,
    15,
    17,
    18,
    19,
    21,
    22,
    24,
    25,
    27,
    30,
    33,
    36,
    38,
    39,
    41,
    42,
    44,
    45,
    47,
    50,
    53,
    57,
    60,
    63,
]


def rrot(x: int, n: int) -> int:
    x &= MASK64
    return ((x >> n) | (x << (64 - n))) & MASK64


def permutation(state: list[int], r: int) -> None:
    state[2] ^= RC[r]

    state[0] ^= state[4]
    state[2] ^= state[1]
    state[4] ^= state[3]

    t0 = state[0] ^ ((~state[1] & MASK64) & state[2])
    t1 = state[1] ^ ((~state[2] & MASK64) & state[3])
    t2 = state[2] ^ ((~state[3] & MASK64) & state[4])
    t3 = state[3] ^ ((~state[4] & MASK64) & state[0])
    t4 = state[4] ^ ((~state[0] & MASK64) & state[1])

    state[0], state[1], state[2], state[3], state[4] = t0, t1, t2, t3, t4

    state[1] ^= state[0]
    state[3] ^= state[2]
    state[0] ^= state[4]
    state[2] = (~state[2]) & MASK64

    state[0] ^= rrot(state[0], 19) ^ rrot(state[0], 28)
    state[1] ^= rrot(state[1], 61) ^ rrot(state[1], 39)
    state[2] ^= rrot(state[2], 1) ^ rrot(state[2], 6)
    state[3] ^= rrot(state[3], 10) ^ rrot(state[3], 17)
    state[4] ^= rrot(state[4], 7) ^ rrot(state[4], 41)

    state[0] &= MASK64
    state[1] &= MASK64
    state[2] &= MASK64
    state[3] &= MASK64
    state[4] &= MASK64


def ascon(key: tuple[int, int], nonce: tuple[int, int]) -> tuple[int, int]:
    state = [IV, key[0], key[1], nonce[0], nonce[1]]
    for r in range(NROUNDS):
        permutation(state, r)
    return state[0], state[1]


def undo_mix(y: int) -> int:
    y &= MASK64
    acc = y
    for rot in UNDO_MIX_ROTS:
        acc ^= rrot(y, rot)
    return acc & MASK64


def classify_bias(bias: float) -> tuple[tuple[int, int], tuple[int, int], float, float]:
    ranked = sorted((abs(bias - target), pair) for pair, target in TARGET_BIASES.items())
    best_dist, best_pair = ranked[0]
    alt_dist, alt_pair = ranked[1]
    return best_pair, alt_pair, best_dist, (alt_dist - best_dist)


def set_pair_on_column(key0: int, key1: int, col: int, pair: tuple[int, int]) -> tuple[int, int]:
    bit = 1 << col
    if pair[0]:
        key0 |= bit
    else:
        key0 &= ~bit
    if pair[1]:
        key1 |= bit
    else:
        key1 &= ~bit
    return key0, key1


def verify_key(candidate: tuple[int, int], refs: list[tuple[tuple[int, int], tuple[int, int]]]) -> bool:
    for nonce, target in refs:
        if ascon(candidate, nonce) != target:
            return False
    return True


def u64_from_hex(buf: bytes, start: int) -> int:
    return int(buf[start : start + 16], 16)


def build_column_batch(col: int, samples_per_col: int) -> bytes:
    diff = 1 << col
    line = f"{diff:016x}{diff:016x}\n".encode()
    return line * samples_per_col


def recover_key(
    p,
    samples_per_col: int,
    tolerance: float,
    recv_timeout: float | None,
    uncertain_cols: int,
    verify_refs: int,
) -> tuple[int, int]:
    n_columns = COL_END - COL_START
    total_queries = n_columns * samples_per_col
    if total_queries + 1 > MAX_QUERIES:
        raise ValueError(
            f"Need {total_queries + 1} queries, max is {MAX_QUERIES}. Reduce --samples."
        )

    log.info("Running %d queries in %d column batches...", total_queries, n_columns)

    base_key0 = 0
    base_key1 = 0
    refs: list[tuple[tuple[int, int], tuple[int, int]]] = []
    columns: list[dict[str, object]] = []

    for col in range(COL_START, COL_END):
        p.send(build_column_batch(col, samples_per_col))
        raw = p.recvn(samples_per_col * RECORD_SIZE, timeout=recv_timeout)

        count_zero = 0
        pos = (col + 1) & 63
        off = 0

        for _ in range(samples_per_col):
            rec = raw[off : off + RECORD_SIZE]
            off += RECORD_SIZE

            if len(refs) < verify_refs:
                refs.append(
                    (
                        (u64_from_hex(rec, 0), u64_from_hex(rec, 16)),
                        (u64_from_hex(rec, 33), u64_from_hex(rec, 49)),
                    )
                )

            out1 = undo_mix(u64_from_hex(rec, 33))
            out2 = undo_mix(u64_from_hex(rec, 66))
            if ((out1 ^ out2) >> pos) & 1 == 0:
                count_zero += 1

        bias = (count_zero / samples_per_col) - 0.5
        best, alt, best_dist, margin = classify_bias(bias)
        if best_dist > tolerance:
            log.warning(
                "Column %d is ambiguous (distance %.4f, margin %.4f)", col, best_dist, margin
            )

        base_key0, base_key1 = set_pair_on_column(base_key0, base_key1, col, best)
        columns.append(
            {
                "col": col,
                "bias": bias,
                "best": best,
                "alt": alt,
                "best_dist": best_dist,
                "margin": margin,
            }
        )
        log.info(
            "Column %2d | bias = %+0.4f | best=%s alt=%s margin=%.4f",
            col,
            bias,
            best,
            alt,
            margin,
        )

    if not refs:
        raise RuntimeError("No reference sample captured")

    uncertain = sorted(columns, key=lambda c: (float(c["margin"]), float(c["best_dist"])))[:uncertain_cols]
    uncertain = [c for c in uncertain if c["best"] != c["alt"]]
    n_combos = 1 << len(uncertain)
    log.info("Bruteforcing low bits across %d high-bit profiles...", n_combos)

    primary_nonce, primary_out = refs[0]
    extra_refs = refs[1:]

    for mask in range(n_combos):
        high0 = base_key0
        high1 = base_key1
        for i, colinfo in enumerate(uncertain):
            pair = colinfo["best"] if ((mask >> i) & 1) == 0 else colinfo["alt"]
            high0, high1 = set_pair_on_column(high0, high1, int(colinfo["col"]), pair)

        for low16 in range(1 << 16):
            cand = (high0 | (low16 >> 8), high1 | (low16 & 0xFF))
            if ascon(cand, primary_nonce) == primary_out and verify_key(cand, extra_refs):
                if mask != 0:
                    log.warning("Recovered key using an alternate high-bit profile")
                return cand

    raise RuntimeError("No key candidate matched references; increase --samples")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Ascon lightweight challenge solver")
    parser.add_argument("--mode", choices=("remote", "local"), default="remote")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=1337)
    parser.add_argument("--binary", default="./server")
    parser.add_argument("--samples", type=int, default=1031)
    parser.add_argument("--tolerance", type=float, default=0.035)
    parser.add_argument("--recv-timeout", type=float, default=180.0)
    parser.add_argument("--uncertain-cols", type=int, default=8)
    parser.add_argument("--verify-refs", type=int, default=4)
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if args.mode == "local":
        log.info("Starting local process: %s", args.binary)
        p = process(args.binary, stdin=PIPE, stdout=PIPE, stderr=PIPE)
    else:
        log.info("Connecting to %s:%d", args.host, args.port)
        p = remote(args.host, args.port)

    try:
        key0, key1 = recover_key(
            p,
            args.samples,
            args.tolerance,
            args.recv_timeout,
            args.uncertain_cols,
            args.verify_refs,
        )

        p.sendline(b"00000000000000000000000000000000")
        guess = f"{key0:016x}{key1:016x}"
        p.sendline(guess.encode())
        log.info("Guessed key: %s", guess)

        reply = p.recvline().strip().decode(errors="replace")
        log.info(reply)
        if "Correct key!" in reply:
            flag = p.recvline().strip().decode(errors="replace")
            log.success("FLAG: %s", flag)
    finally:
        p.close()


if __name__ == "__main__":
    main()
