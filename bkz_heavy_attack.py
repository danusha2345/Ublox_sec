#!/usr/bin/env python3
"""
Heavy BKZ lattice attack with progress indication.

Designed to run long (hours) with a sequence of BKZ block sizes.
Prints status before/after each BKZ call so it is clear the job is alive.

Usage:
  python bkz_heavy_attack.py [--csv sigs_new.csv] [--top 200]
                             [--blocks 30,32,34,36] [--loops 2]

Defaults: top=200 best-biased signatures, blocks 30→36 step 2, 2 loops each.
"""

import argparse
import csv
import math
import os
import time
from datetime import datetime
from ecdsa.curves import NIST192p

ORDER = NIST192p.order


def load_signatures(path: str):
    sigs = []
    with open(path, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            sigs.append(
                {
                    "r": int(row["r"]),
                    "s": int(row["s"]),
                    "z": int(row["z"]),
                    "r_bits": int(row["r_bits"]),
                }
            )
    sigs.sort(key=lambda x: x["r_bits"])  # strongest leak first
    return sigs


def inv(a, n):
    return pow(a, -1, n)


def build_matrix(sigs, weighted=True):
    from fpylll import IntegerMatrix
    m = len(sigs)
    min_rbits = min(s["r_bits"] for s in sigs)
    B = 2 ** min_rbits

    t = []
    u = []
    for s in sigs:
        sinv = inv(s["s"], ORDER)
        t.append((sinv * s["r"]) % ORDER)
        u.append((sinv * s["z"]) % ORDER)

    M = IntegerMatrix(m + 2, m + 2)
    for i in range(m):
        # индивидуальный bound: 2^{r_bits_i}
        Bi = 2 ** sigs[i]["r_bits"] if weighted else B
        M[i, i] = Bi * ORDER
        M[m, i] = t[i] * Bi
        M[m + 1, i] = u[i] * Bi
    M[m, m] = 1
    M[m + 1, m + 1] = B

    return M, B, min_rbits


def find_candidate(M, B):
    m = M.ncols - 2
    for i in range(M.nrows):
        row = M[i]
        last = row[m + 1]
        if abs(abs(last) - B) > B // 10:
            continue
        d = row[m]
        if last < 0:
            d = -d
        d %= ORDER
        if d == 0:
            continue
        return int(d)
    return None


def run_attack(sigs, blocks, loops, weighted=True):
    # импортируем fpylll после установки env (см. main)
    from fpylll import IntegerMatrix, LLL, BKZ
    M, B, min_rbits = build_matrix(sigs, weighted=weighted)
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Matrix size: {M.nrows}x{M.ncols}, min r_bits={min_rbits}, B=2^{min_rbits}")

    print(f"[{datetime.now().strftime('%H:%M:%S')}] LLL...")
    LLL.reduction(M)

    start = time.time()
    for blk in blocks:
        print(f"[{datetime.now().strftime('%H:%M:%S')}] BKZ block={blk}, loops={loops} ...")
        before = time.time()
        params = BKZ.Param(block_size=blk, max_loops=loops)
        BKZ.reduction(M, params)
        elapsed = time.time() - before
        total = time.time() - start
        print(f"[{datetime.now().strftime('%H:%M:%S')}] done block={blk} in {elapsed/60:.2f} min (total {total/60:.2f} min)")

        cand = find_candidate(M, B)
        if cand:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] [!] Candidate private key: {hex(cand)}")
            return cand

    print(f"[{datetime.now().strftime('%H:%M:%S')}] [ ] No candidate found in provided BKZ schedule.")
    return None


def main():
    parser = argparse.ArgumentParser(description="Heavy BKZ lattice attack with progress output")
    parser.add_argument("--csv", default="sigs_new.csv", help="CSV with r,s,z,r_bits")
    parser.add_argument("--top", type=int, default=200, help="Take top-N most biased signatures")
    parser.add_argument(
        "--blocks",
        default="30,32,34,36",
        help="Comma-separated BKZ block sizes to run in sequence",
    )
    parser.add_argument("--loops", type=int, default=2, help="BKZ max_loops for each block")
    parser.add_argument("--no-weight", action="store_true", help="Disable per-signature bounds (use uniform B)")
    parser.add_argument("--threads", type=int, default=None, help="Force thread count (sets OMP/BLAS env vars)")

    args = parser.parse_args()

    if args.threads:
        for var in [
            "OMP_NUM_THREADS",
            "OPENBLAS_NUM_THREADS",
            "MKL_NUM_THREADS",
            "NUMEXPR_NUM_THREADS",
            "VECLIB_MAXIMUM_THREADS",
            "BLIS_NUM_THREADS",
        ]:
            os.environ[var] = str(args.threads)
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Threads forced to {args.threads} (OMP/BLAS)")

    sigs = load_signatures(args.csv)
    sigs = sigs[: args.top]
    blocks = [int(x) for x in args.blocks.split(",") if x.strip()]

    print(f"[+] Loaded {len(sigs)} signatures, r_bits range {sigs[0]['r_bits']}..{sigs[-1]['r_bits']}")
    print(f"[+] BKZ schedule: blocks={blocks}, loops={args.loops}")

    run_attack(sigs, blocks, args.loops, weighted=not args.no_weight)


if __name__ == "__main__":
    main()
