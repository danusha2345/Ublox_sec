#!/usr/bin/env python3
"""
bkz_farm_attack.py
Одним процессом запускает несколько (по умолчанию 10) параллельных рабочих BKZ,
каждому выдаёт свою случайную подвыборку и расписание блоков.
Использует multiprocessing → все ядра будут заняты даже с однопоточной BKZ.

Пример:
  python bkz_farm_attack.py --workers 10 --top 200 --blocks 42,44,46 --loops 30 --runs 1

Каждый воркер логирует прогресс в stdout со своим worker_id.
"""

import argparse
import csv
import multiprocessing as mp
import os
import random
import time
from datetime import datetime

from ecdsa.curves import NIST192p
from fpylll import IntegerMatrix, LLL, BKZ

ORDER = NIST192p.order


def load_sigs(path):
    sigs = []
    with open(path, "r") as f:
        r = csv.DictReader(f)
        for row in r:
            sigs.append(
                {
                    "r": int(row["r"]),
                    "s": int(row["s"]),
                    "z": int(row["z"]),
                    "r_bits": int(row["r_bits"]),
                }
            )
    sigs.sort(key=lambda x: x["r_bits"])
    return sigs


def build_matrix(sigs, weighted=True):
    m = len(sigs)
    min_rbits = min(s["r_bits"] for s in sigs)
    B = 2 ** min_rbits

    def inv(a, n):
        return pow(a, -1, n)

    t = []
    u = []
    for s in sigs:
        sinv = inv(s["s"], ORDER)
        t.append((sinv * s["r"]) % ORDER)
        u.append((sinv * s["z"]) % ORDER)

    M = IntegerMatrix(m + 2, m + 2)
    for i in range(m):
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


def worker(job):
    (wid, sigs, blocks, loops, weighted) = job
    ts = lambda: datetime.now().strftime("%H:%M:%S")

    M, B, min_rbits = build_matrix(sigs, weighted=weighted)
    print(f"[{ts()}][W{wid}] start LLL, m={len(sigs)}, min_rbits={min_rbits}")
    LLL.reduction(M)

    for blk in blocks:
        start = time.time()
        print(f"[{ts()}][W{wid}] BKZ block={blk} loops={loops}")
        BKZ.reduction(M, BKZ.Param(block_size=blk, max_loops=loops))
        print(f"[{ts()}][W{wid}] done block={blk} in {(time.time()-start)/60:.2f} min")
        cand = find_candidate(M, B)
        if cand:
            print(f"[{ts()}][W{wid}] FOUND d={hex(cand)}")
            return cand
    print(f"[{ts()}][W{wid}] no candidate")
    return None


def main():
    ap = argparse.ArgumentParser(description="Farm multiple BKZ workers with random subsets.")
    ap.add_argument("--csv", default="sigs_new.csv")
    ap.add_argument("--workers", type=int, default=10)
    ap.add_argument("--top", type=int, default=200, help="Pool size to sample from")
    ap.add_argument("--subset", type=int, default=120, help="Subset per worker")
    ap.add_argument("--blocks", default="42,44,46")
    ap.add_argument("--loops", type=int, default=30)
    ap.add_argument("--runs", type=int, default=1, help="How many waves of workers to launch")
    ap.add_argument("--no-weight", action="store_true", help="Disable per-signature bounds")
    ap.add_argument("--threads", type=int, default=None, help="Set OMP/BLAS threads for each worker")
    args = ap.parse_args()

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

    sigs_all = load_sigs(args.csv)[: args.top]
    blocks = [int(x) for x in args.blocks.split(",") if x.strip()]

    for wave in range(args.runs):
        jobs = []
        for wid in range(args.workers):
            subset = random.sample(sigs_all, min(args.subset, len(sigs_all)))
            jobs.append((wid + wave * args.workers, subset, blocks, args.loops, not args.no_weight))
        with mp.Pool(processes=args.workers) as pool:
            res = pool.map(worker, jobs)
        if any(res):
            break


if __name__ == "__main__":
    main()
