# Benchmark methodology and results

Numbers below were **actually measured** on the build machine that produced
v0.1.0, with the reproduction script and parameters included. Re-run them
yourself; expect different absolute numbers on different hardware, and
similar relative shape.

## Methodology

- Script: `scripts/benchmark.py` (shipped in the repository).
- Synthetic tree: N Python files (~S KB each, generated code-like text),
  10% carrying two planted synthetic credentials (AWS documentation example
  key + fake DB URL), sparse binary files, plus a `vendor/` directory.
- Working-tree scan (`no_git=True`), default configuration, in-process.
- Each result is the **median of 3 runs** on a fresh tree (temporary
  directory, cold cache per run).
- Findings verified non-zero so the scan does real rule work.

```
python scripts/benchmark.py --files 200 --size 2 --runs 3
python scripts/benchmark.py --files 2000 --size 4 --runs 3
```

## Results (v0.1.0, 2026-10-26)

Environment: sandboxed Linux container, 2 vCPUs, Python 3.12.15, default
settings (`workers=0` → 4 threads).

| Tree | Size | Findings | Median | Throughput |
|---|---|---|---|---|
| 200 files × ~2 KB | 0.4 MiB | 38 | 0.23 s | ~860 files/s |
| 2 000 files × ~4 KB | 7.5 MiB | 394 | 4.35 s | ~460 files/s, ~1.7 MiB/s |

Controlled observations from the same machine:

- **Worker count does not change wall time on this box** (1/2/4 threads
  within noise): content scanning is regex-bound and Python's GIL serialises
  it; with 2 vCPUs there is no spare core for parallel I/O. The thread pool
  exists for I/O overlap on larger machines and for future bounded
  parallelism, not as a CPU speedup.
- Larger files reduce files/s (per-line rule work dominates); MiB/s is the
  more stable metric across shapes.
- Binary files are detected in the 8 KiB head and skip content rules — they
  cost stat + read of the head only.

## Interpretation

A typical application repository (1 000–5 000 source files, < 50 MiB text)
scans in **single-digit seconds** on this modest hardware, which fits the
intended pre-release gate use (pre-push / CI per-PR). History scanning adds
time proportional to unique reachable blobs (deduplicated) and is intended
for scheduled runs.

## What we do NOT claim

- No comparison against other tools under matched conditions (would require
  running them here; see docs/comparison.md for feature-level comparison
  with sources instead).
- No production-repository measurements — the corpus is synthetic by
  design (no real code, no real secrets, reproducible by anyone).
- No memory-profiled numbers in v0.1.0 (budgets exist and are tested, but
  RSS was not recorded in this run).

If you benchmark AgentPreflight, include: hardware, Python version, command
line, repository shape (files/MiB), and whether history was scanned.
