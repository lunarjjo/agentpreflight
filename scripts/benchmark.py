"""Reproducible benchmark for AgentPreflight.

Generates synthetic repositories of parameterised size (with and without
planted secrets), runs the engine in-process, and reports throughput.

Usage:
    python scripts/benchmark.py [--files N] [--size KB] [--runs N]

Methodology (documented in docs/benchmark.md):
- synthetic tree: N files of ~S KB each, 10% with a planted synthetic
  credential, some binary noise, plus a vendor directory
- each run creates a fresh tree (tmp), runs ScanOptions with default
  config, no_git=True (working-tree scan)
- results: wall time via time.perf_counter, median of R runs
"""

from __future__ import annotations

import argparse
import os
import statistics
import tempfile
import time
from pathlib import Path

from agentpreflight.config import Config
from agentpreflight.engine import ScanOptions, run_scan

LOREM = (
    "def handler(event, context):\n"
    "    # process the request payload and fan out to workers\n"
    "    payload = normalise(event)\n"
    "    for shard in payload.shards:\n"
    "        dispatch(shard, retries=3)\n"
    "    return {'statusCode': 200, 'body': 'ok'}\n\n"
)


def build_tree(root: Path, files: int, size_kb: int) -> tuple[int, int]:
    """Create the synthetic repo; returns (bytes_written, secrets_planted)."""
    written = 0
    secrets = 0
    repeats = max(1, size_kb * 1024 // len(LOREM.encode()))
    (root / "vendor" / "lib").mkdir(parents=True, exist_ok=True)
    for i in range(files):
        subdir = f"src/module_{i % 20}"
        (root / subdir).mkdir(parents=True, exist_ok=True)
        path = root / subdir / f"file_{i:05d}.py"
        body = LOREM * repeats
        if i % 10 == 0:
            body += "aws_key = AKIAIOSFODNN7EXAMPLE\n"  # synthetic (AWS docs example)  # agentpreflight: allow
            body += "db = " + "postgres://admin:Sup3rS3cretP4ss" + "@db.internal/prod\n"
            secrets += 2
        if i % 97 == 0:  # binary noise
            path = path.with_suffix(".bin")
            data = os.urandom(min(size_kb * 1024, 65536))
            path.write_bytes(b"\x00\x01\x02" + data)
            written += len(data) + 3
            continue
        path.write_text(body, encoding="utf-8")
        written += len(body.encode())
        if i % 500 == 0:  # vendor dir noise (pruned in walk mode, still detected once)
            (root / "vendor" / "lib" / f"vend_{i}.js").write_text("module.exports = 1\n", encoding="utf-8")
            written += 20
    return written, secrets


def run_once(files: int, size_kb: int) -> dict[str, float]:
    with tempfile.TemporaryDirectory(prefix="apf-bench-") as tmp:
        root = Path(tmp)
        bytes_written, _secrets = build_tree(root, files, size_kb)
        start = time.perf_counter()
        result = run_scan(ScanOptions(path=str(root), config=Config(), no_git=True))
        duration = time.perf_counter() - start
        return {
            "seconds": duration,
            "files": files,
            "mb": bytes_written / 1024 / 1024,
            "findings": len(result.findings),
        }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--files", type=int, default=2000)
    parser.add_argument("--size", type=int, default=4, help="KB per file")
    parser.add_argument("--runs", type=int, default=3)
    args = parser.parse_args()

    print(f"benchmark: {args.files} files x ~{args.size} KB x {args.runs} runs")
    results = [run_once(args.files, args.size) for _ in range(args.runs)]
    seconds = [r["seconds"] for r in results]
    med = statistics.median(seconds)
    mb = results[0]["mb"]
    print(f"tree size      : {mb:.1f} MiB")
    print(f"findings       : {results[0]['findings']}")
    print(f"runs (s)       : {', '.join(f'{s:.2f}' for s in seconds)}")
    print(f"median         : {med:.2f} s")
    print(f"throughput     : {args.files / med:,.0f} files/s, {mb / med:.1f} MiB/s")


if __name__ == "__main__":
    main()
