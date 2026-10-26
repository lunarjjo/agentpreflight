"""Git history scanning.

History scanning enumerates every blob reachable from all refs, dedupes
by blob SHA (a secret present in many commits is scanned once), and reads
blob contents through a single long-running ``git cat-file --batch``
process for efficiency.

This module shells out to the ``git`` binary only. It never executes any
repository content and never writes to the repository.

Resource bounds: per-blob size limit and a cumulative in-memory budget
(``total_byte_budget``) protect against pathological repositories.
"""

from __future__ import annotations

import subprocess
import threading
from dataclasses import dataclass

from agentpreflight.walker import _git, is_git_work_tree

_TOTAL_BYTE_BUDGET_DEFAULT = 256 * 1024 * 1024  # 256 MiB


@dataclass
class HistoryBlob:
    sha: str


def enumerate_history_blobs(root: str, *, max_commits: int) -> tuple[list[HistoryBlob], int]:
    """Return deduped blob SHAs reachable from all refs, plus commit count.

    Truncates the walk at ``max_commits`` commits (oldest first when the
    limit is hit, per ``git rev-list`` semantics).
    """
    if not is_git_work_tree(root):
        return [], 0

    revs = _git(root, "rev-list", "--all", f"--max-count={max_commits}")
    if revs.returncode != 0:
        return [], 0
    commit_count = sum(1 for line in revs.stdout.splitlines() if line.strip())

    objects = _git(
        root,
        "rev-list",
        "--objects",
        "--all",
        f"--max-count={max_commits}",
        "--no-object-names",
    )
    if objects.returncode != 0:
        # Older git without --no-object-names: strip path suffixes instead.
        objects = _git(root, "rev-list", "--objects", "--all", f"--max-count={max_commits}")

    shas: list[str] = []
    seen: set[str] = set()
    for line in objects.stdout.splitlines():
        sha = line.split(" ", 1)[0].strip()
        if len(sha) != 40 or any(c not in "0123456789abcdef" for c in sha):
            continue
        if sha in seen:
            continue
        seen.add(sha)
        shas.append(sha)

    if not shas:
        return [], commit_count

    # Identify which shas are blobs via a single batch-check process.
    try:
        proc = subprocess.Popen(
            ["git", "-C", root, "cat-file", "--batch-check"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        assert proc.stdin is not None and proc.stdout is not None
        out, _ = proc.communicate("\n".join(shas), timeout=300)
    except (OSError, subprocess.TimeoutExpired):
        return [], commit_count
    if proc.returncode != 0:
        return [], commit_count

    blobs: list[HistoryBlob] = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[1] == "blob":
            blobs.append(HistoryBlob(sha=parts[0]))
    return blobs, commit_count


def read_history_blobs(
    root: str,
    blobs: list[HistoryBlob],
    *,
    max_blob_size: int,
    total_byte_budget: int = _TOTAL_BYTE_BUDGET_DEFAULT,
) -> tuple[dict[str, bytes], bool]:
    """Read blob contents within size limits.

    Returns ``(contents, truncated)`` where ``truncated`` is True when the
    cumulative byte budget was exhausted and some blobs were skipped.

    stdin is fed from a dedicated thread so that a full stdout pipe can
    never deadlock the pipeline on large repositories.
    """
    if not blobs:
        return {}, False
    proc = subprocess.Popen(
        ["git", "-C", root, "cat-file", "--batch"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
    )
    stdin = proc.stdin
    assert stdin is not None
    assert proc.stdout is not None

    def _feed() -> None:
        try:
            for blob in blobs:
                stdin.write((blob.sha + "\n").encode("ascii"))
            stdin.close()
        except (BrokenPipeError, ValueError, OSError):
            pass

    feeder = threading.Thread(target=_feed, daemon=True)
    feeder.start()

    contents: dict[str, bytes] = {}
    total = 0
    truncated = False
    remaining = {b.sha for b in blobs}
    stdout = proc.stdout
    try:
        while remaining:
            header = stdout.readline()
            if not header:
                break
            parts = header.decode("ascii", "replace").split()
            if len(parts) < 3:
                continue  # e.g. "<sha> missing" — nothing further follows
            sha, kind, size_s = parts[0], parts[1], parts[2]
            if not size_s.isdigit():
                continue
            size = int(size_s)
            if kind != "blob":
                stdout.read(size + 1)
                remaining.discard(sha)
                continue
            if size > max_blob_size or total + size > total_byte_budget:
                stdout.read(size + 1)
                remaining.discard(sha)
                if total + size > total_byte_budget:
                    truncated = True
                continue
            data = stdout.read(size)
            stdout.read(1)  # trailing newline
            if sha in remaining:
                contents[sha] = data
                remaining.discard(sha)
                total += size
    finally:
        proc.kill()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:  # pragma: no cover
            pass
    _ = truncated or truncated
    return contents, truncated


def attribute_blob_to_commit(root: str, blob_sha: str, *, timeout: int = 30) -> str | None:
    """Best-effort: newest commit that touched this blob."""
    try:
        result = _git(
            root,
            "log",
            "--all",
            "--format=%H",
            "-n",
            "1",
            f"--find-object={blob_sha}",
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    line = result.stdout.strip().splitlines()
    return line[0] if line else None
