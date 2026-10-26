"""Safe file-system and Git file enumeration.

The walker treats repository content as untrusted input:

- Symlinks are never followed (and never counted as regular files).
- Every candidate path is validated to stay inside the scan root after
  normalisation (defence against crafted Git index entries such as
  ``../evil`` or absolute paths).
- Vendor/generated directories are pruned during plain filesystem walks
  but recorded so the artifact rules can still flag them.
- Hard resource limits (file count, file size, depth) are enforced.
"""

from __future__ import annotations

import os
import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from agentpreflight.rules.artifacts import VENDOR_DIR_NAMES

MAX_DEPTH_DEFAULT = 128


@dataclass
class FileInventory:
    """Result of enumerating candidate files for a scan."""

    files: list[str] = field(default_factory=list)  # relative paths, '/'-separated
    tracked: set[str] | None = None  # None when not inside a Git repository
    pruned_dirs: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def _git(root: str, *args: str, timeout: int = 60) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", root, *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
    )


def is_git_work_tree(root: str) -> bool:
    try:
        result = _git(root, "rev-parse", "--is-inside-work-tree")
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0 and result.stdout.strip() == "true"


def _validate_relative(path: str) -> str | None:
    """Reject anything that is not a safe, root-relative, forward-slash path."""
    if not path or "\x00" in path:
        return None
    if path.startswith("/") or path.startswith("\\"):
        return None
    normalised = path.replace("\\", "/")
    if normalised.startswith("../") or "/../" in normalised or normalised == "..":
        return None
    if normalised.endswith("/."):
        return None
    if normalised == ".":
        return None
    return normalised


def _walk_filesystem(root: str, max_files: int, exclude_paths: Callable[[str], bool] | None) -> FileInventory:
    inventory = FileInventory(tracked=None)
    count = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        rel_dir = os.path.relpath(dirpath, root)
        if rel_dir == ".":
            rel_dir = ""
        # prune vendor dirs but remember them for artifact rules
        for name in list(dirnames):
            if name in VENDOR_DIR_NAMES:
                inventory.pruned_dirs.append(_join_rel(rel_dir, name))
                dirnames.remove(name)
                continue
            if name == ".git":
                dirnames.remove(name)
                continue
        dirnames.sort()
        for name in sorted(filenames):
            rel = _join_rel(rel_dir, name)
            safe = _validate_relative(rel)
            if safe is None:
                inventory.errors.append(f"skipped suspicious path: {rel!r}")
                continue
            if os.path.islink(os.path.join(dirpath, name)):
                continue  # never follow symlinks
            if exclude_paths is not None and exclude_paths(safe):
                continue
            inventory.files.append(safe)
            count += 1
            if count >= max_files:
                inventory.errors.append(
                    f"file limit ({max_files}) reached; scan results are partial — "
                    "raise [scan] max_files or narrow the scan path"
                )
                return inventory
    return inventory


def _join_rel(dir_part: str, name: str) -> str:
    return f"{dir_part}/{name}" if dir_part else name


def _git_inventory(root: str, max_files: int, exclude_paths: Callable[[str], bool] | None) -> FileInventory:
    inventory = FileInventory()
    tracked_result = _git(root, "ls-files", "-z", "--cached")
    if tracked_result.returncode != 0:
        inventory.errors.append(f"git ls-files failed: {tracked_result.stderr.strip()[:200]}")
        return inventory
    tracked_raw = [p for p in tracked_result.stdout.split("\x00") if p]
    others_result = _git(root, "ls-files", "-z", "--others", "--exclude-standard")
    others_raw = [p for p in others_result.stdout.split("\x00") if p] if others_result.returncode == 0 else []
    if others_result.returncode != 0:
        inventory.errors.append(f"git ls-files --others failed: {others_result.stderr.strip()[:200]}")

    tracked: set[str] = set()
    for raw in tracked_raw:
        safe = _validate_relative(raw)
        if safe is None:
            inventory.errors.append(f"skipped suspicious index path: {raw!r}")
            continue
        tracked.add(safe)
    candidates: list[str] = []
    seen: set[str] = set()
    for raw in [*tracked_raw, *others_raw]:
        safe = _validate_relative(raw)
        if safe is None or safe in seen:
            continue
        seen.add(safe)
        if exclude_paths is not None and exclude_paths(safe):
            continue
        candidates.append(safe)
        if len(candidates) >= max_files:
            inventory.errors.append(
                f"file limit ({max_files}) reached; scan results are partial — "
                "raise [scan] max_files or narrow the scan path"
            )
            break

    # Only keep candidates that actually exist on disk and are not symlinks.
    for rel in candidates:
        target = Path(root) / rel
        try:
            if target.is_symlink():
                continue
            if not target.is_file():
                continue  # removed from worktree or a submodule gitlink
        except OSError:
            inventory.errors.append(f"could not inspect {rel!r}")
            continue
        inventory.files.append(rel)

    inventory.tracked = tracked
    return inventory


def gather_files(
    root: str,
    *,
    max_files: int,
    no_git: bool = False,
    exclude_paths: Callable[[str], bool] | None = None,
) -> FileInventory:
    """Enumerate files to scan.

    In a Git repository the default set is: tracked files plus untracked
    files that are not ignored. This matches "what would get committed" —
    an untracked-but-not-ignored ``.env`` is caught before the first
    commit, while ignored files stay out of the noise.
    """
    if no_git or not is_git_work_tree(root):
        return _walk_filesystem(root, max_files, exclude_paths)
    return _git_inventory(root, max_files, exclude_paths)


def resolve_scan_root(path: str) -> str:
    """Resolve and validate the scan root. Raises NotADirectoryError/NotAFileError."""
    root = Path(path).expanduser().resolve()
    if not root.exists():
        raise NotADirectoryError(f"scan path does not exist: {path}")
    return str(root)


def is_binary_head(head: bytes) -> bool:
    """Heuristic binary check: NUL byte or too many control characters."""
    if b"\x00" in head:
        return True
    if not head:
        return False
    controls = sum(1 for b in head if b < 0x09 or 0x0E <= b <= 0x1F)
    return controls / len(head) > 0.30


def read_file_content(abs_path: str, *, max_file_size: int) -> tuple[int, str | None, str | None]:
    """Read one file honouring size limits.

    Returns ``(size, text_or_None, skipped_reason)`` where ``text`` is None
    when the file was skipped (binary, oversized or unreadable) and
    ``skipped_reason`` explains why (``""`` for binary — path rules still
    apply without content; ``None`` when the file was fully read).
    """
    try:
        size = os.path.getsize(abs_path)
    except OSError as exc:
        return 0, None, f"unreadable: {exc.__class__.__name__}"
    if size > max_file_size:
        return size, None, "oversized"
    try:
        with open(abs_path, "rb") as fh:
            head = fh.read(8192)
    except OSError as exc:
        return size, None, f"unreadable: {exc.__class__.__name__}"
    if is_binary_head(head):
        return size, None, ""  # binary: path rules still apply, no content
    try:
        with open(abs_path, encoding="utf-8", errors="replace") as fh:
            text = fh.read(max_file_size + 1)
    except OSError as exc:
        return size, None, f"unreadable: {exc.__class__.__name__}"
    return size, text, None
