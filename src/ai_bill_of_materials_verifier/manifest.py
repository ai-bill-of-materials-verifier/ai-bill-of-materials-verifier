from __future__ import annotations

import json
import math
import os
from collections.abc import Iterable
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from .hashers import algorithm

DEFAULT_CHUNK_SIZE = 16 * 1024 * 1024
LEAF_PREFIX = b"ai-bill-of-materials-verifier leaf v1\x00"
NODE_PREFIX = b"ai-bill-of-materials-verifier node v1\x00"
DIR_PREFIX = b"ai-bill-of-materials-verifier directory v1\x00"
ManifestKind = Literal["file", "directory"]


@dataclass(frozen=True, slots=True)
class ChunkProof:
    index: int
    leaf: str
    siblings: list[tuple[str, str]]


def canonical_json(data: object) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _hash_parts(parts: Iterable[bytes], alg: str) -> bytes:
    return algorithm(alg).digest(b"".join(parts))


def _leaf_hash(chunk: bytes, alg: str) -> bytes:
    return _hash_parts([LEAF_PREFIX, len(chunk).to_bytes(8, "big"), chunk], alg)


def _node_hash(left: bytes, right: bytes, alg: str) -> bytes:
    return _hash_parts([NODE_PREFIX, left, right], alg)


def _dir_hash(entries: list[dict[str, Any]], alg: str) -> str:
    return _hash_parts([DIR_PREFIX, canonical_json(entries)], alg).hex()


def _build_levels(leaves: list[bytes], alg: str) -> list[list[bytes]]:
    if not leaves:
        leaves = [_leaf_hash(b"", alg)]
    levels = [leaves]
    cur = leaves
    while len(cur) > 1:
        nxt: list[bytes] = []
        for idx in range(0, len(cur), 2):
            left = cur[idx]
            right = cur[idx + 1] if idx + 1 < len(cur) else left
            nxt.append(_node_hash(left, right, alg))
        levels.append(nxt)
        cur = nxt
    return levels


def _read_chunks(path: Path, chunk_size: int) -> Iterable[bytes]:
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(chunk_size)
            if not chunk:
                break
            yield chunk


def _read_leaf_hashes(path: Path, chunk_size: int, alg: str, threads: int) -> list[bytes]:
    if threads <= 1:
        return [_leaf_hash(chunk, alg) for chunk in _read_chunks(path, chunk_size)]

    leaves_by_index: dict[int, bytes] = {}
    pending: dict[Future[bytes], int] = {}
    max_pending = max(1, threads * 2)
    next_index = 0

    def drain_one() -> None:
        done = next(as_completed(pending))
        index = pending.pop(done)
        leaves_by_index[index] = done.result()

    with path.open("rb") as fh, ThreadPoolExecutor(max_workers=threads) as pool:
        while True:
            chunk = fh.read(chunk_size)
            if not chunk:
                break
            pending[pool.submit(_leaf_hash, chunk, alg)] = next_index
            next_index += 1
            if len(pending) >= max_pending:
                drain_one()
        while pending:
            drain_one()
    return [leaves_by_index[index] for index in range(next_index)]


def file_manifest(
    path: str | Path,
    *,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    alg: str = "blake3",
    threads: int = 1,
) -> dict[str, Any]:
    file_path = Path(path)
    alg = algorithm(alg).name
    leaves = _read_leaf_hashes(file_path, chunk_size, alg, threads)
    levels = _build_levels(leaves, alg)
    stat = file_path.stat()
    return {
        "schema": "ai-bill-of-materials-verifier-manifest-v1",
        "kind": "file",
        "name": file_path.name,
        "path": str(file_path),
        "size": stat.st_size,
        "chunk_size": chunk_size,
        "alg": alg,
        "leaves": [leaf.hex() for leaf in leaves] or [_leaf_hash(b"", alg).hex()],
        "root": levels[-1][0].hex(),
        "created": datetime.now(UTC).isoformat(),
    }


def directory_manifest(
    path: str | Path,
    *,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    alg: str = "blake3",
    threads: int = 1,
) -> dict[str, Any]:
    directory = Path(path)
    entries: list[dict[str, Any]] = []
    for child in sorted(p for p in directory.rglob("*") if p.is_file()):
        rel = child.relative_to(directory).as_posix()
        fm = file_manifest(child, chunk_size=chunk_size, alg=alg, threads=threads)
        entries.append({"path": rel, "size": fm["size"], "root": fm["root"], "alg": fm["alg"]})
    chosen_alg = entries[0]["alg"] if entries else algorithm(alg).name
    return {
        "schema": "ai-bill-of-materials-verifier-manifest-v1",
        "kind": "directory",
        "name": directory.name,
        "path": str(directory),
        "size": sum(int(e["size"]) for e in entries),
        "chunk_size": chunk_size,
        "alg": chosen_alg,
        "files": entries,
        "root": _dir_hash(entries, chosen_alg),
        "created": datetime.now(UTC).isoformat(),
    }


def create_manifest(
    path: str | Path,
    *,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    alg: str = "blake3",
    threads: int = 1,
) -> dict[str, Any]:
    p = Path(path)
    if p.is_dir():
        return directory_manifest(p, chunk_size=chunk_size, alg=alg, threads=threads)
    if p.is_file():
        return file_manifest(p, chunk_size=chunk_size, alg=alg, threads=threads)
    raise FileNotFoundError(p)


def manifest_from_json(path: str | Path) -> dict[str, Any]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("manifest must be a JSON object")
    return data


def write_manifest(manifest: dict[str, Any], path: str | Path) -> None:
    Path(path).write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def proof_for_index(manifest: dict[str, Any], index: int) -> ChunkProof:
    leaves = [bytes.fromhex(str(leaf)) for leaf in manifest["leaves"]]
    if index < 0 or index >= len(leaves):
        raise IndexError(index)
    levels = _build_levels(leaves, str(manifest["alg"]))
    siblings: list[tuple[str, str]] = []
    pos = index
    for level in levels[:-1]:
        sibling_pos = pos ^ 1
        if sibling_pos >= len(level):
            sibling_pos = pos
        side = "right" if pos % 2 == 0 else "left"
        siblings.append((side, level[sibling_pos].hex()))
        pos //= 2
    return ChunkProof(index=index, leaf=leaves[index].hex(), siblings=siblings)


def verify_proof(leaf_hex: str, root_hex: str, siblings: list[tuple[str, str]], alg: str) -> bool:
    node = bytes.fromhex(leaf_hex)
    for side, sibling_hex in siblings:
        sibling = bytes.fromhex(sibling_hex)
        node = _node_hash(node, sibling, alg) if side == "right" else _node_hash(sibling, node, alg)
    return node.hex() == root_hex


def expected_chunk_count(size: int, chunk_size: int) -> int:
    return 1 if size == 0 else math.ceil(size / chunk_size)


def file_id(path: Path) -> str:
    st = path.stat()
    device = getattr(st, "st_dev", 0)
    inode = getattr(st, "st_ino", 0)
    index = getattr(st, "st_file_attributes", 0)
    return f"{device}:{inode}:{index}:{os.path.abspath(path)}"
