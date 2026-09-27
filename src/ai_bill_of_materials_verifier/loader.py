from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from .manifest import manifest_from_json
from .verify import open_verified, verify_full


def verify_before_load[T](
    path: str | Path, manifest_path: str | Path, loader: Callable[[Path], T]
) -> T:
    manifest = manifest_from_json(manifest_path)
    result = verify_full(path, manifest)
    if not result.ok:
        raise ValueError(f"verification failed: {result.reason}")
    return loader(Path(path))


def load_bytes_streaming(path: str | Path, manifest_path: str | Path) -> bytes:
    manifest = manifest_from_json(manifest_path)
    with open_verified(path, manifest) as reader:
        data = reader.read()
        result = reader.finish()
    if not result.ok:
        raise ValueError(result.reason)
    return data


def verify_onnx_path(path: str | Path, manifest_path: str | Path) -> Path:
    return verify_before_load(path, manifest_path, lambda p: p)


def verify_safetensors_path(path: str | Path, manifest_path: str | Path) -> Path:
    return verify_before_load(path, manifest_path, lambda p: p)
