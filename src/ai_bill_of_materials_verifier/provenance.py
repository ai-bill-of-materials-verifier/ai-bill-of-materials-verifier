from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .signing import verify_dsse

SLSA_PAYLOAD_TYPE = "application/vnd.in-toto+json"


@dataclass(frozen=True, slots=True)
class ProvenancePolicy:
    builder_ids: set[str]
    build_types: set[str]
    required_materials: set[str]


@dataclass(frozen=True, slots=True)
class ProvenanceResult:
    ok: bool
    reason: str


def load_policy(data: dict[str, Any]) -> ProvenancePolicy:
    return ProvenancePolicy(
        set(map(str, data.get("builder_ids", []))),
        set(map(str, data.get("build_types", []))),
        set(map(str, data.get("required_materials", []))),
    )


def verify_provenance_dsse(
    envelope: dict[str, Any],
    public_key: str | Path,
    *,
    subject_name: str,
    subject_digest: str,
    policy: ProvenancePolicy,
) -> ProvenanceResult:
    ok, statement = verify_dsse(envelope, public_key)
    if not ok or statement is None:
        return ProvenanceResult(False, "DSSE signature invalid")
    if statement.get("_type") != "https://in-toto.io/Statement/v1":
        return ProvenanceResult(False, "not an in-toto Statement v1")
    subjects = statement.get("subject", [])
    if not any(
        isinstance(s, dict)
        and s.get("name") == subject_name
        and isinstance(s.get("digest"), dict)
        and s["digest"].get("sha256") == subject_digest
        for s in subjects
    ):
        return ProvenanceResult(False, "subject digest mismatch")
    if statement.get("predicateType") != "https://slsa.dev/provenance/v1":
        return ProvenanceResult(False, "not SLSA Provenance v1")
    predicate = statement.get("predicate", {})
    builder_id = str(predicate.get("builder", {}).get("id", ""))
    build_type = str(predicate.get("buildDefinition", {}).get("buildType", ""))
    if policy.builder_ids and builder_id not in policy.builder_ids:
        return ProvenanceResult(False, "builder.id not allowed")
    if policy.build_types and build_type not in policy.build_types:
        return ProvenanceResult(False, "buildType not allowed")
    materials = {
        str(m.get("uri", ""))
        for m in predicate.get("buildDefinition", {}).get("resolvedDependencies", [])
        if isinstance(m, dict)
    }
    missing = policy.required_materials - materials
    if missing:
        return ProvenanceResult(False, "required materials missing: " + ",".join(sorted(missing)))
    return ProvenanceResult(True, "ok")
