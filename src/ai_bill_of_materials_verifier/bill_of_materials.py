from __future__ import annotations

import json
from datetime import UTC, datetime
from importlib.resources import files
from pathlib import Path
from typing import Any

import jsonschema


def generate_bill_of_materials(
    manifest: dict[str, Any],
    *,
    model_name: str | None = None,
    datasets: list[str] | None = None,
    frameworks: list[str] | None = None,
) -> dict[str, Any]:
    alg = str(manifest["alg"]).upper()
    bom: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(UTC).isoformat(),
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "ai-bill-of-materials-verifier",
                        "version": "0.1.0",
                    }
                ]
            },
            "component": {
                "type": "machine-learning-model",
                "name": model_name or str(manifest["name"]),
                "version": "0.0.0",
                "hashes": [{"alg": alg, "content": manifest["root"]}],
                "properties": [
                    {
                        "name": "ai-bill-of-materials-verifier:manifest-root",
                        "value": str(manifest["root"]),
                    },
                    {
                        "name": "ai-bill-of-materials-verifier:manifest-alg",
                        "value": str(manifest["alg"]),
                    },
                ],
                "modelCard": {
                    "modelParameters": {
                        "approach": {"type": "supervised"},
                        "task": "model artifact integrity verification fixture",
                    },
                    "considerations": {"users": ["offline verifier operators"]},
                },
            },
        },
        "components": [],
    }
    for dataset in datasets or []:
        bom["components"].append({"type": "data", "name": dataset, "scope": "required"})
    for framework in frameworks or []:
        bom["components"].append({"type": "library", "name": framework, "scope": "required"})
    return bom


def schema() -> dict[str, Any]:
    parsed = json.loads(
        (files("ai_bill_of_materials_verifier._vendor") / "cyclonedx-1.6.schema.json").read_text(
            encoding="utf-8"
        )
    )
    if not isinstance(parsed, dict):
        raise ValueError("schema must be an object")
    return parsed


def validate_bill_of_materials(bom: dict[str, Any]) -> None:
    jsonschema.Draft202012Validator(schema()).validate(bom)


def write_bill_of_materials(bom: dict[str, Any], path: str | Path) -> None:
    validate_bill_of_materials(bom)
    Path(path).write_text(json.dumps(bom, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def read_bill_of_materials(path: str | Path) -> dict[str, Any]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("AI Bill of Materials must be a JSON object")
    validate_bill_of_materials(data)
    return data


def manifest_root_from_bom(bom: dict[str, Any]) -> str:
    props = bom.get("metadata", {}).get("component", {}).get("properties", [])
    if not isinstance(props, list):
        raise ValueError("missing properties")
    for prop in props:
        if (
            isinstance(prop, dict)
            and prop.get("name") == "ai-bill-of-materials-verifier:manifest-root"
        ):
            return str(prop.get("value"))
    raise ValueError(
        "AI Bill of Materials does not link an AI Bill of Materials Verifier manifest root"
    )
