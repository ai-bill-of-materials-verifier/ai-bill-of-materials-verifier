from __future__ import annotations

import os
import shutil
import subprocess

import pytest

pytestmark = pytest.mark.integration


SERVICE_SMOKE_COMMANDS = [
    (
        "opa",
        ["docker", "run", "--rm", "openpolicyagent/opa:1.10.1-static", "version"],
        0,
    ),
    (
        "envoy",
        ["docker", "run", "--rm", "envoyproxy/envoy:v1.36.2", "--version"],
        0,
    ),
    (
        "vault",
        ["docker", "run", "--rm", "hashicorp/vault:1.21", "version"],
        0,
    ),
    (
        "spire-server",
        [
            "docker",
            "run",
            "--rm",
            "--entrypoint",
            "/opt/spire/bin/spire-server",
            "ghcr.io/spiffe/spire-server:1.13.3",
            "validate",
            "-config",
            "/does-not-exist",
        ],
        1,
    ),
    (
        "spire-agent",
        [
            "docker",
            "run",
            "--rm",
            "--entrypoint",
            "/opt/spire/bin/spire-agent",
            "ghcr.io/spiffe/spire-agent:1.13.3",
            "validate",
            "-config",
            "/does-not-exist",
        ],
        1,
    ),
]


@pytest.mark.skipif(os.getenv("RUN_INTEGRATION_TESTS") != "1", reason="set RUN_INTEGRATION_TESTS=1")
@pytest.mark.skipif(shutil.which("docker") is None, reason="docker CLI unavailable")
@pytest.mark.parametrize(("name", "cmd", "expected_code"), SERVICE_SMOKE_COMMANDS)
def test_docker_service_images_are_runnable(name: str, cmd: list[str], expected_code: int) -> None:
    proc = subprocess.run(  # noqa: S603
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=45,
        check=False,
    )
    assert proc.returncode == expected_code, name
