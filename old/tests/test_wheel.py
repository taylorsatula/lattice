"""Verify the built wheel installs cleanly in a fresh virtual environment."""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def wheel_file() -> Path:
    """Build the wheel and return its path."""
    subprocess.run(
        ["uv", "build", "--wheel"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    # Locate the most recently built wheel.
    wheels = sorted((REPO_ROOT / "dist").glob("*.whl"), key=lambda p: p.stat().st_mtime)
    if not wheels:
        pytest.fail("no wheel produced")
    return wheels[-1]


def test_wheel_installs_and_imports(wheel_file: Path) -> None:
    """Install the wheel in a fresh venv and sanity-check the CLI."""
    with tempfile.TemporaryDirectory() as tmp:
        venv = Path(tmp) / "venv"
        python = venv / "bin" / "python"
        subprocess.run(["uv", "venv", str(venv)], check=True, capture_output=True)
        subprocess.run(
            ["uv", "pip", "install", "--python", str(python), str(wheel_file)],
            check=True,
            capture_output=True,
        )
        # The package imports.
        subprocess.run(
            [str(python), "-c", "import lattice; print(lattice.__version__)"],
            check=True,
            capture_output=True,
        )
        # The CLI entry point exists.
        lattice_cli = venv / "bin" / "lattice"
        result = subprocess.run(
            [str(lattice_cli), "--help"],
            check=True,
            capture_output=True,
            text=True,
        )
        assert "Lattice node operator CLI" in result.stdout
