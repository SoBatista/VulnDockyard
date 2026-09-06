from __future__ import annotations

from pathlib import Path

import pytest

from vulndockyard.catalogue import Catalogue, ReviewedLab
from vulndockyard.paths import Paths


@pytest.fixture
def xdg_paths(tmp_path: Path) -> Paths:
    return Paths(
        cache=tmp_path / "cache" / "vulndockyard",
        state=tmp_path / "state" / "vulndockyard",
        config=tmp_path / "config" / "vulndockyard",
        data=tmp_path / "data" / "vulndockyard",
    )


@pytest.fixture
def juice_shop() -> ReviewedLab:
    return Catalogue().get("juice-shop")
