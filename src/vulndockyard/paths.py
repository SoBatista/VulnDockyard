"""XDG paths and guarded local deletion."""

from __future__ import annotations

import os
import shutil
import stat
from dataclasses import dataclass
from pathlib import Path

from .errors import IntegrityError


def _xdg(env_name: str, fallback: Path) -> Path:
    value = os.environ.get(env_name)
    selected = Path(value).expanduser() if value else fallback
    if not selected.is_absolute():
        raise IntegrityError(f"{env_name} must be an absolute path")
    return selected


@dataclass(frozen=True)
class Paths:
    cache: Path
    state: Path
    config: Path
    data: Path

    @classmethod
    def discover(cls) -> Paths:
        home = Path.home()
        return cls(
            cache=_xdg("XDG_CACHE_HOME", home / ".cache") / "vulndockyard",
            state=_xdg("XDG_STATE_HOME", home / ".local/state") / "vulndockyard",
            config=_xdg("XDG_CONFIG_HOME", home / ".config") / "vulndockyard",
            data=_xdg("XDG_DATA_HOME", home / ".local/share") / "vulndockyard",
        )

    def ensure(self) -> None:
        for path in (self.cache, self.state, self.config, self.data):
            if path.is_symlink():
                raise IntegrityError(f"refusing symlinked XDG ownership root: {path}")
            path.mkdir(mode=0o700, parents=True, exist_ok=True)
            path.chmod(0o700)

    def owned_roots(self) -> tuple[Path, ...]:
        return self.cache, self.state, self.config, self.data


def assert_owned_path(target: Path, root: Path) -> Path:
    """Return an absolute safe target only when it is a child of an owned root."""
    if target.is_symlink() or root.is_symlink():
        raise IntegrityError("refusing a symlinked deletion target or ownership root")
    resolved_root = root.resolve(strict=False)
    resolved_target = target.resolve(strict=False)
    if resolved_target == resolved_root or resolved_root not in resolved_target.parents:
        raise IntegrityError(f"deletion target is outside the owned root: {target}")
    return resolved_target


def remove_owned_tree(target: Path, root: Path) -> None:
    safe = assert_owned_path(target, root)
    if not safe.exists():
        return
    mode = safe.lstat().st_mode
    if stat.S_ISLNK(mode):
        raise IntegrityError(f"refusing to delete symlink: {safe}")
    if safe.is_dir():
        shutil.rmtree(safe)
    else:
        safe.unlink()
