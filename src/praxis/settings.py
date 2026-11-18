"""Settings: environment variables first, then the nearest praxis.toml.

Code must never hard-code where content lives; it asks `get_settings()`.
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

CONFIG_NAME = "praxis.toml"


class SettingsError(RuntimeError):
    pass


@dataclass(frozen=True)
class Settings:
    content_dir: Path
    deploy_dir: Path | None
    # Name of the SIEM connection used for lab tests (see platforms/*/connection.py).
    lab_connection: str
    # Where pinned upstream rule sources are checked out.
    sources_cache: Path


def _find_config(start: Path) -> Path | None:
    explicit = os.environ.get("PRAXIS_CONFIG")
    if explicit:
        return Path(explicit)
    for folder in (start, *start.parents):
        candidate = folder / CONFIG_NAME
        if candidate.is_file():
            return candidate
    return None


def load_env_files() -> None:
    """Load KEY=VALUE files named in PRAXIS_ENV_FILE (os.pathsep-separated).

    This is how a self-hosted runner hands SIEM connections to `praxis` without
    the secrets ever being stored in the repo or in the CI service. Variables
    that are already set win.
    """
    for name in filter(None, os.environ.get("PRAXIS_ENV_FILE", "").split(os.pathsep)):
        for line in Path(name).read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            os.environ.setdefault(key.strip(), value.strip())


def load_settings(start: Path | None = None) -> Settings:
    config_path = _find_config((start or Path.cwd()).resolve())
    file_values: dict = {}
    base = Path.cwd()
    if config_path:
        file_values = tomllib.loads(config_path.read_text())
        base = config_path.parent

    def path_setting(name: str) -> Path | None:
        env = os.environ.get(f"PRAXIS_{name.upper()}")
        if env:
            return Path(env).expanduser().resolve()
        if name in file_values:
            return (base / file_values[name]).resolve()
        return None

    content_dir = path_setting("content_dir")
    if content_dir is None:
        raise SettingsError(
            "content_dir is not set: export PRAXIS_CONTENT_DIR or add it to praxis.toml"
        )
    lab_connection = os.environ.get("PRAXIS_LAB_CONNECTION") or file_values.get(
        "lab_connection", "lab"
    )
    return Settings(
        content_dir=content_dir,
        deploy_dir=path_setting("deploy_dir"),
        lab_connection=lab_connection,
        sources_cache=path_setting("sources_cache") or Path.home() / ".cache/praxis/sources",
    )


@lru_cache
def get_settings() -> Settings:
    return load_settings()
