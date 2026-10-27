"""Read explicit package selections and reject unreviewed release payloads."""

from __future__ import annotations

import base64
import csv
import hashlib
import io
import stat
import tarfile
import tomllib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from zipfile import ZipFile


def safe_path(name: str) -> str:
    """Require a portable, canonical path relative to an archive or project."""
    path = PurePosixPath(name)
    if (
        not name
        or not path.parts
        or name.startswith("/")
        or "\\" in name
        or ":" in name
        or "\x00" in name
        or any(ord(character) < 32 or ord(character) == 127 for character in name)
        or ".." in path.parts
        or path.as_posix() != name
        or name.endswith("/")
    ):
        raise ValueError("Package contains an unsafe or noncanonical path.")
    return name


def read_selection(project: Path, target: str) -> tuple[str, ...]:
    """Use Hatch's file-only selections as the single release allowlist."""
    data = tomllib.loads((project / "pyproject.toml").read_text())
    selection = data["tool"]["hatch"]["build"]["targets"][target].get("only-include")
    if not isinstance(selection, list) or not selection:
        raise ValueError("Every distribution must have an explicit file allowlist.")
    if any(not isinstance(name, str) for name in selection):
        raise ValueError("Package file allowlists must contain relative filenames.")
    names = tuple(safe_path(name) for name in selection)
    if len(set(names)) != len(names) or any(
        any(character in name for character in "*?[]") for name in names
    ):
        raise ValueError("Package file allowlists cannot contain duplicates or globs.")
    return names


def source_bytes(project: Path, names: tuple[str, ...]) -> dict[str, bytes]:
    """Reject missing files and links before reading any approved source."""
    contents = {}
    for name in names:
        path = project / safe_path(name)
        if any(
            parent.is_symlink()
            for parent in (path, *path.parents)
            if parent != project.parent
            and (parent == project or project in parent.parents)
        ):
            raise ValueError("Package sources cannot contain symbolic links.")
        if not path.is_file():
            raise ValueError("An approved package source is missing or not a file.")
        contents[name] = path.read_bytes()
    return contents


def _development_cache(path: PurePosixPath) -> bool:
    return (
        "__pycache__" in path.parts
        or path.suffix in {".pyc", ".pyo"}
        or path.name == ".DS_Store"
    )


def check_source_tree(
    project: Path, names: tuple[str, ...], directories: tuple[str, ...]
) -> None:
    """Fail on stray files even when Git or the build backend would ignore them."""
    allowed = set(names)
    for directory in directories:
        base = project / directory
        if base.is_symlink():
            raise ValueError("Package sources cannot contain symbolic links.")
        for path in base.rglob("*"):
            relative = path.relative_to(project).as_posix()
            if path.is_symlink():
                raise ValueError("Package sources cannot contain symbolic links.")
            if _development_cache(PurePosixPath(relative)):
                continue
            if path.is_file() and relative not in allowed:
                raise ValueError("An unapproved file exists in a packaged source tree.")


@dataclass(frozen=True)
class PackagingPolicy:
    """Exact reviewed selections for this independent SDK."""

    wheel: tuple[str, ...]
    sdist: tuple[str, ...]


def load_policy(root: Path, *, verify_sources: bool = True) -> PackagingPolicy:
    policy = PackagingPolicy(
        read_selection(root, "wheel"), read_selection(root, "sdist")
    )
    if any(not name.startswith("src/ipguard_api/") for name in policy.wheel):
        raise ValueError("The SDK wheel must contain only its reviewed package.")
    if not set(policy.wheel).issubset(policy.sdist):
        raise ValueError("The source distribution must include every wheel source.")
    if verify_sources:
        source_bytes(root, policy.sdist)
        check_source_tree(root, policy.sdist, ("src", "docs", "tests", "scripts"))
    return policy


def zip_contents(path: Path, prefix: str = "") -> dict[str, bytes]:
    with ZipFile(path) as archive:
        contents = {}
        for entry in archive.infolist():
            name = safe_path(entry.filename)
            mode = stat.S_IFMT(entry.external_attr >> 16)
            if (
                name in contents
                or not name.startswith(prefix)
                or mode not in {0, stat.S_IFREG}
            ):
                raise ValueError(
                    "Package archive contains duplicate or invalid members."
                )
            contents[name] = archive.read(entry)
        return {name.removeprefix(prefix): data for name, data in contents.items()}


def sdist_contents(path: Path, prefix: str) -> dict[str, bytes]:
    with tarfile.open(path, "r:gz") as archive:
        contents = {}
        for entry in archive.getmembers():
            name = safe_path(entry.name)
            if not name.startswith(prefix) or name in contents or not entry.isfile():
                raise ValueError(
                    "Source archive contains duplicate or invalid members."
                )
            source = archive.extractfile(entry)
            if source is None:
                raise ValueError("Source archive member is unreadable.")
            with source:
                contents[name] = source.read()
        return {name.removeprefix(prefix): data for name, data in contents.items()}


def validate_wheel_payload(
    path: Path,
    distribution: str,
    version: str,
    sources: dict[str, bytes],
    license_bytes: bytes,
) -> dict[str, bytes]:
    contents = zip_contents(path)
    metadata = f"{distribution.replace('-', '_')}-{version}.dist-info/"
    generated = {
        metadata + "METADATA",
        metadata + "WHEEL",
        metadata + "RECORD",
        metadata + "licenses/LICENSE",
    }
    if set(contents) != set(sources) | generated:
        raise ValueError("Wheel payload differs from its explicit file allowlist.")
    if any(contents[name] != data for name, data in sources.items()):
        raise ValueError("Wheel payload differs from its approved source files.")
    if contents[metadata + "licenses/LICENSE"] != license_bytes:
        raise ValueError("Wheel license differs from its approved license.")
    record = metadata + "RECORD"
    rows = list(csv.reader(io.StringIO(contents[record].decode())))
    if (
        any(len(row) != 3 for row in rows)
        or {row[0] for row in rows} != set(contents)
        or len(rows) != len(contents)
    ):
        raise ValueError("Wheel RECORD must describe exactly its approved members.")
    for name, digest, size in rows:
        safe_path(name)
        if name == record:
            if digest or size:
                raise ValueError("Wheel RECORD cannot contain its own digest.")
            continue
        expected_hash = (
            base64.urlsafe_b64encode(hashlib.sha256(contents[name]).digest())
            .decode()
            .rstrip("=")
        )
        if digest != "sha256=" + expected_hash or size != str(len(contents[name])):
            raise ValueError(
                "Wheel RECORD contains an incorrect member digest or size."
            )
    return {name: contents[name] for name in sources}


def validate_sdist_payload(
    path: Path, stem: str, sources: dict[str, bytes], *, gitignore: bytes | None = None
) -> None:
    contents = sdist_contents(path, stem + "/")
    expected = set(sources) | {"PKG-INFO"}
    if gitignore is not None:
        expected.add(".gitignore")
    if set(contents) != expected:
        raise ValueError(
            "Source archive payload differs from its explicit file allowlist."
        )
    if any(contents[name] != data for name, data in sources.items()):
        raise ValueError(
            "Source archive payload differs from its approved source files."
        )
    if gitignore is not None and contents[".gitignore"] != gitignore:
        raise ValueError("Source archive contains an unexpected Git ignore file.")


def validate_build_constraints(root: Path) -> None:
    """Keep isolated build pins and hashes in agreement with the workspace lock."""
    expected_names = {
        "hatchling",
        "packaging",
        "pathspec",
        "pluggy",
        "tomlkit",
        "trove-classifiers",
    }
    lock = tomllib.loads((root / "uv.lock").read_text())
    packages = {package["name"]: package for package in lock["package"]}
    expected = {}
    for name in expected_names:
        package = packages[name]
        hashes = {wheel["hash"] for wheel in package["wheels"]}
        hashes.add(package["sdist"]["hash"])
        expected[name] = (package["version"], hashes)
    closure = {"hatchling"}
    remaining = ["hatchling"]
    while remaining:
        for dependency in packages[remaining.pop()].get("dependencies", []):
            if dependency["name"] not in closure:
                closure.add(dependency["name"])
                remaining.append(dependency["name"])
    if closure != expected_names:
        raise ValueError(
            "Review the isolated build dependency closure after backend changes."
        )
    actual = {}
    for line in (root / "build-constraints.txt").read_text().splitlines():
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        name, separator, version = parts[0].partition("==")
        if (
            not separator
            or name in actual
            or any(not field.startswith("--hash=sha256:") for field in parts[1:])
        ):
            raise ValueError(
                "Build constraints must contain unique pins and SHA256 hashes."
            )
        actual[name] = (version, {field.removeprefix("--hash=") for field in parts[1:]})
    if actual != expected:
        raise ValueError(
            "Build constraints must exactly match the locked build dependencies."
        )
    for project in (root,):
        data = tomllib.loads((project / "pyproject.toml").read_text())
        if data["build-system"] != {
            "requires": [f"hatchling=={packages['hatchling']['version']}"],
            "build-backend": "hatchling.build",
        }:
            raise ValueError("The project must pin its actual locked build backend.")
