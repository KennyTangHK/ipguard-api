"""Validate the independent SDK's source, packages and publication identity."""

from __future__ import annotations

import argparse
import hashlib
import re
import shutil
import subprocess
import sys
import time
import tomllib
from dataclasses import dataclass
from email.parser import BytesParser
from pathlib import Path

from scripts.packaging_policy import (
    load_policy,
    sdist_contents,
    source_bytes,
    validate_build_constraints,
    validate_sdist_payload,
    validate_wheel_payload,
    zip_contents,
)

ROOT = Path(__file__).resolve().parents[1]
VERSION = re.compile(
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:b[1-9][0-9]*)?"
)
COMMIT = re.compile(r"[0-9a-f]{40}")


@dataclass(frozen=True)
class ReleaseMetadata:
    version: str

    @property
    def assets(self) -> tuple[str, str]:
        return (
            f"ipguard_api-{self.version}-py3-none-any.whl",
            f"ipguard_api-{self.version}.tar.gz",
        )


def read_metadata(root: Path = ROOT, tag: str = "") -> ReleaseMetadata:
    project = tomllib.loads((root / "pyproject.toml").read_text())["project"]
    version = project["version"]
    if (
        project["name"] != "ipguard-api"
        or not isinstance(version, str)
        or VERSION.fullmatch(version) is None
    ):
        raise ValueError(
            "SDK metadata must name ipguard-api with an X.Y.Z or X.Y.ZbN version."
        )
    if tag and tag != f"v{version}":
        raise ValueError("Release tag must exactly match the SDK package version.")
    lock = tomllib.loads((root / "uv.lock").read_text())
    local = [item for item in lock["package"] if item["name"] == "ipguard-api"]
    if (
        len(local) != 1
        or local[0]["version"] != version
        or local[0]["source"] != {"editable": "."}
    ):
        raise ValueError(
            "The standalone lock must match the SDK version and local source."
        )
    if any(
        item["name"]
        in {"homeassistant", "ha-ipguard", "pytest-homeassistant-custom-component"}
        for item in lock["package"]
    ):
        raise ValueError(
            "SDK development must not depend on the Home Assistant integration."
        )
    load_policy(root)
    validate_build_constraints(root)
    return ReleaseMetadata(version)


def _requirement(value: str) -> tuple[str, tuple[str, ...]]:
    match = re.fullmatch(r"([A-Za-z0-9_.-]+)(.*)", value.replace(" ", ""))
    if match is None:
        raise ValueError("Invalid distribution requirement.")
    return match[1].lower().replace("_", "-"), tuple(sorted(match[2].split(",")))


def _check_metadata(data: bytes, root: Path, metadata: ReleaseMetadata) -> None:
    project = tomllib.loads((root / "pyproject.toml").read_text())["project"]
    parsed = BytesParser().parsebytes(data)
    expected = {
        "Name": "ipguard-api",
        "Version": metadata.version,
        "License-Expression": project["license"],
        "Description-Content-Type": "text/markdown",
    }
    if any(parsed.get_all(key) != [value] for key, value in expected.items()):
        raise ValueError("Distribution metadata differs from the approved project.")
    if (
        parsed.get_all("Requires-Python") is None
        or len(parsed.get_all("Requires-Python", [])) != 1
        or sorted(parsed["Requires-Python"].replace(" ", "").split(","))
        != sorted(project["requires-python"].replace(" ", "").split(","))
    ):
        raise ValueError(
            "Distribution Python requirements differ from the approved project."
        )
    if sorted(
        _requirement(item) for item in parsed.get_all("Requires-Dist", [])
    ) != sorted(_requirement(item) for item in project["dependencies"]):
        raise ValueError("Distribution dependencies differ from the approved project.")
    if sorted(parsed.get_all("Project-URL", [])) != sorted(
        f"{key}, {value}" for key, value in project["urls"].items()
    ):
        raise ValueError("Distribution project URLs differ from the approved project.")
    if parsed.get_payload() != (root / "README.md").read_text():
        raise ValueError("Distribution description differs from the SDK README.")


def _digest(path: Path) -> str:
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def validate_assets(
    dist: Path, metadata: ReleaseMetadata, root: Path = ROOT
) -> tuple[Path, Path]:
    policy = load_policy(root)
    validate_build_constraints(root)
    assets = tuple(dist / name for name in metadata.assets)
    if any(not path.is_file() or path.is_symlink() for path in assets):
        raise ValueError("Required SDK archives are missing or not regular files.")
    if (
        not dist.is_dir()
        or dist.is_symlink()
        or any(item.is_symlink() or not item.is_file() for item in dist.iterdir())
        or set(item.name for item in dist.iterdir())
        - {*metadata.assets, "SHA256SUMS", ".gitignore"}
    ):
        raise ValueError("Distribution directory contains unapproved release files.")
    if (dist / ".gitignore").exists() and (dist / ".gitignore").read_bytes() not in {
        b"*",
        b"*\n",
    }:
        raise ValueError("Unexpected distribution ignore file.")
    wheel, sdist = assets
    validate_wheel_payload(
        wheel,
        "ipguard-api",
        metadata.version,
        {
            name.removeprefix("src/"): data
            for name, data in source_bytes(root, policy.wheel).items()
        },
        (root / "LICENSE").read_bytes(),
    )
    validate_sdist_payload(
        sdist, f"ipguard_api-{metadata.version}", source_bytes(root, policy.sdist)
    )
    wheel_data = zip_contents(wheel)
    info = f"ipguard_api-{metadata.version}.dist-info/"
    _check_metadata(wheel_data[info + "METADATA"], root, metadata)
    _check_metadata(
        sdist_contents(sdist, f"ipguard_api-{metadata.version}/")["PKG-INFO"],
        root,
        metadata,
    )
    wheel_headers = BytesParser().parsebytes(wheel_data[info + "WHEEL"])
    if wheel_headers.get_all("Tag") != ["py3-none-any"] or wheel_headers.get_all(
        "Root-Is-Purelib"
    ) != ["true"]:
        raise ValueError("SDK wheel must be platform-independent Python.")
    return wheel, sdist


def checksums(assets: tuple[Path, Path]) -> str:
    return "".join(f"{_digest(path)}  {path.name}\n" for path in assets)


def validate_checksums(dist: Path, assets: tuple[Path, Path]) -> None:
    path = dist / "SHA256SUMS"
    if path.is_symlink() or not path.is_file() or path.read_text() != checksums(assets):
        raise ValueError("SDK checksums must exactly match both checked archives.")


def _git(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), *args],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    return result.stdout.strip()


def validate_release_context(
    root: Path,
    metadata: ReleaseMetadata,
    *,
    tag: str,
    event_name: str,
    ref_type: str,
    ref_name: str,
    event_sha: str,
    tested_sha: str,
    repository: str,
) -> None:
    if (
        event_name not in {"push", "workflow_dispatch"}
        or ref_type != "tag"
        or ref_name != tag
        or tag != f"v{metadata.version}"
    ):
        raise ValueError("Publication requires an explicit matching release tag event.")
    if (
        COMMIT.fullmatch(event_sha) is None
        or COMMIT.fullmatch(tested_sha) is None
        or event_sha != tested_sha
    ):
        raise ValueError("Publication must use the exact tested event commit.")
    if (
        _git(root, "rev-parse", "HEAD") != event_sha
        or _git(root, "rev-parse", f"refs/tags/{tag}^{{commit}}") != event_sha
    ):
        raise ValueError("Checkout, release tag and tested event commit must agree.")
    if _git(root, "status", "--porcelain", "--untracked-files=all"):
        raise ValueError(
            "Publication requires a clean source checkout at the tested commit."
        )
    project = tomllib.loads((root / "pyproject.toml").read_text())["project"]
    if (
        "REPLACE_WITH_OWNER" in str(project.get("urls", {}))
        or re.fullmatch(r"[A-Za-z0-9_.-]+/ipguard-api", repository) is None
        or project["urls"]["Repository"] != f"https://github.com/{repository}"
    ):
        raise ValueError(
            "Configure the real independent SDK repository before publication."
        )


def validate_remote_tag(root: Path, tag: str, commit: str) -> None:
    """Bound transient GitHub reads; a moved or unresolvable tag stops publishing."""
    for attempt in range(3):
        try:
            response = _git(
                root,
                "ls-remote",
                "--tags",
                "origin",
                f"refs/tags/{tag}",
                f"refs/tags/{tag}^{{}}",
            )
        except subprocess.CalledProcessError, subprocess.TimeoutExpired:
            if attempt == 2:
                raise ValueError("Cannot confirm the remote release tag.") from None
            time.sleep(attempt + 1)
            continue
        refs = dict(line.split("\t", 1)[::-1] for line in response.splitlines() if line)
        if refs.get(f"refs/tags/{tag}^{{}}", refs.get(f"refs/tags/{tag}")) != commit:
            raise ValueError("Remote release tag does not match the tested commit.")
        return


def stage_upload(assets: tuple[Path, Path], destination: Path) -> None:
    """Copy only verified archives into a fresh directory for the publishing action."""
    destination.mkdir(parents=True, exist_ok=False)
    for path in assets:
        target = destination / path.name
        shutil.copyfile(path, target)
        if _digest(target) != _digest(path):
            raise ValueError("Staged upload bytes differ from the checked archive.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--tag", default="")
    parser.add_argument("--dist", type=Path)
    parser.add_argument("--write-checksums", action="store_true")
    parser.add_argument("--publish-ready", action="store_true")
    parser.add_argument("--upload-dir", type=Path)
    parser.add_argument("--github-output", type=Path)
    for name in (
        "event-name",
        "ref-type",
        "ref-name",
        "event-sha",
        "tested-sha",
        "repository",
    ):
        parser.add_argument(f"--{name}", default="")
    args = parser.parse_args()
    try:
        metadata = read_metadata(args.root, args.tag)
        if args.tag:
            validate_release_context(
                args.root,
                metadata,
                tag=args.tag,
                event_name=args.event_name,
                ref_type=args.ref_type,
                ref_name=args.ref_name,
                event_sha=args.event_sha,
                tested_sha=args.tested_sha,
                repository=args.repository,
            )
        if args.publish_ready:
            if (
                not args.tag
                or args.dist is None
                or args.write_checksums
                or args.upload_dir is None
            ):
                raise ValueError(
                    "Publishing requires the tag context, checked archives, checksums and a fresh upload directory."
                )
            validate_remote_tag(args.root, args.tag, args.tested_sha)
        if args.dist is not None:
            assets = validate_assets(args.dist, metadata, args.root)
            if args.write_checksums:
                checksum = args.dist / "SHA256SUMS"
                if checksum.is_symlink():
                    raise ValueError("Checksum output cannot be a symbolic link.")
                checksum.write_text(checksums(assets))
            else:
                validate_checksums(args.dist, assets)
            if args.upload_dir is not None:
                if not args.publish_ready:
                    raise ValueError("Only a validated release may stage PyPI uploads.")
                stage_upload(assets, args.upload_dir)
        if args.github_output is not None:
            with args.github_output.open("a") as output:
                output.write(f"version={metadata.version}\n")
    except (ValueError, OSError, subprocess.SubprocessError, KeyError) as error:
        print(f"SDK release validation failed: {error}", file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
