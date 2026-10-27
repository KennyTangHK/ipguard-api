"""Package and release guards reject contaminated sources and untested releases."""

import base64
import csv
import hashlib
import io
import shutil
import subprocess
import sys
import tarfile
import tomllib
from pathlib import Path
from zipfile import ZipFile

import pytest

from scripts.packaging_policy import load_policy, validate_build_constraints
from scripts.release_metadata import (
    checksums,
    read_metadata,
    stage_upload,
    validate_assets,
    validate_checksums,
    validate_release_context,
    validate_remote_tag,
)

ROOT = Path(__file__).parents[1]
SHA = "a" * 40


@pytest.fixture(scope="session")
def built_project(tmp_path_factory):
    root = tmp_path_factory.mktemp("sdk-package")
    for name in load_policy(ROOT).sdist:
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, target)
    subprocess.run(
        [sys.executable, "-m", "hatchling", "build", "-t", "wheel", "-t", "sdist"],
        cwd=root,
        check=True,
        capture_output=True,
    )
    assets = validate_assets(root / "dist", read_metadata(root), root)
    (root / "dist/SHA256SUMS").write_text(checksums(assets))
    return root


@pytest.fixture
def project(tmp_path, built_project):
    root = tmp_path / "sdk"
    shutil.copytree(built_project, root)
    return root


def rewrite_wheel(path, edit):
    with ZipFile(path) as archive:
        contents = {name: archive.read(name) for name in archive.namelist()}
    edit(contents)
    record = next(name for name in contents if name.endswith(".dist-info/RECORD"))
    output = io.StringIO()
    writer = csv.writer(output, lineterminator="\n")
    for name, data in sorted(contents.items()):
        if name == record:
            writer.writerow([name, "", ""])
        else:
            digest = (
                base64.urlsafe_b64encode(hashlib.sha256(data).digest())
                .decode()
                .rstrip("=")
            )
            writer.writerow([name, "sha256=" + digest, str(len(data))])
    contents[record] = output.getvalue().encode()
    with ZipFile(path, "w") as archive:
        for name, data in contents.items():
            archive.writestr(name, data)


def test_built_packages_match_sources_and_staged_bytes(project):
    metadata = read_metadata(project)
    assets = validate_assets(project / "dist", metadata, project)
    validate_checksums(project / "dist", assets)
    destination = project / "upload"
    stage_upload(assets, destination)
    assert {path.name for path in destination.iterdir()} == set(metadata.assets)
    assert all(
        (destination / path.name).read_bytes() == path.read_bytes() for path in assets
    )
    with pytest.raises(FileExistsError):
        stage_upload(assets, destination)


@pytest.mark.parametrize(
    "name",
    [
        "src/ipguard_api/session.json",
        "docs/private.txt",
        "tests/credentials.json",
        "scripts/extra.py",
    ],
)
def test_stray_source_files_are_rejected(project, name):
    (project / name).write_text("synthetic-private-fixture")
    with pytest.raises(ValueError, match="unapproved"):
        load_policy(project)


def test_source_symlinks_are_rejected(project):
    target = project / "src/ipguard_api/client.py"
    target.unlink()
    target.symlink_to(project / "README.md")
    with pytest.raises(ValueError, match="symbolic"):
        load_policy(project)


@pytest.mark.parametrize("change", ["source", "extra", "metadata", "path"])
def test_wheel_tampering_fails_even_with_recomputed_record(project, change):
    metadata = read_metadata(project)
    path = project / "dist" / metadata.assets[0]

    def edit(contents):
        if change == "source":
            contents["ipguard_api/client.py"] += b"\n# altered\n"
        elif change == "extra":
            contents["ipguard_api/session.json"] = b"synthetic"
        elif change == "path":
            contents["../outside.py"] = b"synthetic"
        else:
            name = next(
                name for name in contents if name.endswith(".dist-info/METADATA")
            )
            contents[name] = contents[name].replace(
                b"Requires-Dist: pyzmq", b"Requires-Dist: changed"
            )

    rewrite_wheel(path, edit)
    with pytest.raises(ValueError):
        validate_assets(project / "dist", metadata, project)


@pytest.mark.parametrize("change", ["source", "extra", "link", "duplicate", "path"])
def test_sdist_tampering_is_rejected(project, change):
    metadata = read_metadata(project)
    path = project / "dist" / metadata.assets[1]
    with tarfile.open(path) as archive:
        entries = [
            (item, archive.extractfile(item).read()) for item in archive.getmembers()
        ]
    info, data = entries[0]
    if change == "source":
        data += b"altered"
        info.size = len(data)
        entries[0] = info, data
    else:
        info = tarfile.TarInfo(f"ipguard_api-{metadata.version}/extra.txt")
        data = b"synthetic"
        if change == "link":
            info.type = tarfile.SYMTYPE
            info.linkname = "README.md"
            data = b""
        elif change == "duplicate":
            info.name = entries[0][0].name
        elif change == "path":
            info.name = f"ipguard_api-{metadata.version}/../outside"
        info.size = len(data)
        entries.append((info, data))
    with tarfile.open(path, "w:gz") as archive:
        for item, content in entries:
            archive.addfile(item, io.BytesIO(content))
    with pytest.raises(ValueError):
        validate_assets(project / "dist", metadata, project)


def test_checksum_change_and_stale_archives_fail(project):
    metadata = read_metadata(project)
    assets = validate_assets(project / "dist", metadata, project)
    (project / "dist/SHA256SUMS").write_text("0" * 64 + "  wrong.whl\n")
    with pytest.raises(ValueError, match="checksums"):
        validate_checksums(project / "dist", assets)
    (project / "dist/old.whl").write_bytes(b"old")
    with pytest.raises(ValueError, match="unapproved release"):
        validate_assets(project / "dist", metadata, project)


def test_build_constraints_and_lock_must_agree(project):
    path = project / "build-constraints.txt"
    path.write_text(path.read_text().replace("--hash=sha256:", "--hash=sha256:0", 1))
    with pytest.raises(ValueError, match="exactly match"):
        validate_build_constraints(project)


def test_release_requires_exact_version_and_standalone_lock(project):
    with pytest.raises(ValueError, match="exactly match"):
        read_metadata(project, "v999.0.0")
    lock = project / "uv.lock"
    lock.write_text(
        lock.read_text().replace('editable = "."', 'editable = "../sdk"', 1)
    )
    with pytest.raises(ValueError, match="standalone lock"):
        read_metadata(project)


@pytest.fixture
def release_context(project, monkeypatch):
    from scripts import release_metadata

    metadata = read_metadata(project)
    path = project / "pyproject.toml"
    repository = tomllib.loads(path.read_text())["project"]["urls"]["Repository"]
    path.write_text(
        path.read_text().replace(
            repository, "https://github.com/example-owner/ipguard-api"
        )
    )
    monkeypatch.setattr(
        release_metadata,
        "_git",
        lambda root, command, *args: "" if command == "status" else SHA,
    )
    return metadata, {
        "tag": f"v{metadata.version}",
        "event_name": "push",
        "ref_type": "tag",
        "ref_name": f"v{metadata.version}",
        "event_sha": SHA,
        "tested_sha": SHA,
        "repository": "example-owner/ipguard-api",
    }


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("event_name", "pull_request"),
        ("ref_type", "branch"),
        ("ref_name", "master"),
        ("tag", "v999.0.0"),
        ("tested_sha", "b" * 40),
        ("event_sha", "bad"),
        ("repository", "different-owner/ipguard-api"),
    ],
)
def test_publication_context_rejects_unchecked_identity(
    project, release_context, field, value
):
    metadata, context = release_context
    context[field] = value
    with pytest.raises(ValueError):
        validate_release_context(project, metadata, **context)


def test_matching_context_is_accepted_and_placeholder_is_rejected(
    project, release_context
):
    metadata, context = release_context
    validate_release_context(project, metadata, **context)
    path = project / "pyproject.toml"
    path.write_text(path.read_text().replace("example-owner", "REPLACE_WITH_OWNER"))
    with pytest.raises(ValueError, match="real independent"):
        validate_release_context(project, metadata, **context)


def test_local_and_remote_moved_tags_are_rejected(
    project, release_context, monkeypatch
):
    from scripts import release_metadata

    metadata, context = release_context
    monkeypatch.setattr(release_metadata, "_git", lambda *args: "b" * 40)
    with pytest.raises(ValueError, match="must agree"):
        validate_release_context(project, metadata, **context)
    monkeypatch.setattr(
        release_metadata,
        "_git",
        lambda *args: f"{'b' * 40}\trefs/tags/{context['tag']}",
    )
    with pytest.raises(ValueError, match="Remote release tag"):
        validate_remote_tag(project, context["tag"], SHA)
    monkeypatch.setattr(
        release_metadata,
        "_git",
        lambda *args: (
            f"{'b' * 40}\trefs/tags/{context['tag']}\n{SHA}\trefs/tags/{context['tag']}^{{}}"
        ),
    )
    validate_remote_tag(project, context["tag"], SHA)


def test_remote_read_retries_are_bounded(project, monkeypatch):
    from scripts import release_metadata

    calls = []

    def fail(*args):
        calls.append(args)
        raise subprocess.TimeoutExpired("git", 30)

    monkeypatch.setattr(release_metadata, "_git", fail)
    monkeypatch.setattr(release_metadata.time, "sleep", lambda delay: None)
    with pytest.raises(ValueError, match="Cannot confirm"):
        validate_remote_tag(project, "v1.0.0", SHA)
    assert len(calls) == 3


def test_dirty_source_checkout_cannot_be_published(
    project, release_context, monkeypatch
):
    from scripts import release_metadata

    metadata, context = release_context
    monkeypatch.setattr(
        release_metadata,
        "_git",
        lambda root, command, *args: (
            " M src/ipguard_api/client.py" if command == "status" else SHA
        ),
    )
    with pytest.raises(ValueError, match="clean source checkout"):
        validate_release_context(project, metadata, **context)
