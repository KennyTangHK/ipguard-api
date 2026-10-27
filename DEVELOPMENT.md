# Development

This repository builds and tests `ipguard-api` independently. It does not require Home Assistant, a workspace member, or a sibling checkout. [pyproject.toml](pyproject.toml) declares the runtime requirements and development tools. [uv.lock](uv.lock) records the resolved versions and hashes. Use the interpreter selected by [.python-version](.python-version). Use the `uv` version pinned in the [checks workflow](.github/workflows/checks.yml).

## Local checks

```sh
uv sync --locked
uv run --no-sync ruff check .
uv run --no-sync ruff format --check .
uv run --no-sync mypy
uv run --no-sync pytest
uv run --no-sync python -m scripts.release_metadata
uv build --build-constraints build-constraints.txt --require-hashes
uv run --no-sync python -m scripts.release_metadata --dist dist --write-checksums
```

Use a clean `dist` directory when you build a different version. Validation rejects stale or unexpected archives. The development environment and caches are local and ignored.

`conftest.py` guards ordinary Python sockets, DNS resolution, and native ZeroMQ connections. It permits only loopback or in-process fixtures. Tests use synthetic accounts. Tests must not contact the provider, send verification messages, replace a mobile installation, answer a call, or actuate a physical door. Secure transport tests require native ZeroMQ CURVE support.

The package tests build the wheel and source distribution in temporary directories. They verify exact contents and metadata. They also test rejection of altered or extra files, unsafe paths, links, changed checksums, and invalid release identity. Network-guard tests verify the Python and native ZeroMQ restrictions. CI also runs the pinned `actionlint` workflow validator.

## Package boundaries

The explicit Hatch `only-include` lists in [pyproject.toml](pyproject.toml) are the authoritative package allowlists. The wheel contains only `ipguard_api`, its type marker, the license, and generated metadata. The source distribution also contains the development-only test harness (`conftest.py`), package validators, usage and development documentation, and reproducible environment inputs. It does not contain local credentials, caches, application artifacts, or integration files.

[scripts/packaging_policy.py](scripts/packaging_policy.py) checks all allowed source bytes. It rejects stray or missing source files, symbolic links, unsafe archive paths, and duplicate members. Wheel RECORD hashes and sizes must describe exactly the approved payload. [scripts/release_metadata.py](scripts/release_metadata.py) also checks the distribution identity, runtime requirements, README, license, URLs, Python requirements, and pure-Python wheel tags against the checked source. Both archives must match their SHA-256 manifest.

[build-constraints.txt](build-constraints.txt) pins and hashes the complete isolated Hatch build dependency set. It must agree exactly with the lockfile and the build backend declaration. When you change the backend, review and update all three together. Do not relax an allowlist or hash check to make an unexpected build pass.

## Publishing to PyPI

The SDK repository is [KennyTangHK/ipguard-api](https://github.com/KennyTangHK/ipguard-api). Its default branch is `master`. Ordinary CI checks run on pushes to `master` and on pull requests.

The package is available on [PyPI](https://pypi.org/project/ipguard-api/). Releases use Trusted Publishing from `KennyTangHK/ipguard-api`, workflow `publish.yml`, and GitHub environment `pypi`. If the repository, workflow filename, or environment changes, update the [PyPI trusted publisher](https://docs.pypi.org/trusted-publishers/adding-a-publisher/) before the next release.

To publish a release:

1. Set the intended `X.Y.Z` version in [pyproject.toml](pyproject.toml). Keep the beta notice and Beta development-status classifier while the project is in beta. Run `uv lock` and the local checks. Review the lockfile change. A package version change must not silently upgrade external dependencies.
2. Commit and push the reviewed changes to `master` in the independent SDK repository.
3. Push the matching `vX.Y.Z` tag. The tag must match the committed package version exactly. Do not move or reuse a published tag or version.

The [publication workflow](.github/workflows/publish.yml) calls the checks workflow for the tagged commit. It downloads the three checked assets from that run. It then validates the event, tag, clean checkout, tested commit, remote tag, archive payloads, and hashes again. It stages only the two validated distribution archives for upload.

The separate publishing job uses the `pypi` environment. Only this job receives `id-token: write`. Ordinary checks have read-only repository access. [PyPA's publishing action](https://github.com/pypa/gh-action-pypi-publish) uses [Trusted Publishing](https://docs.pypi.org/trusted-publishers/using-a-publisher/) and produces attestations. It does not need a stored PyPI password or API token.

If no source changes are necessary, you can rerun a failed run from GitHub Actions or manually dispatch it against the same tag. The workflow rejects branch dispatches. Publication does not skip existing distributions. After an uncertain or partial upload, inspect PyPI before you decide what to release next. A source or workflow fix requires a new version and tag. Published artifacts are never overwritten. Publishing the SDK does not release the separate Home Assistant integration.

## Runtime invariants

Keep the Android handset profile independent of package releases. Human-readable provider metadata uses the configured Android strings. Preserve opaque identifiers, credentials, and call tokens exactly. Enrollment, resends, and installation replacement must remain explicit. Release operations must check current permission, reject busy or unavailable operations, and never queue or replay a command with an uncertain outcome.

Incoming-call callbacks expose only sanitized board information. The SDK is passive by default. An explicit `auto_hangup=True` enables one immediate hangup attempt with cause zero after notification. The SDK does not retain media offers, answer calls, or implement media transport. Disconnect and shutdown cancel owned work. The SDK never replays uncertain attempts.

Store credentials in the consumer's private session storage. Keep raw packets, session contents, arbitrary provider errors, call tokens, and media data out of logs, tracebacks, and callback data. [README.md](README.md) and [API usage](docs/USAGE.md) document the plaintext enrollment stage and other protocol limits. Synthetic tests show local client behavior. They do not show current provider acceptance, account-wide routing guarantees, or physical door outcomes.
