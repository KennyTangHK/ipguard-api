# ipguard-api

Source repository: [KennyTangHK/ipguard-api](https://github.com/KennyTangHK/ipguard-api). The default branch is `master`.

**Beta software.** This software is not a stable release.

This is an independent community project. It is not affiliated with, sponsored by, or endorsed by IPGUARD, NACD, or Noralsy.

Use this software lawfully. Use it only with your own authorized account and with buildings or doors that you have permission to access and control. Do not use it for unauthorized access or abuse.

**Use at your own risk.** To the extent permitted by applicable law, the software is provided without warranty. Its authors and contributors accept no responsibility or liability for its use. The warranty and liability limits in the [Apache-2.0 license](LICENSE) apply.

`ipguard-api` is a typed asynchronous Python library for an authorized IPGUARD cloud account. It supports phone and email enrollment, ZeroMQ CURVE connections, relay discovery, incoming-call callbacks, and explicit remote release commands. It does not depend on Home Assistant.

**Video calling and camera streaming are not supported.** By default, incoming calls give passive notifications. The library does not retain media offers or answer calls. To attempt one immediate hangup after the notification, set `auto_hangup=True` for the client. This attempt is intended to trigger carrier-call fallback sooner. The provider and account configuration determine the actual routing and timing.

For enrollment, saved sessions, event subscriptions, and command errors, see [API usage](docs/USAGE.md). For tests and release builds, see [Development](DEVELOPMENT.md).

The [package metadata](pyproject.toml) defines the Python and dependency requirements. The [lockfile](uv.lock) records the resolved dependencies. The PyPI package is `ipguard-api`; the import package is `ipguard_api`. The separate Home Assistant integration is at [hass-ipguard](https://github.com/KennyTangHK/hass-ipguard).

The [protocol implementation](src/ipguard_api/protocol.py) defines the protocol behavior. The [handset profile](src/ipguard_api/models.py) defines the client metadata values. Direct enrollment uses unencrypted TCP to retrieve the server public key. The authenticated channel then uses CURVE. A board acknowledgement does not show the physical state of a door. Bluetooth, SIP, pickup, and media transport and decoding are outside the scope of this library. Local fixtures test client behavior with synthetic accounts. They do not show current provider acceptance or physical door outcomes.

## Installation

After a release is published to PyPI, install the package:

```sh
python -m pip install --pre ipguard-api
```

The `--pre` option permits beta releases. To install this checkout, use `python -m pip install .`. For a locked test environment, see the [development guide](DEVELOPMENT.md). Installation and import do not enroll an account or open a connection.
