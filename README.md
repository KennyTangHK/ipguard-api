# ipguard-api

An asynchronous Python client for the IPGUARD cloud service. Connect an existing account, discover door relays, receive incoming-call notifications, and send door-release commands.

**Beta software.** This software is not a stable release.

This is an independent community project. It is not affiliated with, sponsored by, or endorsed by IPGUARD, NACD, or Noralsy.

Use this software lawfully. Use it only with your own authorized account and with buildings or doors that you have permission to access and control. Do not use it for unauthorized access or abuse.

**Use at your own risk.** To the extent permitted by applicable law, the software is provided without warranty. Its authors and contributors accept no responsibility or liability for its use. The warranty and liability limits in the [Apache-2.0 license](LICENSE) apply.

## Installation

Install from [PyPI](https://pypi.org/project/ipguard-api/):

```sh
python -m pip install --pre ipguard-api
```

The `--pre` option includes beta releases. See the [API guide](docs/USAGE.md) for account setup and examples.

## Limitations

**Video calling and camera streaming are not supported.** The client does not answer calls or provide audio conversation, Bluetooth access, SIP calling, or manual call controls.

Incoming-call notifications are passive by default. Set `auto_hangup=True` to make one immediate hangup attempt after a notification. This is intended to trigger carrier-call fallback sooner. The provider and account configuration determine the actual routing and timing.

Enrollment uses unencrypted TCP, including retrieval of the server public key. The authenticated connection then uses ZeroMQ CURVE. A door-release acknowledgement does not confirm that the physical door opened. See [transport and logging](docs/USAGE.md#transport-and-logging) for details. Tests use synthetic accounts and do not establish current provider acceptance or physical door outcomes.

## Development

See the [development guide](DEVELOPMENT.md) for local setup, tests, and releases.

For Home Assistant, use [hass-ipguard](https://github.com/KennyTangHK/hass-ipguard). This Python library can also be used independently.
