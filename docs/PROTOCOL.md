# Protocol behavior and compatibility limits

This document describes the behavior and limits of `ipguard-api`. The library supports account enrollment, saved authorization, relay discovery, door-release commands and incoming-call notifications. For client setup and code examples, see [API usage](USAGE.md).

## Enrollment and saved authorization

Verification requests and resends require an explicit method call. A reconnection with saved authorization does not request another code or replace an installation. The library refuses replacement by default. The application must obtain user consent before it enables replacement, which can disable the previous installation. Revoked authorization stops reconnection and requires enrollment again.

Serialized sessions contain the account identifier, installation UUID, verification code, server public key and any activation credential returned by the service. The application is responsible for private storage of this data. Treat serialized sessions and their backups as credentials. Do not include them in issue reports or debug captures. The SDK omits credentials, raw packets and arbitrary provider error text from diagnostics.

## Transport security

The default enrollment endpoint is `tcp://zmq.campiserveur.com:5579`. This connection is not encrypted. The client gets the server public key during that exchange. ZeroMQ CURVE then protects the authenticated connection at `tcp://zmq.campiserveur.com:5577` with that key.

CURVE does not protect the earlier enrollment exchange. Enrollment does not use HTTPS, and the SDK has no encrypted enrollment fallback. Do not disable CURVE authentication to work around connection failures.

## Door-release commands

A relay can receive a release command only if it has current remote-release permission and does not need badge confirmation. The SDK checks permission immediately before transmission. It rejects unavailable or busy operations. It does not put a release command in a queue for a later connection.

A successful result means that the board sent a matching acknowledgement. It does not show if the physical door moved, or if it is open or locked. If a command may have been sent but there is no matching acknowledgement, its outcome is unknown. The SDK does not automatically replay release commands. The application must report the uncertainty and leave any further attempt to the user.

## Incoming calls

A fresh, validated incoming call on the active account connection causes a callback. Callbacks include sanitized board information when the caller can be identified. Unknown callers still cause a callback. The SDK suppresses duplicates for a limited time. It validates and discards media descriptions. It does not expose call tokens, caller routes or media credentials through callbacks. Calls missed during a disconnection are not recovered.

The SDK is passive by default. It does not acknowledge, answer or hang up an incoming call. An application can set `auto_hangup=True` to enable one immediate hangup attempt after notification. This is intended to start carrier-call fallback sooner. Routing and timing depend on the provider and account configuration. The SDK skips the attempt if the call or connection is no longer current or the write is busy. It cancels pending work on disconnect or close. It does not queue, retry or replay an uncertain write. See [Automatic hangup](USAGE.md#automatic-hangup) for client configuration.

Video calls, camera streaming, audio conversation, call answering, manual call controls, Firebase, Bluetooth and SIP calling are not supported. Incoming calls do not cause a door release.

## Verification limits

Automated SDK tests use synthetic accounts and loopback plaintext/CURVE servers. These checks validate client behavior against fixtures. They do not establish current provider acceptance, credential lifetime, account aliases, simultaneous mobile installations, incoming-call delivery, carrier routing or a physical door release. Routing and delivery depend on the provider and account configuration. A live account or physical check requires explicit user direction.
