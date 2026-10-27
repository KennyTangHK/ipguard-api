# API usage

Create the asynchronous client in an active event loop. Always close it or use its async context manager. Client construction and cached properties do not send messages. Enrollment and release occur only when you call the related methods.

## Enrollment

```python
from ipguard_api import ExistingInstallationError, IpguardClient


async def enroll(identifier: str, label: str, read_code):
    async with IpguardClient() as client:
        await client.async_request_verification(identifier, label)
        code = await read_code()
        await client.async_verify_code(code)
        try:
            return await client.async_complete_registration()
        except ExistingInstallationError:
            # Ask the user before explicitly requesting replacement.
            raise
```

Use the email address or international phone number registered to the account. The client normalizes phone numbers to the Android API's `00` format. Keep verification codes as strings of six ASCII digits. Include leading zeros. Use a personal name or Android device name as the installation label. The handset model is separate and is fixed to `Pixel 7`.

`async_request_verification` requests an SMS or email. It resets the challenge credentials but preserves the identity for the same pending account. A second call explicitly requests a resend. `async_verify_code` validates the code and gets a server public key. `async_complete_registration` performs secure registration, requires fresh configuration and relay inventory, and returns an activated `Session`.

If registration would replace an installation, the client raises `ExistingInstallationError`. Replacement can disable the previous installation. After the user gives explicit consent, call `async_complete_registration(replace_existing=True)`. If the connection is interrupted while you wait for consent, do not send another code or replacement command without an explicit call. Enrollment and discovery do not test a physical release.

## Saved authorization and updates

Store `Session.to_dict()` in private storage. It contains credentials. Its `repr` omits sensitive fields. Use `Session.from_dict(data)` to restore it. Restoration alone does not authenticate the session.

```python
from ipguard_api import IpguardClient, Session


async def observe(saved_data, on_snapshot):
    session = Session.from_dict(saved_data)
    async with IpguardClient(session=session) as client:
        unsubscribe = client.subscribe(on_snapshot)
        try:
            await client.async_connect(session)
            return await client.async_get_relays()
        finally:
            unsubscribe()
```

For normal startup, call `async_connect`. This does not request a code or replace an installation. Keep the context open to receive cloud pushes. `subscribe` registers a synchronous event-loop callback and returns an unsubscribe function. Do not block inside a callback.

A `ClientSnapshot` contains cached relays, connection and revocation flags, a classified error, and the current session. If credentials change, explicitly serialize the session to save them. `client.connected`, `client.session`, and `client.snapshot` read cached values. Background recovery uses bounded exponential backoff and the saved session. Revocation stops reconnection and requires user-driven enrollment. `async_close` closes sockets, cancels recovery, and clears callbacks. You can call it more than once.

## Incoming calls

Call `subscribe_calls` before you connect, and keep the client open. It registers a synchronous event-loop callback and returns an unsubscribe function:

```python
from ipguard_api import IncomingCall, IpguardClient, Session


async def listen(saved_data, stop):
    def on_call(call: IncomingCall) -> None:
        print(call.board.name if call.board else "Incoming intercom call")

    session = Session.from_dict(saved_data)
    async with IpguardClient(session=session) as client:
        unsubscribe = client.subscribe_calls(on_call)
        try:
            await client.async_connect(session)
            await stop.wait()
        finally:
            unsubscribe()
```

`IncomingCall` contains only an optional `Board`. The client matches the board by exact identity against the latest cached inventory. Unknown or ambiguous callers still cause a callback, with `board=None`. Malformed or oversized optional board and site labels, and site identities, are omitted. Callback data does not expose call tokens, routing senders, SDP, or media credentials. The client validates and discards media descriptions. Offers must come from the current authenticated transport for an activated installation. The client ignores malformed offers and continues relay updates.

Callbacks can arrive before `async_connect` completes, including during reconnection. If your interface is not ready, briefly buffer sanitized notifications. With the default constructor, call receipt does not acknowledge an offer, answer, pick up, hang up, or negotiate media. The client does not use Firebase. Delivery depends on the provider routing the call to the active account connection.

The client suppresses repeated offers in a bounded in-memory cache. The cache expires after inactivity. It stays available across reconnects for the same installation. Explicit close or an installation change clears it. The client does not fetch or replay disconnected call history.

Video calling and camera streaming are not supported. The SDK has no API to retain offers, answer calls, or manage media sessions. It does not send ring acknowledgements or pickup commands.

### Automatic hangup

`IpguardClient(auto_hangup=True)` enables one immediate hangup attempt after each fresh, validated incoming-call notification. This is intended to trigger carrier-call fallback sooner. The provider and account configuration determine the actual routing and timing. The standalone SDK defaults to `auto_hangup=False`. In that mode, it gives incoming-call notifications without sending a hangup. Home Assistant has an **Auto hangup** option for each account. It is enabled by default. Find it under **Settings → Devices & services → IPGUARD → Configure**.

An attempt requires a current call, connection, and installation. The client skips busy, stale, disconnected, or superseded attempts. Call termination, disconnect, or shutdown cancels pending work. The client does not queue or replay attempts. It does not retry a send with an uncertain outcome. Duplicate suppression stays available across reconnects for the same installation. It does not persist after the client closes or the process restarts. The SDK has no manual hangup or call-answering API.

Sanitized DEBUG messages report `IPGUARD auto hangup outcome=attempted`, `sent`, `uncertain`, or `skipped`. `sent` confirms only a local transport write. It does not confirm carrier-call delivery.

## Release one relay

Select a current `Relay` with `remote_allowed=True` and no pending confirmation. Only for a deliberate user action, call `await client.async_release(relay.board_identity, relay.number)`. The SDK accepts relay numbers from 1 to 3.

The SDK checks the current permission and rejects a concurrent release for the same relay. It does not queue actions for a later connection. Success means that the board sent a matching acknowledgement. It does not show whether the door is physically open or closed.

`OutcomeUnknownError` means that the command can have reached the board. Report the uncertainty and do not replay the command automatically. `ReleaseRejectedError` reports a matching rejection. `RelayUnavailableError` covers absent or unpermitted relays. `AuthRevokedError` requires enrollment. `ConnectionFailureError` reports ordinary connection failures. All these errors derive from `IpguardError`. Authentication failures derive from `AuthenticationError`.

## Transport and logging

The default activation endpoint is `tcp://zmq.campiserveur.com:5579`. The default secure messaging endpoint is `tcp://zmq.campiserveur.com:5577`. Activation uses unencrypted TCP, including for retrieval of the server public key. CURVE protects the subsequent authenticated connection. The client does not implement an encrypted enrollment fallback. Do not disable CURVE authentication to work around handshake failures.

The constructor accepts test endpoints, `timeout`, `reconnect_delay`, and `max_reconnect_delay`. Saved sessions retain their endpoints.

Enable `ipguard_api` at DEBUG level for sanitized stage and event information. Outgoing metadata uses Android app values or mock Android handset details from the [handset profile](../src/ipguard_api/models.py). The [protocol implementation](../src/ipguard_api/protocol.py) validates these values. Do not log raw packets, identifiers, UUIDs, codes, passwords, keys, tokens, or arbitrary server text.

The supported timeout range is 0.001–300 seconds. Reconnect delays are 0.001–3,600 seconds. The maximum delay must be at least the initial delay. Routing identities must be valid UTF-8, with a maximum of 255 bytes and no NUL. Service messages are limited to 16 frames and 8 MiB in total. Inventory updates permit a maximum of 256 sites and 1,024 board entries. An oversized inventory update fails as a whole. These limits do not change saved session serialization.
