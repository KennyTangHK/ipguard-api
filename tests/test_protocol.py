"""Preserve wire shapes, eligibility and privacy boundaries from the app."""

from copy import deepcopy
from dataclasses import FrozenInstanceError, fields, replace
from datetime import timedelta
from unittest.mock import Mock
from uuid import uuid4

import pytest

from ipguard_api import (
    AndroidProfile,
    Board,
    IncomingCall,
    InvalidInputError,
    ProtocolError,
    Session,
    validate_identifier,
)
from ipguard_api.protocol import (
    MAX_CALL_SDP_BYTES,
    MAX_CALL_TOKEN_BYTES,
    MAX_INVENTORY_BOARDS,
    MAX_INVENTORY_SITES,
    MAX_MESSAGE_BYTES,
    MAX_MESSAGE_FRAMES,
    assert_android_metadata,
    configuration_password,
    decode_frames,
    door_inventory,
    envelope,
    hangup_call,
    hello,
    incoming_call,
    relay_inventory,
)


def test_mixed_transport_frames_do_not_dispatch_sip_control_or_noise():
    assert decode_frames([b"", b"not-json", b'{"action":"register","data":{}}']) is None
    assert (
        decode_frames(
            [b'{"action":"register","header":{"event":"srv_sp_delete"},"body":{}}']
        )
        is None
    )
    assert decode_frames([b'{"header":{"event":"hello"}}']) is None
    assert decode_frames(
        [b"routing-frame", b'{"header":{"event":"bc_sp_relays"},"body":{}}']
    ) == {"header": {"event": "bc_sp_relays"}, "body": {}}


def test_inventory_eligibility_uses_explicit_type_not_call_activity_or_mode():
    board = {
        "identity": "test-board",
        "relay_name": ["Door", "Bluetooth", "Pending"],
        "relay_active": [False, True, True],
        "relay_access_mobile_v2": [
            {"type": 0, "mode": 0},
            {"type": 1, "mode": 2},
            {"type": "2", "mode": 1},
        ],
    }
    modern = relay_inventory(
        {"sites": {"site": {"name": "Test site", "boards": [board]}}}
    )
    legacy = relay_inventory({"boards": [board]})
    assert [r.remote_allowed for r in modern] == [True, False, True]
    assert [r.remote_allowed for r in legacy] == [True, False, True]
    assert [r.number for r in modern] == [1, 2, 3]
    pending = relay_inventory({"boards": [{**board, "waitConfirmBadgeDigital": True}]})
    assert not any(r.remote_allowed for r in pending)
    invalid = relay_inventory(
        {
            "boards": [
                {
                    **board,
                    "relay_access_mobile_v2": [
                        {"type": None},
                        {"type": False},
                        {"type": ""},
                        {"type": 0},
                    ],
                }
            ]
        }
    )
    assert not any(r.remote_allowed for r in invalid)
    assert len(invalid) == 3
    unnamed = relay_inventory(
        {
            "boards": [
                {"identity": "test-board", "relay_access_mobile_v2": [{"type": 0}]}
            ]
        }
    )
    assert unnamed[0].name == "Relay 1" and unnamed[0].remote_allowed
    assert relay_inventory({"sites": {}}) == ()
    with pytest.raises(ProtocolError):
        relay_inventory({})


def test_configuration_accepts_array_or_numeric_object_without_inventing_fields():
    assert (
        configuration_password(
            envelope("test", "srv_sp_update", {"data": [{}, {"sip_pwd": "synthetic"}]})
        )
        == "synthetic"
    )
    assert (
        configuration_password(
            envelope("test", "srv_sp_update", {"data": {"1": {"sip_pwd": "synthetic"}}})
        )
        == "synthetic"
    )
    assert configuration_password(envelope("test", "srv_sp_update", {})) is None
    assert (
        configuration_password(
            envelope("test", "srv_sp_update", {"data": [{"sip_pwd": "wrong-index"}]})
        )
        is None
    )


def test_saved_profile_cannot_override_outgoing_android_strings():
    session = Session(
        str(uuid4()),
        validate_identifier("user@example.invalid"),
        "Personal phone",
        "012345",
        "opaque-key",
        android_profile=AndroidProfile(
            model="customclient", os_version="Node.js", connection_info="CLI"
        ),
    )
    packet = hello(session.identity, session.identifier, session)
    assert_android_metadata(packet)
    assert packet["body"]["data"]["os_version"] == "14"
    assert packet["body"]["data"]["connectionInfo"] == "WiFi"
    with pytest.raises(InvalidInputError):
        hello(session.identity, session.identifier, replace(session, label="CLI_app"))
    with pytest.raises(InvalidInputError):
        assert_android_metadata(
            envelope(
                session.identity,
                "sp_srv_check_username",
                {"username": "Personal phone", "model": "Node.js CLI"},
            )
        )
    assert_android_metadata(
        envelope(session.identity, "sp_srv_update_ack", {}, "opaque_Node.js_CLI_token")
    )


def test_canonical_android_greeting_shapes(monkeypatch):
    import ipguard_api.protocol as protocol

    identity = "00000000-0000-0000-0000-000000000001"
    identifier = validate_identifier("+44 7700 900123")
    clock = Mock()
    clock.now.return_value.astimezone.return_value.utcoffset.return_value = timedelta(
        hours=1
    )
    monkeypatch.setattr(protocol, "datetime", clock)
    monkeypatch.setattr(protocol.time, "time_ns", lambda: 1234567890000000)
    monkeypatch.setattr(protocol, "uuid4", lambda: "test-correlation-token")
    data = {
        "fcm_token": "",
        "without_sip": True,
        "os_version": "14",
        "language": "en_GB",
        "timezone": 3600,
        "weektypes": [[], [], [], [], [], [], []],
        "connectionInfo": "WiFi",
    }
    expected = {
        "header": {"event": "hello", "sender": identity, "timestamp": 1234567890},
        "body": {
            "type": 0,
            "version": "3.4.8",
            "data": data,
            "token": "test-correlation-token",
        },
    }
    assert hello(identity, identifier, None) == expected
    assert_android_metadata(expected)
    session = Session(identity, identifier, "Personal phone", "012345", "synthetic-key")
    secure = deepcopy(expected)
    secure["body"]["data"].update(
        {
            "username": "Personal phone",
            "phone": "00447700900123",
            "email": "",
            "akey": "",
            "code": "012345",
        }
    )
    assert hello(identity, identifier, session) == secure
    assert_android_metadata(secure)
    pending = replace(session, status=protocol.SessionStatus.PENDING)
    secure["body"]["data"]["username"] = ""
    assert hello(identity, identifier, pending) == secure


@pytest.mark.parametrize(
    "kind,value",
    [("phone", "00447700900123"), ("email", "customclient@example.invalid")],
)
def test_canonical_android_request_bodies_preserve_opaque_authorization(kind, value):
    identity, token = "test-installation", "opaque_Node.js_CLI_token"
    bodies = {
        "sp_srv_check_auth": {kind: value},
        "sp_srv_validate_auth": {kind: value, "code": "012345"},
        "sp_srv_ask_key": {kind: value, "code": "012345"},
        "sp_srv_check_username": {
            kind: value,
            "code": "012345",
            "username": "Personal phone",
            "model": "Pixel 7",
        },
        "sp_srv_override_username": {
            kind: value,
            "code": "012345",
            "username": "Personal phone",
            "model": "Pixel 7",
        },
        "sp_srv_update_ack": {},
        "sp_brd_open_door": {"door": 1},
    }
    for event, body in bodies.items():
        packet = envelope(identity, event, body, token)
        assert packet["body"] == {**body, "token": token}
        assert set(packet["header"]) == {"event", "sender", "timestamp"}
        assert_android_metadata(packet)


@pytest.mark.parametrize(
    "location,key,value",
    [
        ("packet", "User-Agent", "Python"),
        ("header", "User-Agent", "Node.js"),
        ("header", "timestamp", True),
        ("body", "platform", "customclient"),
        ("body", "type", False),
        ("data", "User-Agent", "curl"),
        ("data", "os_version", "Python"),
        ("data", "language", "CLI"),
        ("data", "connectionInfo", "Home Assistant"),
        ("data", "fcm_token", "token"),
        ("data", "without_sip", 1),
        ("data", "weektypes", [[], []]),
        ("data", "timezone", True),
        ("data", "timezone", 86401),
        ("data", "username", "CLI_app"),
    ],
)
def test_outgoing_greeting_rejects_unobserved_fields_and_metadata(location, key, value):
    session = Session(
        "test-installation",
        validate_identifier("user@example.invalid"),
        "Personal phone",
        "012345",
        "key",
    )
    packet = hello(session.identity, session.identifier, session)
    target = {
        "packet": packet,
        "header": packet["header"],
        "body": packet["body"],
        "data": packet["body"]["data"],
    }[location]
    target[key] = value
    with pytest.raises(InvalidInputError):
        assert_android_metadata(packet)


@pytest.mark.parametrize(
    "event,body",
    [
        ("unknown-event", {}),
        ("sp_brd_open_door", {"door": True}),
        ("sp_brd_open_door", {"door": 4}),
        ("sp_brd_open_door", {"door": 1, "User-Agent": "curl"}),
        ("sp_srv_check_auth", {"phone": "+447700900123"}),
        (
            "sp_srv_check_auth",
            {"phone": "00447700900123", "email": "user@example.invalid"},
        ),
        ("sp_srv_check_auth", {}),
        ("sp_srv_check_auth", {"email": "user@example.invalid", "platform": "android"}),
        ("sp_srv_update_ack", {"model": "Pixel 7"}),
    ],
)
def test_outgoing_request_rejects_unobserved_shapes(event, body):
    with pytest.raises(InvalidInputError):
        assert_android_metadata(envelope("test-installation", event, body))


@pytest.mark.parametrize(
    ("event", "body"),
    [
        ("sp_ps_sdp_answer", {"remoteIdentity": "board", "sdp": "dj0wDQo="}),
        ("sp_ps_sip_ring", {"remoteIdentity": "board"}),
        ("sp_ps_ring_ack", {}),
        ("sp_brd_pickup_call", {"media": ["audio"]}),
    ],
)
def test_outgoing_call_control_is_unsupported(event, body):
    with pytest.raises(InvalidInputError):
        assert_android_metadata(
            envelope(
                "test-installation",
                event,
                body,
                "private-call-token",
            )
        )


def test_hangup_has_only_original_token_and_numeric_zero_cause():
    token = "opaque_CLI_Node.js_Home Assistant_å_token"
    packet = hangup_call("test-installation", token)
    assert packet["header"]["event"] == "sp_brd_hangup_call"
    assert packet["header"]["sender"] == "test-installation"
    assert packet["body"] == {"token": token, "cause": 0}
    assert type(packet["body"]["cause"]) is int
    assert_android_metadata(packet)


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"cause": True},
        {"cause": False},
        {"cause": "0"},
        {"cause": 0.0},
        {"cause": 1},
        {"cause": -1},
        {"cause": 0, "remoteIdentity": "board"},
        {"cause": 0, "sdp": "dj0wDQo="},
    ],
)
def test_hangup_rejects_any_other_shape(body):
    with pytest.raises(InvalidInputError):
        assert_android_metadata(
            envelope("test-installation", "sp_brd_hangup_call", body, "call-token")
        )


@pytest.mark.parametrize(
    "token", [None, False, 0, "", " ", "a\0b", "a\nb", "x" * 1025, "\ud800"]
)
def test_hangup_rejects_invalid_call_tokens(token):
    with pytest.raises(InvalidInputError):
        hangup_call("test-installation", token)


def test_incoming_frame_limits_and_aggregate_bounds():
    assert decode_frames([b""] * MAX_MESSAGE_FRAMES) is None
    assert decode_frames([b" " * MAX_MESSAGE_BYTES]) is None
    with pytest.raises(ProtocolError):
        decode_frames([b""] * (MAX_MESSAGE_FRAMES + 1))
    with pytest.raises(ProtocolError):
        decode_frames([b" " * MAX_MESSAGE_BYTES, b"x"])


def test_inventory_site_and_total_board_caps_count_invalid_entries():
    assert (
        relay_inventory(
            {"sites": {str(i): {"boards": []} for i in range(MAX_INVENTORY_SITES)}}
        )
        == ()
    )
    assert relay_inventory({"boards": [None] * MAX_INVENTORY_BOARDS}) == ()
    with pytest.raises(ProtocolError):
        relay_inventory(
            {"sites": {str(i): {"boards": []} for i in range(MAX_INVENTORY_SITES + 1)}}
        )
    with pytest.raises(ProtocolError):
        relay_inventory({"boards": [None] * (MAX_INVENTORY_BOARDS + 1)})
    with pytest.raises(ProtocolError):
        relay_inventory(
            {"sites": {"a": {"boards": [None] * 513}, "b": {"boards": [None] * 512}}}
        )
    boards = [
        {"identity": f"board-{i}", "relay_access_mobile_v2": [{"type": 0}]}
        for i in range(MAX_INVENTORY_BOARDS)
    ]
    assert len(relay_inventory({"boards": boards})) == MAX_INVENTORY_BOARDS


@pytest.mark.parametrize(
    "identity", ["x" * 256, "é" * 128, "bad\ud800", "bad\0identity"]
)
def test_service_board_routing_identity_validation(identity):
    with pytest.raises(ProtocolError):
        relay_inventory(
            {
                "boards": [
                    {"identity": identity, "relay_access_mobile_v2": [{"type": 0}]}
                ]
            }
        )
    assert relay_inventory(
        {"boards": [{"identity": "x" * 255, "relay_access_mobile_v2": [{"type": 0}]}]}
    )[0].remote_allowed


def test_inventory_reads_only_first_three_relay_permissions():
    class LimitedReads(list):
        def __iter__(self):
            raise AssertionError("The entire service relay list must not be scanned.")

    permissions = LimitedReads([{"type": 0}] * 10000)
    result = relay_inventory(
        {"boards": [{"identity": "board", "relay_access_mobile_v2": permissions}]}
    )
    assert len(result) == 3


def test_incoming_call_model_contains_only_a_frozen_known_board():
    board = Board("known-board", name="Entrance")
    call = IncomingCall(board)
    assert [field.name for field in fields(call)] == ["board"]
    assert IncomingCall().board is None
    with pytest.raises(FrozenInstanceError):
        call.board = None


def test_board_inventory_retains_boards_without_relay_permissions():
    boards, relays = door_inventory(
        {
            "sites": {
                "building": {
                    "name": "Building",
                    "boards": [
                        {"identity": "board", "name": "Entrance", "secret": "private"}
                    ],
                }
            }
        }
    )
    assert relays == ()
    assert boards == (
        Board("board", name="Entrance", site_id="building", site_name="Building"),
    )
    assert "private" not in repr(boards)


@pytest.mark.parametrize(
    "location,key",
    [
        ("header", "sender"),
        ("body", "token"),
        ("body", "remoteIdentity"),
        ("body", "sdp"),
    ],
)
def test_missing_offer_fields_are_ignored(location, key):
    packet = envelope(
        "sender",
        "ps_sp_sdp_offer",
        {"remoteIdentity": "board", "sdp": "dj0wDQo="},
        "token",
    )
    del packet[location][key]
    assert incoming_call(packet, {}) is None


def test_call_field_bounds_are_encoded_byte_limits_and_tokens_are_opaque():
    import base64

    board = Board("x" * 255)
    packet = envelope(
        "s" * 255,
        "ps_sp_sdp_offer",
        {
            "remoteIdentity": board.identity,
            "sdp": base64.b64encode(
                b"v=0\r\n" + b"x" * (MAX_CALL_SDP_BYTES * 3 // 4 - 5)
            ).decode(),
        },
        "é" * (MAX_CALL_TOKEN_BYTES // 2),
    )
    assert len(packet["body"]["sdp"]) == MAX_CALL_SDP_BYTES
    parsed = incoming_call(packet, {board.identity: board})
    assert parsed is not None and parsed[0] == IncomingCall(board)
    assert len(parsed[1]) == 32
    packet["body"]["token"] += "x"
    assert incoming_call(packet, {}) is None
    packet["body"]["token"] = "opaque_Node.js_CLI_token"
    assert incoming_call(packet, {}) is not None
    packet["header"]["event"] = "srv_sp_sdp_offer"
    assert incoming_call(packet, {}) is None


@pytest.mark.parametrize("field", ["name", "site_id", "site_name"])
@pytest.mark.parametrize(
    "value",
    [
        None,
        "",
        " ",
        "bad\0metadata",
        "bad\tmetadata",
        "bad\nmetadata",
        "bad\x7fmetadata",
        "bad\x85metadata",
        "bad\u202emetadata",
        "bad\ud800metadata",
        "x" * 257,
        "é" * 129,
    ],
)
def test_call_projection_omits_invalid_optional_board_metadata(field, value):
    original = replace(
        Board("board", name="Entrance", site_id="building", site_name="Building"),
        **{field: value},
    )
    packet = envelope(
        "sender",
        "ps_sp_sdp_offer",
        {"remoteIdentity": "board", "sdp": "dj0wDQo="},
        "token",
    )
    parsed = incoming_call(packet, {original.identity: original})
    assert parsed is not None
    board = parsed[0].board
    assert board is not None and board.identity == original.identity
    assert not getattr(board, field)
    assert getattr(original, field) == value


@pytest.mark.parametrize("field", ["name", "site_id", "site_name"])
@pytest.mark.parametrize("value", ["x" * 256, "é" * 128, "😀" * 64, "Étage principal"])
def test_call_projection_accepts_printable_optional_metadata_byte_boundaries(
    field, value
):
    original = replace(
        Board("board", name="Entrance", site_id="building", site_name="Building"),
        **{field: value},
    )
    packet = envelope(
        "sender",
        "ps_sp_sdp_offer",
        {"remoteIdentity": "board", "sdp": "dj0wDQo="},
        "token",
    )
    parsed = incoming_call(packet, {original.identity: original})
    assert parsed is not None and parsed[0].board == original


def test_call_projection_preserves_original_release_inventory_metadata():
    boards, relays = door_inventory(
        {
            "sites": {
                "private\0site-id": {
                    "name": "private\ud800site-name",
                    "boards": [
                        {
                            "identity": "board",
                            "name": "x" * 257,
                            "relay_access_mobile_v2": [{"type": 0}],
                        }
                    ],
                }
            }
        }
    )
    original = boards[0]
    packet = envelope(
        "sender",
        "ps_sp_sdp_offer",
        {"remoteIdentity": "board", "sdp": "dj0wDQo="},
        "token",
    )
    parsed = incoming_call(packet, {original.identity: original})
    assert parsed is not None
    assert parsed[0].board == Board("board")
    assert relays[0].board is original
    assert original.name == "x" * 257
    assert original.site_id == "private\0site-id"
    assert original.site_name == "private\ud800site-name"


def test_call_projection_omits_unused_device_metadata_without_changing_inventory():
    original = Board(
        "board", device_id="private\0device" * 1000, device_type="private\ud800type"
    )
    packet = envelope(
        "sender",
        "ps_sp_sdp_offer",
        {"remoteIdentity": "board", "sdp": "dj0wDQo="},
        "token",
    )
    parsed = incoming_call(packet, {original.identity: original})
    assert parsed is not None and parsed[0].board == Board("board")
    assert "private" not in repr(parsed[0])
    assert original.device_id == "private\0device" * 1000
    assert original.device_type == "private\ud800type"
