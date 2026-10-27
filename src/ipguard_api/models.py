"""Typed account authorization and relay discovery models.

Credential fields are omitted from representations. Explicit session serialization
still contains credentials and must be treated as confidential.
"""

from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from enum import StrEnum

from .errors import InvalidInputError, IpguardError

DEFAULT_ACTIVATION_ENDPOINT = "tcp://zmq.campiserveur.com:5579"
DEFAULT_SECURE_ENDPOINT = "tcp://zmq.campiserveur.com:5577"


class IdentifierKind(StrEnum):
    """Email and phone identifiers supported for enrollment."""

    EMAIL = "email"
    PHONE = "phone"


class SessionStatus(StrEnum):
    """Enrollment phase used to interpret server reset notices."""

    PENDING = "pending"
    ACTIVATED = "activated"
    DISABLED = "disabled"


@dataclass(frozen=True, slots=True)
class AuthIdentifier:
    """A registered email or API-normalized international telephone number."""

    kind: IdentifierKind
    value: str = field(repr=False)

    def to_dict(self) -> dict[str, str]:
        """Return the identifier for explicit, confidential persistence."""
        return {"kind": self.kind.value, "value": self.value}


@dataclass(frozen=True, slots=True)
class AndroidProfile:
    """Static Android metadata used for provider-facing messages."""

    model: str = "Pixel 7"
    os_version: str = "14"
    connection_info: str = "WiFi"
    language: str = "en_GB"
    app_version: str = "3.4.8"


@dataclass(frozen=True, slots=True)
class Session:
    """Authorization for one enrolled installation, not a canonical account ID.

    The installation label differs from the UUID used for routing and SIP
    authorization. The server public key is a CURVE key rather than a bearer
    token. No model field implies current physical door or lock state.
    """

    identity: str = field(repr=False)
    identifier: AuthIdentifier = field(repr=False)
    label: str = field(repr=False)
    verification_code: str = field(repr=False)
    server_public_key: str = field(repr=False)
    sip_password: str | None = field(default=None, repr=False)
    android_profile: AndroidProfile = field(default_factory=AndroidProfile)
    activation_endpoint: str = DEFAULT_ACTIVATION_ENDPOINT
    secure_endpoint: str = DEFAULT_SECURE_ENDPOINT
    status: SessionStatus = SessionStatus.ACTIVATED

    def to_dict(self) -> dict[str, object]:
        """Return a credential-bearing config-entry payload without redaction."""
        return {
            "identity": self.identity,
            "identifier": self.identifier.to_dict(),
            "label": self.label,
            "verification_code": self.verification_code,
            "server_public_key": self.server_public_key,
            "sip_password": self.sip_password,
            "android_profile": asdict(self.android_profile),
            "activation_endpoint": self.activation_endpoint,
            "secure_endpoint": self.secure_endpoint,
            "status": self.status.value,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> Session:
        """Restore a serialized session; this does not authenticate or connect."""
        identifier = data.get("identifier")
        profile = data.get("android_profile", {})
        if not isinstance(identifier, Mapping) or not isinstance(profile, Mapping):
            raise InvalidInputError("Invalid saved session structure.")
        try:
            kind = IdentifierKind(_text(identifier, "kind"))
            status = SessionStatus(_text(data, "status", SessionStatus.ACTIVATED.value))
        except ValueError:
            raise InvalidInputError("Invalid saved identifier kind.") from None
        password = data.get("sip_password")
        if password is not None and not isinstance(password, str):
            raise InvalidInputError("Invalid saved session credential type.")
        defaults = AndroidProfile()
        return cls(
            identity=_text(data, "identity"),
            identifier=AuthIdentifier(kind, _text(identifier, "value")),
            label=_text(data, "label"),
            verification_code=_text(data, "verification_code"),
            server_public_key=_text(data, "server_public_key"),
            sip_password=password,
            android_profile=AndroidProfile(
                model=_text(profile, "model", defaults.model),
                os_version=_text(profile, "os_version", defaults.os_version),
                connection_info=_text(
                    profile, "connection_info", defaults.connection_info
                ),
                language=_text(profile, "language", defaults.language),
                app_version=_text(profile, "app_version", defaults.app_version),
            ),
            activation_endpoint=_text(
                data, "activation_endpoint", DEFAULT_ACTIVATION_ENDPOINT
            ),
            secure_endpoint=_text(data, "secure_endpoint", DEFAULT_SECURE_ENDPOINT),
            status=status,
        )


@dataclass(frozen=True, slots=True)
class Board:
    """A server-discovered physical intercom board."""

    identity: str
    name: str = ""
    site_id: str | None = None
    site_name: str | None = None
    device_id: str | int | None = None
    device_type: str | int | None = None


@dataclass(frozen=True, slots=True)
class IncomingCall:
    """A notification containing only a uniquely mapped inventory board.

    Unknown or ambiguous callers have ``board=None``. Call tokens, signalling
    senders and media descriptions are never part of the public notification.
    Optional board names and site fields are bounded, valid text without controls.
    Unused device identifiers and device types are omitted from this projection.
    This records receipt of an offer, not an active call or an answered call.
    """

    board: Board | None = None


@dataclass(frozen=True, slots=True)
class Relay:
    """A discovered relay and its permission to perform a release action.

    ``number`` is one-based, matching the transmitted ``body.door``. Eligibility
    is configuration, not a contact sensor or a locked/unlocked state.
    """

    board: Board
    number: int
    name: str = ""
    remote_allowed: bool = False
    pending_confirmation: bool = False
    access_type: int | str | None = None
    access_mode: int | str | None = None

    def __post_init__(self) -> None:
        if isinstance(self.number, bool) or not isinstance(self.number, int):
            raise InvalidInputError("Relay number must be a one-based integer.")
        if self.number < 1:
            raise InvalidInputError("Relay number must be a one-based integer.")

    @property
    def board_identity(self) -> str:
        """Return the board routing identity."""
        return self.board.identity

    @property
    def relay_number(self) -> int:
        """Return the one-based relay number."""
        return self.number


@dataclass(frozen=True, slots=True)
class ClientSnapshot:
    """Immutable pushed inventory and connectivity, without physical door state."""

    relays: tuple[Relay, ...]
    connected: bool
    revoked: bool = False
    error: IpguardError | None = field(default=None, repr=False)
    session: Session | None = field(default=None, repr=False)


def _text(data: Mapping[str, object], key: str, default: str | None = None) -> str:
    value = data.get(key, default)
    if not isinstance(value, str):
        # Values are deliberately omitted: the payload can contain credentials.
        raise InvalidInputError("Invalid saved session field type.")
    return value
