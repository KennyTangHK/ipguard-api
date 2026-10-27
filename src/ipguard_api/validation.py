"""Local enrollment input validation; these functions perform no network IO."""

import re
from math import isfinite

from .errors import InvalidInputError
from .models import AuthIdentifier, IdentifierKind

_EMAIL = re.compile(r"[^\s@]+@[^\s@]+\.[^\s@]+", re.ASCII)
_PHONE = re.compile(r"00[1-9][0-9]{6,14}", re.ASCII)
_CODE = re.compile(r"[0-9]{6}", re.ASCII)
_CLIENT_MARKER = re.compile(
    r"(?:^|[^a-z0-9])(?:cli|node[\s._-]*js|home[\s_-]*assistant|custom[\s_-]*client|codex|poc|proof[\s_-]*of[\s_-]*concept|automation|integration|script|python|curl|bot|macbook|macos|windows|linux|docker|terminal|laptop|desktop|raspberry[\s_-]*pi)(?:$|[^a-z0-9])",
    re.IGNORECASE | re.ASCII,
)


def validate_utf8(value: str, maximum: int, message: str) -> bytes:
    """Bound encoded text without including its contents in an error."""
    if not isinstance(value, str) or len(value) > maximum:
        raise InvalidInputError(message)
    try:
        encoded = value.encode("utf-8")
    except UnicodeError:
        raise InvalidInputError(message) from None
    if len(encoded) > maximum:
        raise InvalidInputError(message)
    return encoded


def validate_routing_identity(identity: str) -> bytes:
    """Validate a ZeroMQ routing identity before allocating or sending."""
    encoded = validate_utf8(identity, 255, "Invalid board or installation identity.")
    if not encoded or b"\0" in encoded:
        raise InvalidInputError("Invalid board or installation identity.")
    return encoded


def validate_duration(value: float, maximum: float) -> float:
    """Reject non-numeric, unbounded and sub-millisecond durations."""
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not 0.001 <= value <= maximum
        or not isfinite(value)
    ):
        raise InvalidInputError(
            "Timeouts and reconnect delays are outside supported bounds."
        )
    return float(value)


def validate_identifier(identifier: str) -> AuthIdentifier:
    """Preserve email spelling or normalize an international phone to ``00``."""
    validate_utf8(identifier, 1024, "Invalid account identifier.")
    if not identifier.strip():
        raise InvalidInputError(
            "A registered email or international phone is required."
        )
    value = identifier.strip()
    if _EMAIL.fullmatch(value):
        validate_utf8(value, 320, "Invalid account identifier.")
        return AuthIdentifier(IdentifierKind.EMAIL, value)
    phone = re.sub(r"[\s().-]", "", value)
    if phone.startswith("+"):
        phone = f"00{phone[1:]}"
    if not _PHONE.fullmatch(phone):
        raise InvalidInputError(
            "Use a registered email or an international phone number."
        )
    return AuthIdentifier(IdentifierKind.PHONE, phone)


def validate_verification_code(code: str) -> str:
    """Require six ASCII digits as text, preserving any leading zero."""
    if not isinstance(code, str) or not _CODE.fullmatch(code):
        raise InvalidInputError("The verification code must contain six ASCII digits.")
    return code


def validate_installation_label(label: str) -> str:
    """Require a personal label without implementation identifiers."""
    if not isinstance(label, str) or not label.strip() or len(label.strip()) > 80:
        raise InvalidInputError(
            "Choose a personal installation name of 1 to 80 characters."
        )
    value = label.strip()
    validate_utf8(value, 320, "Invalid installation label.")
    if _CLIENT_MARKER.search(value):
        raise InvalidInputError(
            "Choose a personal installation name without client markers."
        )
    return value
