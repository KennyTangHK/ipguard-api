"""Typed asynchronous IPGUARD cloud enrollment, discovery and relay release."""

from .client import IpguardClient
from .errors import (
    AuthenticationError,
    AuthRevokedError,
    ConnectionFailureError,
    ExistingInstallationError,
    InvalidCodeError,
    InvalidInputError,
    IpguardError,
    OutcomeUnknownError,
    ProtocolError,
    RateLimitError,
    RelayUnavailableError,
    ReleaseRejectedError,
    VerificationExpiredError,
)
from .models import (
    AndroidProfile,
    AuthIdentifier,
    Board,
    ClientSnapshot,
    IdentifierKind,
    IncomingCall,
    Relay,
    Session,
    SessionStatus,
)
from .validation import (
    validate_identifier,
    validate_installation_label,
    validate_verification_code,
)

__all__ = [
    "AndroidProfile",
    "AuthenticationError",
    "AuthRevokedError",
    "AuthIdentifier",
    "Board",
    "ClientSnapshot",
    "ConnectionFailureError",
    "ExistingInstallationError",
    "IdentifierKind",
    "IncomingCall",
    "InvalidInputError",
    "InvalidCodeError",
    "IpguardClient",
    "IpguardError",
    "ProtocolError",
    "OutcomeUnknownError",
    "RateLimitError",
    "Relay",
    "RelayUnavailableError",
    "ReleaseRejectedError",
    "Session",
    "SessionStatus",
    "VerificationExpiredError",
    "validate_identifier",
    "validate_installation_label",
    "validate_verification_code",
]
