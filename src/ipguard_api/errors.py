"""Public errors for the IPGUARD library."""


class IpguardError(Exception):
    """Base error for IPGUARD operations."""


class InvalidInputError(IpguardError, ValueError):
    """Input cannot be used in an IPGUARD enrollment or release request."""


class AuthenticationError(IpguardError):
    """The service rejected authorization without a known specific reason."""


class InvalidCodeError(AuthenticationError):
    """The service rejected the verification code."""


class VerificationExpiredError(AuthenticationError):
    """A service response explicitly identifies an expired challenge."""


class RateLimitError(AuthenticationError):
    """A service response explicitly identifies a rate limit."""


class ExistingInstallationError(AuthenticationError):
    """Registration would replace an existing mobile installation."""


class AuthRevokedError(AuthenticationError):
    """An activated installation received a terminal reset notice."""


class ConnectionFailureError(IpguardError):
    """The cloud connection could not complete an ordinary read or request."""


class ProtocolError(ConnectionFailureError):
    """A relevant service message has an unsupported structure."""


class RelayUnavailableError(IpguardError):
    """A relay is absent, unpermitted, pending confirmation, or already busy."""


class ReleaseRejectedError(IpguardError):
    """A correlated acknowledgement explicitly rejected the release request."""


class OutcomeUnknownError(IpguardError):
    """A release may have been delivered but its acknowledgement was not received."""
