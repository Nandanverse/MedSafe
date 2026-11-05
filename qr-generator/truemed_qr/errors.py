"""TrueMed error types.

Every error carries a machine-readable ``code`` from the table in
``docs/DATA-CONTRACT.md`` §2.4. The mobile app and the API switch on these codes,
never on the human-readable message, so the codes are part of the frozen contract
and must not be renamed without bumping the contract version.
"""

from __future__ import annotations


class TrueMedError(Exception):
    """Base class for every TrueMed failure.

    Attributes:
        code: Stable machine-readable identifier, e.g. ``SIGNATURE_INVALID``.
        message: Human-readable explanation, safe to show a developer. Not
            necessarily safe to show a patient — the app substitutes its own
            localised wording keyed off ``code``.
    """

    code: str = "INTERNAL_ERROR"

    def __init__(self, message: str, *, code: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        if code is not None:
            self.code = code

    def __str__(self) -> str:  # pragma: no cover - trivial
        return f"[{self.code}] {self.message}"

    def as_dict(self) -> dict[str, str]:
        return {"code": self.code, "message": self.message}


class PayloadError(TrueMedError):
    """A data element is missing, malformed, or fails a business rule."""

    code = "PAYLOAD_INVALID"


class QRMalformedError(TrueMedError):
    """The scanned string is not a well-formed TrueMed wire payload."""

    code = "QR_MALFORMED"


class UnknownFormatVersionError(TrueMedError):
    """The prefix is not ``TM1``.

    Fail closed. A verifier that does not understand the format must reject,
    never accept — treating an unrecognised future format as valid would let an
    attacker downgrade verification by inventing a prefix.
    """

    code = "QR_UNKNOWN_VERSION"


class SignatureInvalidError(TrueMedError):
    """ECDSA verification failed. Treat the item as counterfeit."""

    code = "SIGNATURE_INVALID"


class KeyUnknownError(TrueMedError):
    """No trusted public key is registered for this manufacturing licence."""

    code = "SIGNATURE_KEY_UNKNOWN"


class ExpiredError(TrueMedError):
    """Past the printed expiry date."""

    code = "EXPIRED"


class CapacityError(TrueMedError):
    """Payload will not fit in a QR code at error-correction level H."""

    code = "QR_CAPACITY_EXCEEDED"


class DependencyMissingError(TrueMedError):
    """An optional third-party package is needed for this operation."""

    code = "DEPENDENCY_MISSING"


class KeyStoreError(TrueMedError):
    """Key material could not be loaded, written, or is inconsistent."""

    code = "KEYSTORE_ERROR"
