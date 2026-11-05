"""The ``TM1.<payload>.<signature>`` wire format.

Encoding choices, briefly:

* **base64url without padding** (RFC 4648 §5). Standard base64's ``+`` and ``/``
  fall outside the QR alphanumeric character set, which would force the entire
  code into byte mode and inflate it. Padding ``=`` is dropped because it carries
  no information and costs up to two characters.
* **Three dot-separated parts.** ``.`` is not in the base64url alphabet, so
  splitting is unambiguous with no escaping.
* **Signature over received bytes.** :func:`decode` returns the payload bytes
  exactly as they arrived. The verifier signature-checks *those* bytes, never a
  re-serialisation of its own parse. Re-serialising before verifying is a
  well-known signature-bypass pattern: if the parser and serialiser disagree
  about anything — duplicate JSON keys, number formatting, Unicode
  normalisation — an attacker can craft input that verifies under one
  interpretation and is acted on under another.
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass
from typing import Final

from .errors import QRMalformedError, UnknownFormatVersionError
from .payload import WIRE_PREFIX

#: Separator between the three wire parts.
SEPARATOR: Final[str] = "."
#: Raw ECDSA P-256 signature length in bytes.
_SIG_LEN: Final[int] = 64
#: Refuse absurdly long input before doing any work. QR v40 at ECC level L tops
#: out near 2953 bytes, so anything beyond that did not come from a QR code and
#: is more likely an attempt to make us allocate.
_MAX_WIRE_LEN: Final[int] = 4096
#: Anything outside the unpadded base64url alphabet. Note that ``=`` is excluded
#: too: we strip padding on encode, so a code arriving with padding was not
#: produced by this system.
_NON_B64URL: Final[re.Pattern[str]] = re.compile(r"[^A-Za-z0-9_-]")


def b64u_encode(raw: bytes) -> str:
    """base64url-encode without padding."""
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def b64u_decode(text: str, *, what: str = "value") -> bytes:
    """base64url-decode, restoring stripped padding and rejecting stray characters.

    The explicit alphabet check is not redundant with ``validate=True``, which is
    the subtle part. ``base64.b64decode(s, altchars=b"-_", validate=True)``
    translates ``-``/``_`` into ``+``/``/`` *before* validating, so a literal
    ``+`` in the input survives translation and then passes validation. The
    consequence is that ``"A-AA"`` and ``"A+AA"`` decode to identical bytes: two
    distinct wire strings, one payload. That is signature malleability. It does
    not let anyone forge a payload, but it does mean a "unique" code is not
    unique, which quietly undermines the duplicate-scan detection that the whole
    clone defence rests on. So the alphabet is checked directly, first.
    """
    stray = _NON_B64URL.search(text)
    if stray is not None:
        raise QRMalformedError(
            f"{what} contains {stray.group(0)!r} at position {stray.start()}, which is "
            "not in the base64url alphabet (A-Z a-z 0-9 - _)"
        )
    padded = text + "=" * (-len(text) % 4)
    try:
        # binascii.Error subclasses ValueError, so one except clause covers both
        # "bad character" and "wrong length" failures.
        return base64.b64decode(padded, altchars=b"-_", validate=True)
    except ValueError as exc:
        raise QRMalformedError(
            f"{what} is not valid unpadded base64url: {exc}"
        ) from exc


@dataclass(frozen=True, slots=True)
class DecodedQR:
    """The parsed parts of a scanned TrueMed QR string.

    ``payload_bytes`` is verbatim from the wire — that is the whole point of this
    type existing rather than returning a parsed object.
    """

    prefix: str
    payload_bytes: bytes
    signature: bytes

    @property
    def total_wire_length(self) -> int:
        return (
            len(self.prefix)
            + 1
            + len(b64u_encode(self.payload_bytes))
            + 1
            + len(b64u_encode(self.signature))
        )


def encode(payload_bytes: bytes, signature: bytes) -> str:
    """Assemble the wire string from canonical payload bytes and a raw signature."""
    if not isinstance(payload_bytes, (bytes, bytearray)):
        raise TypeError(f"payload_bytes must be bytes, got {type(payload_bytes).__name__}")
    if not isinstance(signature, (bytes, bytearray)):
        raise TypeError(f"signature must be bytes, got {type(signature).__name__}")
    if len(signature) != _SIG_LEN:
        raise ValueError(
            f"signature must be exactly {_SIG_LEN} raw bytes (r‖s), got {len(signature)}"
        )
    return SEPARATOR.join(
        (WIRE_PREFIX, b64u_encode(bytes(payload_bytes)), b64u_encode(bytes(signature)))
    )


def decode(wire: str) -> DecodedQR:
    """Parse a scanned string into its three parts.

    Raises :class:`QRMalformedError` for structural problems and
    :class:`UnknownFormatVersionError` when the prefix is a TrueMed format this
    build does not implement. The distinction matters to the app: a malformed
    string is probably not a TrueMed code at all ("this doesn't look like a
    TrueMed QR"), whereas an unknown version means the app is out of date
    ("please update TrueMed to scan this").
    """
    if not isinstance(wire, str):
        raise QRMalformedError(f"expected a string, got {type(wire).__name__}")

    # Scanners and clipboards routinely append newlines or surrounding spaces.
    text = wire.strip()
    if not text:
        raise QRMalformedError("scanned string is empty")
    if len(text) > _MAX_WIRE_LEN:
        raise QRMalformedError(
            f"scanned string is {len(text)} characters, beyond any real QR code's "
            f"capacity ({_MAX_WIRE_LEN} accepted at most)"
        )

    parts = text.split(SEPARATOR)

    # Decide "is this ours at all?" before validating structure. Checking the part
    # count first produces "expected 3 dot-separated parts" when someone scans a
    # UPI sticker, which is a developer's message leaking into a patient's screen.
    # A code that does not begin with TM is simply not a TrueMed code.
    if not parts[0].upper().startswith("TM"):
        raise QRMalformedError(
            f"not a TrueMed QR code: expected prefix {WIRE_PREFIX!r}, found "
            f"{parts[0][:16]!r}"
        )

    if len(parts) != 3:
        raise QRMalformedError(
            f"expected 3 dot-separated parts (prefix.payload.signature), found "
            f"{len(parts)}"
        )

    prefix, payload_b64, sig_b64 = parts

    if prefix != WIRE_PREFIX:
        # Distinguish "another TrueMed version" from "not TrueMed at all".
        raise UnknownFormatVersionError(
            f"QR uses TrueMed format {prefix!r}; this build only implements "
            f"{WIRE_PREFIX}. Update the app to verify newer codes — it will not "
            "guess."
        )

    if not payload_b64:
        raise QRMalformedError("payload part is empty")
    if not sig_b64:
        raise QRMalformedError("signature part is empty")

    payload_bytes = b64u_decode(payload_b64, what="payload")
    signature = b64u_decode(sig_b64, what="signature")

    if len(signature) != _SIG_LEN:
        raise QRMalformedError(
            f"signature decodes to {len(signature)} bytes; a raw ECDSA P-256 "
            f"signature is exactly {_SIG_LEN} (r‖s, 32 each)"
        )

    return DecodedQR(prefix=prefix, payload_bytes=payload_bytes, signature=signature)


def looks_like_truemed(text: str) -> bool:
    """Cheap check used by the scanner to ignore unrelated QR codes.

    The app's camera sees every QR in frame — WiFi codes, UPI codes, posters. It
    should silently skip anything that is not ours rather than flashing a scary
    "counterfeit" verdict at a UPI sticker.
    """
    return isinstance(text, str) and text.strip().startswith(WIRE_PREFIX + SEPARATOR)
