"""CDSCO data elements, validation, and canonical serialisation.

This module owns the *signed* part of a TrueMed QR code. Everything here is
security-relevant: if the generator and the verifier disagree by even one byte
about how a payload serialises, every signature check fails (best case) or a
canonicalisation gap opens up that lets an attacker mutate fields while keeping
a valid signature (worst case).

Two rules keep that from happening, and both are enforced below:

1. ``canonical_json`` is the *only* way a payload is turned into bytes for
   signing. It sorts keys and strips whitespace, so the mapping from payload to
   bytes is one-to-one.
2. A verifier signature-checks the bytes it *received*, never a re-serialisation
   of its own parse of them. See ``codec.decode`` — it hands back the raw
   payload bytes for exactly this reason.

Wire keys are deliberately short (``bn`` not ``brand_name``) because QR capacity
is the binding constraint on a 10-tablet blister strip. Full names are used
everywhere off the wire. The mapping is in ``docs/DATA-CONTRACT.md`` §1.3.
"""

from __future__ import annotations

import json
import re
import unicodedata
from dataclasses import dataclass, field
from datetime import date
from typing import Any, Final

from .errors import PayloadError

# ── Contract constants ─────────────────────────────────────────────────────────

CONTRACT_VERSION: Final[int] = 1
WIRE_PREFIX: Final[str] = "TM1"

TYPE_MEDICINE: Final[str] = "medicine"
TYPE_VACCINE: Final[str] = "vaccine"

#: Off-wire type name -> single-character wire code.
_TYPE_TO_WIRE: Final[dict[str, str]] = {TYPE_MEDICINE: "M", TYPE_VACCINE: "V"}
_WIRE_TO_TYPE: Final[dict[str, str]] = {v: k for k, v in _TYPE_TO_WIRE.items()}

#: Vaccine cold-chain envelope, inclusive, in degrees Celsius. WHO/CDSCO standard
#: for most routine immunisation vaccines.
VACCINE_TEMP_MIN_C: Final[float] = 2.0
VACCINE_TEMP_MAX_C: Final[float] = 8.0

#: Maximum bytes a QR code can carry at error-correction level H (version 40).
#: Generation raises above this. Well below it we still warn — see generator.py.
QR_MAX_BYTES_ECC_H: Final[int] = 1273

#: Wire overhead outside the payload: ``TM1`` + two ``.`` separators + the
#: base64url of a 64-byte signature (86 characters, unpadded).
_WIRE_OVERHEAD: Final[int] = 3 + 1 + 1 + 86

#: Hard ceiling on the *canonical payload in bytes*, derived from the QR capacity
#: rather than guessed.
#:
#: Bytes, not characters, and that distinction is the whole point. The per-field
#: limits below count characters, which is the right unit for data quality but the
#: wrong unit for capacity: a 64-character Devanagari generic name occupies 192
#: bytes in UTF-8, three times its Latin equivalent. Enforcing only character
#: limits therefore permits payloads that cannot physically be printed — a payload
#: with every field at its documented maximum encodes to 1462 bytes, 189 over the
#: ceiling. Enforcing this budget at construction means an unprintable payload
#: cannot be built at all, so the failure lands on whoever typed the data with a
#: message about what to shorten, instead of stopping a production line at print
#: time.
MAX_PAYLOAD_BYTES: Final[int] = ((QR_MAX_BYTES_ECC_H - _WIRE_OVERHEAD) // 4) * 3

_DATE_RE: Final[re.Pattern[str]] = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_PRODUCT_ID_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Z0-9]+_[A-Z0-9]+_\d{4}_\d{6}$")

#: Per-field maximum lengths, in characters. These are data-quality limits — they
#: catch a pasted paragraph in the brand-name box — and they are deliberately
#: generous. :data:`MAX_PAYLOAD_BYTES` is the authoritative capacity gate.
_MAX_LEN: Final[dict[str, int]] = {
    "product_id": 80,
    "generic_name": 64,
    "brand_name": 48,
    "manufacturer": 120,
    "mfg_licence_no": 32,
    "batch_no": 24,
    "quantity": 32,
    "excipient": 40,
}
_MAX_EXCIPIENTS: Final[int] = 12


def _reject_control_chars(value: str, field_name: str) -> None:
    """Reject C0/C1 control characters.

    A newline or NUL inside a signed field is a red flag: it is how payload
    smuggling and log-injection attacks usually start, and no legitimate
    excipient name contains one.
    """
    for ch in value:
        if unicodedata.category(ch) == "Cc":
            raise PayloadError(
                f"{field_name} contains a control character (U+{ord(ch):04X}); "
                "control characters are not permitted in signed fields"
            )


def _require_str(raw: Any, field_name: str, *, max_len: int | None = None) -> str:
    if not isinstance(raw, str):
        raise PayloadError(f"{field_name} must be a string, got {type(raw).__name__}")
    value = raw.strip()
    if not value:
        raise PayloadError(f"{field_name} must not be empty")
    _reject_control_chars(value, field_name)
    limit = max_len if max_len is not None else _MAX_LEN.get(field_name)
    if limit is not None and len(value) > limit:
        raise PayloadError(
            f"{field_name} is {len(value)} characters, exceeding the {limit}-character "
            "limit that keeps the QR code scannable"
        )
    return value


def parse_iso_date(raw: Any, field_name: str) -> date:
    """Parse a strict ``YYYY-MM-DD`` date.

    The regex is not redundant with ``date.fromisoformat``: on Python 3.11+ that
    function also accepts forms like ``20260315`` and ``2026-W11-3``. Dates
    inside a signed payload must have exactly one representation, so the format
    is pinned explicitly.
    """
    if not isinstance(raw, str) or not _DATE_RE.match(raw):
        raise PayloadError(
            f"{field_name} must be exactly YYYY-MM-DD (got {raw!r})"
        )
    try:
        return date.fromisoformat(raw)
    except ValueError as exc:
        raise PayloadError(f"{field_name} is not a real calendar date: {raw!r}") from exc


def make_product_id(generic_name: str, brand_name: str, year: int, serial: int) -> str:
    """Build a ``{GENERIC}_{BRAND}_{YEAR}_{SERIAL}`` product identifier.

    Non-alphanumerics are *removed* rather than replaced with underscores, so the
    four-segment structure stays unambiguous — ``Paracetamol 500mg`` becoming
    ``PARACETAMOL_500MG`` would introduce a fifth segment and break parsing.

    >>> make_product_id("Paracetamol 500mg", "Paracip 500", 2026, 1)
    'PARACETAMOL500MG_PARACIP500_2026_000001'
    """
    if not isinstance(year, int) or not 1900 <= year <= 2999:
        raise PayloadError(f"year must be a 4-digit integer, got {year!r}")
    if not isinstance(serial, int) or not 0 < serial <= 999_999:
        raise PayloadError(
            f"serial must be an integer in 1..999999, got {serial!r}; "
            "a batch larger than that needs a second brand-year namespace"
        )

    def squash(text: str, label: str) -> str:
        if not isinstance(text, str):
            raise PayloadError(f"{label} must be a string")
        out = re.sub(r"[^A-Z0-9]", "", text.upper())
        if not out:
            raise PayloadError(
                f"{label} {text!r} has no alphanumeric characters to build an ID from"
            )
        return out

    product_id = f"{squash(generic_name, 'generic_name')}_" \
                 f"{squash(brand_name, 'brand_name')}_{year:04d}_{serial:06d}"
    if len(product_id) > _MAX_LEN["product_id"]:
        raise PayloadError(
            f"generated product_id is {len(product_id)} characters, over the "
            f"{_MAX_LEN['product_id']} limit; shorten the generic or brand name"
        )
    return product_id


@dataclass(frozen=True, slots=True)
class MedicineData:
    """The signed data elements of one sellable unit.

    Frozen because a payload must not be mutated between signing and encoding —
    that is precisely the window in which a tampering bug would hide.

    ``product_id`` is the primary key across all of TrueMed: it is the QR field,
    the Fabric world-state key, the API path parameter, and the PostgreSQL
    foreign key.
    """

    product_id: str
    generic_name: str
    brand_name: str
    manufacturer: str
    mfg_licence_no: str
    batch_no: str
    mfg_date: str
    expiry_date: str
    quantity: str
    excipients: list[str] = field(default_factory=list)
    med_type: str = TYPE_MEDICINE
    contract_version: int = CONTRACT_VERSION

    # ── validation ────────────────────────────────────────────────────────────

    def __post_init__(self) -> None:
        object.__setattr__(self, "product_id", _require_str(self.product_id, "product_id"))
        object.__setattr__(self, "generic_name", _require_str(self.generic_name, "generic_name"))
        object.__setattr__(self, "brand_name", _require_str(self.brand_name, "brand_name"))
        object.__setattr__(self, "manufacturer", _require_str(self.manufacturer, "manufacturer"))
        object.__setattr__(
            self, "mfg_licence_no", _require_str(self.mfg_licence_no, "mfg_licence_no")
        )
        object.__setattr__(self, "batch_no", _require_str(self.batch_no, "batch_no"))
        object.__setattr__(self, "quantity", _require_str(self.quantity, "quantity"))

        if not _PRODUCT_ID_RE.match(self.product_id):
            raise PayloadError(
                f"product_id {self.product_id!r} does not match "
                "{GENERIC}_{BRAND}_{YEAR}_{SERIAL} with a 4-digit year and "
                "6-digit serial; build it with make_product_id()"
            )

        if self.contract_version != CONTRACT_VERSION:
            raise PayloadError(
                f"contract_version must be {CONTRACT_VERSION} for prefix {WIRE_PREFIX}, "
                f"got {self.contract_version!r}"
            )

        if self.med_type not in _TYPE_TO_WIRE:
            raise PayloadError(
                f"type must be one of {sorted(_TYPE_TO_WIRE)}, got {self.med_type!r}"
            )

        mfg = parse_iso_date(self.mfg_date, "mfg_date")
        exp = parse_iso_date(self.expiry_date, "expiry_date")
        if exp <= mfg:
            raise PayloadError(
                f"expiry_date ({self.expiry_date}) must be after mfg_date ({self.mfg_date})"
            )

        if not isinstance(self.excipients, list):
            raise PayloadError(
                "excipients must be a JSON array of strings, not "
                f"{type(self.excipients).__name__}; a comma-joined string is "
                "unparseable because excipient names may themselves contain commas"
            )
        if len(self.excipients) > _MAX_EXCIPIENTS:
            raise PayloadError(
                f"excipients has {len(self.excipients)} entries, over the "
                f"{_MAX_EXCIPIENTS} limit; list only the declared inactive ingredients"
            )
        cleaned = [
            _require_str(item, "excipient", max_len=_MAX_LEN["excipient"])
            for item in self.excipients
        ]
        object.__setattr__(self, "excipients", cleaned)

        # Capacity gate, last because it needs every field in its final form.
        # Cheap (one small json.dumps) and worth paying on every construction: it
        # makes "this payload cannot be printed" impossible to discover late.
        size = len(self.canonical_json())
        if size > MAX_PAYLOAD_BYTES:
            raise PayloadError(
                f"payload encodes to {size} bytes, over the {MAX_PAYLOAD_BYTES}-byte "
                f"budget that fits a QR code at error-correction level H "
                f"(overflow: {size - MAX_PAYLOAD_BYTES} bytes). Shorten the "
                "manufacturer address or trim the excipient list. Note that "
                "non-Latin text costs up to 3 bytes per character, so a Devanagari "
                "field uses far more of the budget than its character count suggests."
            )

    # ── derived properties ────────────────────────────────────────────────────

    @property
    def mfg_date_obj(self) -> date:
        return date.fromisoformat(self.mfg_date)

    @property
    def expiry_date_obj(self) -> date:
        return date.fromisoformat(self.expiry_date)

    @property
    def is_vaccine(self) -> bool:
        return self.med_type == TYPE_VACCINE

    def days_to_expiry(self, today: date | None = None) -> int:
        """Days remaining, negative if already expired."""
        return (self.expiry_date_obj - (today or date.today())).days

    def is_expired(self, today: date | None = None) -> bool:
        """True once the calendar date is past the printed expiry.

        The expiry date itself counts as still usable, matching how a pharmacist
        reads a strip: ``EXP 02/2028`` means usable through that day.
        """
        return self.days_to_expiry(today) < 0

    # ── serialisation ─────────────────────────────────────────────────────────

    def to_wire_dict(self) -> dict[str, Any]:
        """Short-key representation that goes inside the QR."""
        return {
            "v": self.contract_version,
            "id": self.product_id,
            "gn": self.generic_name,
            "bn": self.brand_name,
            "mf": self.manufacturer,
            "ml": self.mfg_licence_no,
            "bt": self.batch_no,
            "md": self.mfg_date,
            "ed": self.expiry_date,
            "qt": self.quantity,
            "ex": list(self.excipients),
            "tp": _TYPE_TO_WIRE[self.med_type],
        }

    def to_dict(self) -> dict[str, Any]:
        """Full-name representation used by the API, chaincode, and app."""
        return {
            "contract_version": self.contract_version,
            "product_id": self.product_id,
            "generic_name": self.generic_name,
            "brand_name": self.brand_name,
            "manufacturer": self.manufacturer,
            "mfg_licence_no": self.mfg_licence_no,
            "batch_no": self.batch_no,
            "mfg_date": self.mfg_date,
            "expiry_date": self.expiry_date,
            "quantity": self.quantity,
            "excipients": list(self.excipients),
            "type": self.med_type,
        }

    def canonical_json(self) -> bytes:
        """The exact bytes that get signed.

        Sorted keys, no whitespace, UTF-8, no trailing newline. This is the only
        payload-to-bytes function in the codebase; nothing else may serialise a
        payload for signing.
        """
        return json.dumps(
            self.to_wire_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")

    # ── deserialisation ───────────────────────────────────────────────────────

    @classmethod
    def from_wire_dict(cls, raw: Any) -> "MedicineData":
        """Rebuild from the short-key form found inside a QR code."""
        if not isinstance(raw, dict):
            raise PayloadError(
                f"QR payload must be a JSON object, got {type(raw).__name__}"
            )

        required = ("v", "id", "gn", "bn", "mf", "ml", "bt", "md", "ed", "qt", "ex", "tp")
        missing = [k for k in required if k not in raw]
        if missing:
            raise PayloadError(f"QR payload is missing required keys: {', '.join(missing)}")

        version = raw["v"]
        if not isinstance(version, int) or isinstance(version, bool):
            raise PayloadError(f"payload key 'v' must be an integer, got {version!r}")

        wire_type = raw["tp"]
        if wire_type not in _WIRE_TO_TYPE:
            raise PayloadError(
                f"payload key 'tp' must be one of {sorted(_WIRE_TO_TYPE)}, got {wire_type!r}"
            )

        return cls(
            product_id=raw["id"],
            generic_name=raw["gn"],
            brand_name=raw["bn"],
            manufacturer=raw["mf"],
            mfg_licence_no=raw["ml"],
            batch_no=raw["bt"],
            mfg_date=raw["md"],
            expiry_date=raw["ed"],
            quantity=raw["qt"],
            excipients=raw["ex"],
            med_type=_WIRE_TO_TYPE[wire_type],
            contract_version=version,
        )

    @classmethod
    def from_canonical_json(cls, blob: bytes) -> "MedicineData":
        """Parse signed payload bytes.

        Note the asymmetry with :meth:`canonical_json`: this does *not* verify
        that ``blob`` was canonically encoded. Verification signs over the
        received bytes, so a non-canonical but correctly-signed payload is still
        authentic — it just could not have come from our generator.
        """
        try:
            parsed = json.loads(blob.decode("utf-8"))
        except UnicodeDecodeError as exc:
            raise PayloadError("QR payload is not valid UTF-8") from exc
        except json.JSONDecodeError as exc:
            raise PayloadError(f"QR payload is not valid JSON: {exc.msg}") from exc
        return cls.from_wire_dict(parsed)

    @classmethod
    def from_dict(cls, raw: Any) -> "MedicineData":
        """Rebuild from the full-name form used by the API."""
        if not isinstance(raw, dict):
            raise PayloadError(f"expected an object, got {type(raw).__name__}")
        required = (
            "product_id", "generic_name", "brand_name", "manufacturer",
            "mfg_licence_no", "batch_no", "mfg_date", "expiry_date",
            "quantity", "excipients", "type",
        )
        missing = [k for k in required if k not in raw]
        if missing:
            raise PayloadError(f"missing required fields: {', '.join(missing)}")
        return cls(
            product_id=raw["product_id"],
            generic_name=raw["generic_name"],
            brand_name=raw["brand_name"],
            manufacturer=raw["manufacturer"],
            mfg_licence_no=raw["mfg_licence_no"],
            batch_no=raw["batch_no"],
            mfg_date=raw["mfg_date"],
            expiry_date=raw["expiry_date"],
            quantity=raw["quantity"],
            excipients=raw["excipients"],
            med_type=raw["type"],
            contract_version=raw.get("contract_version", CONTRACT_VERSION),
        )
