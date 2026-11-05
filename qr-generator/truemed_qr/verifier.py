"""Offline verification: the reference implementation.

This module is the authoritative definition of what "verified" means in TrueMed.
The Dart implementation in ``mobile/lib/services/offline_verifier.dart`` mirrors
it check for check, and the API's online path calls :func:`merge_online_evidence`
so that verdict precedence lives in exactly one place rather than being
reimplemented three times with three subtly different bugs.

**What offline verification can and cannot prove.** A valid signature proves the
payload was produced by the holder of the private key registered to that
manufacturing licence. It does not prove the physical strip in the patient's hand
is genuine, because a counterfeiter can photograph one authentic strip and
reprint its perfectly-valid QR onto ten thousand fakes. Cloning is the standard
attack against every QR authentication scheme, and no amount of cryptography
applied to a static printed code can prevent it.

TrueMed's answer is on-chain scan telemetry — a single sellable unit scanned four
hundred times across fourteen districts is almost certainly cloned — and that
signal is only available online. Hence a successful offline check yields
``SIGNATURE_VALID_OFFLINE`` at severity ``warn``, never ``GENUINE`` at ``ok``.
Rendering offline success as an unqualified green tick would be a lie of omission
in a safety-critical interface.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any, Final

from . import codec, crypto
from .errors import (
    DependencyMissingError,
    ExpiredError,
    KeyUnknownError,
    PayloadError,
    QRMalformedError,
    SignatureInvalidError,
    TrueMedError,
    UnknownFormatVersionError,
)
from .payload import (
    VACCINE_TEMP_MAX_C,
    VACCINE_TEMP_MIN_C,
    MedicineData,
)

# ── Verdicts, severities, precedence ──────────────────────────────────────────

VERDICT_GENUINE: Final[str] = "GENUINE"
VERDICT_OFFLINE_OK: Final[str] = "SIGNATURE_VALID_OFFLINE"
VERDICT_EXPIRED: Final[str] = "EXPIRED"
VERDICT_COLD_CHAIN: Final[str] = "COLD_CHAIN_BREACH"
VERDICT_CLONE: Final[str] = "CLONE_SUSPECTED"
VERDICT_RECALLED: Final[str] = "RECALLED"
VERDICT_COUNTERFEIT: Final[str] = "COUNTERFEIT"
VERDICT_UNVERIFIABLE: Final[str] = "UNVERIFIABLE"

SEVERITY_OK: Final[str] = "ok"
SEVERITY_WARN: Final[str] = "warn"
SEVERITY_CRITICAL: Final[str] = "critical"

_SEVERITY: Final[dict[str, str]] = {
    VERDICT_GENUINE: SEVERITY_OK,
    VERDICT_OFFLINE_OK: SEVERITY_WARN,
    VERDICT_EXPIRED: SEVERITY_WARN,
    VERDICT_UNVERIFIABLE: SEVERITY_WARN,
    VERDICT_COLD_CHAIN: SEVERITY_CRITICAL,
    VERDICT_CLONE: SEVERITY_CRITICAL,
    VERDICT_RECALLED: SEVERITY_CRITICAL,
    VERDICT_COUNTERFEIT: SEVERITY_CRITICAL,
}

#: Most severe first. A forged signature makes every other field meaningless, so
#: it dominates everything below it.
_PRECEDENCE: Final[tuple[str, ...]] = (
    VERDICT_COUNTERFEIT,
    VERDICT_RECALLED,
    VERDICT_CLONE,
    VERDICT_COLD_CHAIN,
    VERDICT_EXPIRED,
    VERDICT_UNVERIFIABLE,
    VERDICT_OFFLINE_OK,
    VERDICT_GENUINE,
)

#: Scan-count above which a unit is treated as probably cloned. Tunable per
#: product class: a strip of paracetamol legitimately gets scanned a handful of
#: times (patient, pharmacist, curious relative), not dozens.
CLONE_SCAN_THRESHOLD: Final[int] = 25
#: Distinct districts above which cloning is the only sensible explanation — one
#: physical strip cannot be in five districts at once.
CLONE_DISTRICT_THRESHOLD: Final[int] = 3

_CHECK_PASS: Final[str] = "pass"
_CHECK_FAIL: Final[str] = "fail"
_CHECK_SKIPPED_OFFLINE: Final[str] = "skipped_offline"
_CHECK_SKIPPED_NA: Final[str] = "not_applicable"
#: A check that was never reached because an earlier one failed. Distinct from
#: ``fail`` on purpose: reporting "expiry: fail" when verification aborted at the
#: signature step would send someone debugging the wrong thing.
_CHECK_NOT_EVALUATED: Final[str] = "not_evaluated"


def worst_verdict(verdicts: list[str]) -> str:
    """Return the most severe verdict present, per the documented precedence."""
    for candidate in _PRECEDENCE:
        if candidate in verdicts:
            return candidate
    return VERDICT_UNVERIFIABLE


def severity_for(verdict: str) -> str:
    return _SEVERITY.get(verdict, SEVERITY_WARN)


# ── Result type ───────────────────────────────────────────────────────────────


@dataclass
class VerificationResult:
    """Outcome of verifying one scanned code.

    ``as_dict()`` returns ``{"valid", "error", "data", ...}`` — the shape named in
    the project specification — with the richer verdict/severity/checks fields
    alongside it, so callers can use either level of detail.
    """

    valid: bool
    verdict: str
    error: str | None = None
    error_code: str | None = None
    checks: dict[str, str] = field(default_factory=dict)
    data: dict[str, Any] | None = None
    medicine: MedicineData | None = None
    warnings: list[str] = field(default_factory=list)

    @property
    def severity(self) -> str:
        return severity_for(self.verdict)

    @property
    def is_critical(self) -> bool:
        return self.severity == SEVERITY_CRITICAL

    def as_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "verdict": self.verdict,
            "severity": self.severity,
            "error": self.error,
            "error_code": self.error_code,
            "checks": dict(self.checks),
            "warnings": list(self.warnings),
            "data": self.data,
        }

    def summary_line(self) -> str:
        """One-line human summary, for CLI output and logs."""
        icon = {
            SEVERITY_OK: "[OK]",
            SEVERITY_WARN: "[!]",
            SEVERITY_CRITICAL: "[X]",
        }[self.severity]
        name = ""
        if self.medicine is not None:
            name = f" {self.medicine.brand_name} ({self.medicine.generic_name})"
        detail = f" — {self.error}" if self.error else ""
        return f"{icon} {self.verdict}{name}{detail}"


def _failure(
    exc: TrueMedError,
    verdict: str,
    checks: dict[str, str],
    medicine: MedicineData | None = None,
) -> VerificationResult:
    return VerificationResult(
        valid=False,
        verdict=verdict,
        error=exc.message,
        error_code=exc.code,
        checks=checks,
        medicine=medicine,
        data=_data_block(medicine) if medicine is not None else None,
    )


def _data_block(
    medicine: MedicineData, today: date | None = None, key_fp: str | None = None
) -> dict[str, Any]:
    block = medicine.to_dict()
    block["days_to_expiry"] = medicine.days_to_expiry(today)
    block["is_vaccine"] = medicine.is_vaccine
    if key_fp is not None:
        block["signing_key_fingerprint"] = key_fp
    return block


# ── Offline verification ──────────────────────────────────────────────────────


def verify_wire(
    wire: str,
    bundle: crypto.TrustBundle,
    *,
    today: date | None = None,
) -> VerificationResult:
    """Verify a scanned ``TM1...`` string offline.

    Performs contract checks 1–3 (structure, signature, expiry). Checks 4–5
    (on-chain existence and cold chain) need the network; feed this result to
    :func:`merge_online_evidence` once the API responds.
    """
    today = today or date.today()
    # Every check starts as "not evaluated" and is only set to pass/fail once it
    # actually runs, so the returned dict is an honest record of what was tested.
    checks: dict[str, str] = {
        "structure": _CHECK_NOT_EVALUATED,
        "signature": _CHECK_NOT_EVALUATED,
        "expiry": _CHECK_NOT_EVALUATED,
        "on_chain": _CHECK_SKIPPED_OFFLINE,
        "cold_chain": _CHECK_SKIPPED_OFFLINE,
        "clone_telemetry": _CHECK_SKIPPED_OFFLINE,
    }

    # ── Check 1a: wire structure ──────────────────────────────────────────
    try:
        decoded = codec.decode(wire)
    except UnknownFormatVersionError as exc:
        # App is behind the format, not necessarily a fake. Fail closed but say so.
        checks["structure"] = _CHECK_FAIL
        return _failure(exc, VERDICT_UNVERIFIABLE, checks)
    except QRMalformedError as exc:
        checks["structure"] = _CHECK_FAIL
        return _failure(exc, VERDICT_UNVERIFIABLE, checks)

    # ── Check 1b: payload well-formedness ─────────────────────────────────
    try:
        medicine = MedicineData.from_canonical_json(decoded.payload_bytes)
    except PayloadError as exc:
        # A well-formed TM1 frame containing malformed data is not a misread. QR
        # error correction makes silent corruption that still parses as base64
        # vanishingly unlikely, so this is a fabrication attempt, not a bad scan.
        checks["structure"] = _CHECK_FAIL
        return _failure(exc, VERDICT_COUNTERFEIT, checks)
    checks["structure"] = _CHECK_PASS

    # ── Check 2: signature ────────────────────────────────────────────────
    try:
        public_key = bundle.public_key_for(medicine.mfg_licence_no, when=today)
    except KeyUnknownError as exc:
        # Deliberately UNVERIFIABLE (amber) rather than COUNTERFEIT (red).
        #
        # A stale trust bundle is far more likely than a forgery here, and
        # showing red on genuine medicine because the app has not refreshed its
        # keys would destroy patient trust in the whole system — the failure mode
        # that actually kills adoption. Amber with "could not verify, update the
        # app" is honest and safe: nothing is asserted to be genuine.
        return _failure(exc, VERDICT_UNVERIFIABLE, checks, medicine)

    key_fp = crypto.fingerprint(public_key)
    if not crypto.verify(public_key, decoded.payload_bytes, decoded.signature):
        checks["signature"] = _CHECK_FAIL
        return _failure(
            SignatureInvalidError(
                "signature does not match this payload under the registered key for "
                f"licence {medicine.mfg_licence_no} — treat as counterfeit"
            ),
            VERDICT_COUNTERFEIT,
            checks,
            medicine,
        )
    checks["signature"] = _CHECK_PASS

    # ── Check 3: expiry ───────────────────────────────────────────────────
    if medicine.is_expired(today):
        days = -medicine.days_to_expiry(today)
        result = _failure(
            ExpiredError(
                f"expired {days} day{'s' if days != 1 else ''} ago on "
                f"{medicine.expiry_date}"
            ),
            VERDICT_EXPIRED,
            checks,
            medicine,
        )
        result.checks["expiry"] = _CHECK_FAIL
        result.data = _data_block(medicine, today, key_fp)
        return result
    checks["expiry"] = _CHECK_PASS

    # ── Offline path complete ─────────────────────────────────────────────
    warnings = [
        "Offline verification only. The signature is authentic, but duplicate-scan "
        "and cold-chain checks require an internet connection."
    ]
    days_left = medicine.days_to_expiry(today)
    if days_left <= 30:
        warnings.append(f"Expires in {days_left} days on {medicine.expiry_date}.")

    return VerificationResult(
        valid=True,
        verdict=VERDICT_OFFLINE_OK,
        checks=checks,
        medicine=medicine,
        data=_data_block(medicine, today, key_fp),
        warnings=warnings,
    )


# ── Merging online evidence ───────────────────────────────────────────────────


def merge_online_evidence(
    offline: VerificationResult,
    *,
    on_chain: bool,
    status: str | None = None,
    temperature_readings: list[dict[str, Any]] | None = None,
    cold_chain_breached: bool | None = None,
    scan_count: int = 0,
    distinct_districts: int = 0,
    today: date | None = None,
) -> VerificationResult:
    """Fold blockchain evidence into an offline result and recompute the verdict.

    Called by the API after querying Fabric. Keeping precedence here means the
    Python CLI, the Node API, and the Flutter app cannot drift apart on what a
    given combination of failures should show a patient.

    Args:
        offline: Result from :func:`verify_wire`.
        on_chain: Whether ``product_id`` exists in world state.
        status: On-chain status, e.g. ``at_pharmacy``, ``recalled``.
        temperature_readings: ``{"temperature": float, ...}`` entries, vaccines only.
        cold_chain_breached: Chaincode's sticky breach flag; authoritative when given.
        scan_count: Lifetime patient scans of this product_id.
        distinct_districts: Number of distinct districts it has been scanned in.
    """
    today = today or date.today()

    # A forged or unparseable code cannot be rescued by chain data.
    if offline.verdict in (VERDICT_COUNTERFEIT, VERDICT_UNVERIFIABLE):
        return offline

    medicine = offline.medicine
    checks = dict(offline.checks)
    verdicts: list[str] = []
    warnings = list(offline.warnings)
    # The offline caveat no longer applies once we have chain evidence.
    warnings = [w for w in warnings if not w.startswith("Offline verification only")]
    errors: list[str] = []

    if offline.verdict == VERDICT_EXPIRED:
        verdicts.append(VERDICT_EXPIRED)
        if offline.error:
            errors.append(offline.error)

    # ── Check 4: on chain, and not recalled ───────────────────────────────
    if not on_chain:
        checks["on_chain"] = _CHECK_FAIL
        verdicts.append(VERDICT_COUNTERFEIT)
        errors.append(
            "this product ID has a valid signature but does not exist on the "
            "blockchain, which should be impossible for genuine stock — most likely "
            "a QR minted with a leaked signing key"
        )
    else:
        checks["on_chain"] = _CHECK_PASS
        if status == "recalled":
            verdicts.append(VERDICT_RECALLED)
            errors.append("this batch has been recalled by the regulator — do not use")

    # ── Check 5: cold chain (vaccines only) ───────────────────────────────
    is_vaccine = bool(medicine and medicine.is_vaccine)
    if not is_vaccine:
        checks["cold_chain"] = _CHECK_SKIPPED_NA
    else:
        readings = temperature_readings or []
        temps = [
            float(r["temperature"])
            for r in readings
            if isinstance(r, dict) and "temperature" in r
        ]
        breached = bool(cold_chain_breached)
        if cold_chain_breached is None:
            breached = any(
                t < VACCINE_TEMP_MIN_C or t > VACCINE_TEMP_MAX_C for t in temps
            )
        if breached:
            checks["cold_chain"] = _CHECK_FAIL
            verdicts.append(VERDICT_COLD_CHAIN)
            if temps:
                errors.append(
                    f"cold chain breach: readings ranged "
                    f"{min(temps):.1f}°C to {max(temps):.1f}°C, outside the required "
                    f"{VACCINE_TEMP_MIN_C:.0f}–{VACCINE_TEMP_MAX_C:.0f}°C — this vaccine "
                    "may have lost potency"
                )
            else:
                errors.append(
                    "cold chain breach recorded on the blockchain for this vaccine"
                )
        elif not temps:
            checks["cold_chain"] = _CHECK_SKIPPED_OFFLINE
            warnings.append(
                "No temperature readings recorded for this vaccine, so cold-chain "
                "integrity is unconfirmed."
            )
        else:
            checks["cold_chain"] = _CHECK_PASS

    # ── Clone telemetry ──────────────────────────────────────────────────
    if scan_count > CLONE_SCAN_THRESHOLD or distinct_districts > CLONE_DISTRICT_THRESHOLD:
        checks["clone_telemetry"] = _CHECK_FAIL
        verdicts.append(VERDICT_CLONE)
        errors.append(
            f"this exact code has been scanned {scan_count} times across "
            f"{distinct_districts} districts; one physical pack cannot be in that many "
            "places, so the QR has probably been copied onto counterfeit stock"
        )
    else:
        checks["clone_telemetry"] = _CHECK_PASS

    if not verdicts:
        verdicts.append(VERDICT_GENUINE)

    final = worst_verdict(verdicts)
    key_fp = (offline.data or {}).get("signing_key_fingerprint")

    data = _data_block(medicine, today, key_fp) if medicine else None
    if data is not None:
        data["status"] = status
        data["scan_count"] = scan_count
        data["distinct_districts"] = distinct_districts

    return VerificationResult(
        valid=final == VERDICT_GENUINE,
        verdict=final,
        error="; ".join(errors) if errors else None,
        error_code=_verdict_to_error_code(final),
        checks=checks,
        medicine=medicine,
        data=data,
        warnings=warnings,
    )


def _verdict_to_error_code(verdict: str) -> str | None:
    return {
        VERDICT_COUNTERFEIT: "SIGNATURE_INVALID",
        VERDICT_RECALLED: "RECALLED",
        VERDICT_CLONE: "CLONE_SUSPECTED",
        VERDICT_COLD_CHAIN: "COLD_CHAIN_BREACH",
        VERDICT_EXPIRED: "EXPIRED",
        VERDICT_UNVERIFIABLE: "PAYLOAD_INVALID",
    }.get(verdict)


# ── Reading a QR out of an image ──────────────────────────────────────────────


def decode_qr_image(path: str | Path) -> str:
    """Read the text out of a QR image file.

    Needs a decoder, which is *not* required for generation, so it stays optional:
    ``pip install opencv-python-headless`` or ``pip install pyzbar`` (the latter
    also needs the system ``libzbar0`` package). OpenCV is tried first because it
    has no non-Python dependency.
    """
    image_path = Path(path)
    if not image_path.is_file():
        raise TrueMedError(f"no such image file: {image_path}", code="FILE_NOT_FOUND")

    try:
        import cv2  # type: ignore[import-not-found]
    except ImportError:
        pass
    else:
        image = cv2.imread(str(image_path))
        if image is None:
            raise TrueMedError(
                f"OpenCV could not read {image_path} as an image", code="IMAGE_UNREADABLE"
            )
        text, _points, _straight = cv2.QRCodeDetector().detectAndDecode(image)
        if text:
            return str(text)
        raise QRMalformedError(
            f"no QR code found in {image_path.name}. If the code is very dense, try a "
            "higher --scale when generating."
        )

    try:
        from pyzbar import pyzbar  # type: ignore[import-not-found]
        from PIL import Image
    except ImportError as exc:
        raise DependencyMissingError(
            "reading a QR out of an image needs a decoder. Install one with:\n"
            "  pip install opencv-python-headless\n"
            "Generation and verification of raw payload strings work without it."
        ) from exc

    results = pyzbar.decode(Image.open(image_path))
    if not results:
        raise QRMalformedError(f"no QR code found in {image_path.name}")
    return results[0].data.decode("utf-8")


def verify_image(
    path: str | Path, bundle: crypto.TrustBundle, *, today: date | None = None
) -> VerificationResult:
    """Decode a QR image then verify it offline."""
    return verify_wire(decode_qr_image(path), bundle, today=today)
