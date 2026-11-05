#!/usr/bin/env python3
"""Generate cross-language test fixtures for the Node.js verifier.

The Node verifier in ``backend/src/core/`` is a second, independent
implementation of the same wire format that ``qr-generator/`` implements in
Python. Two implementations of one signature scheme is exactly the situation in
which they drift: a canonical-JSON detail, a base64url padding rule, or an r|s
byte order that differs by one and only shows up on some payloads.

So the Node test suite does not sign its own fixtures. It verifies wire strings
produced *here*, by the Python signer, and asserts the verdicts match. If the
two ever disagree, the fixture tests fail rather than a patient getting a green
tick on a forged strip.

Run from the repository root:

    python3 backend/tests/fixtures/generate-fixtures.py

Writes ``fixtures.json`` beside this script. Deterministic apart from the key
material, which is freshly generated on every run — so a regenerated file will
have different keys and signatures but identical structure and expectations.
The fixtures are committed, so this only needs re-running when the wire format
or the trust bundle format changes.
"""

from __future__ import annotations

import json
import sys
from datetime import date
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[2]
sys.path.insert(0, str(REPO_ROOT / "qr-generator"))

try:
    from truemed_qr import crypto
    from truemed_qr.codec import b64u_decode, b64u_encode, encode
    from truemed_qr.payload import MedicineData
except ImportError as exc:  # pragma: no cover - operator error
    sys.exit(
        f"cannot import truemed_qr ({exc}).\n"
        f"Run from the repo root with qr-generator/ present, and install its "
        f"requirements:\n"
        f"    pip install -r qr-generator/requirements.txt"
    )

# Fixed reference date. Every "days to expiry" expectation below is relative to
# this, never to the real today, or the fixtures would rot.
TODAY = date(2026, 8, 22)

LICENCE_A = "MH/25D/2019/187"
MAKER_A = "Sanjeevani Pharma Ltd, Plot 42 MIDC, Pune 411018"
LICENCE_B = "KA/25B/2021/044"
MAKER_B = "Bharat Biologics Pvt Ltd, Plot 9 Peenya, Bengaluru 560058"
LICENCE_REVOKED = "GJ/25D/2017/512"
MAKER_REVOKED = "Sunrise Formulations Pvt Ltd, GIDC Vatva, Ahmedabad 382445"
LICENCE_UNREGISTERED = "XX/99Z/2099/999"


def medicine(**overrides) -> MedicineData:
    """A valid, unexpired tablet. Fictional brand, per DATA-CONTRACT.md §6."""
    base = dict(
        product_id="PARACETAMOL500MG_PARACIP500_2026_000001",
        generic_name="Paracetamol 500mg",
        brand_name="Paracip 500",
        manufacturer=MAKER_A,
        mfg_licence_no=LICENCE_A,
        batch_no="SP26A0417",
        mfg_date="2026-03-15",
        expiry_date="2028-02-29",
        quantity="10 tablets",
        excipients=["Maize Starch", "Povidone K30", "Talc"],
        med_type="medicine",
    )
    base.update(overrides)
    return MedicineData(**base)


def vaccine(**overrides) -> MedicineData:
    base = dict(
        product_id="MEASLESRUBELLA_SURAKSHAMR_2026_000042",
        generic_name="Measles-Rubella Vaccine",
        brand_name="Suraksha MR",
        manufacturer=MAKER_B,
        mfg_licence_no=LICENCE_B,
        batch_no="BB26MR009",
        mfg_date="2026-06-01",
        expiry_date="2027-05-31",
        quantity="1 vial (5 doses)",
        excipients=["Sorbitol", "Hydrolysed Gelatin"],
        med_type="vaccine",
    )
    base.update(overrides)
    return MedicineData(**base)


def flip_last_bit(raw: bytes) -> bytes:
    """Flip one bit of the final byte — a minimal, surgical corruption."""
    return raw[:-1] + bytes([raw[-1] ^ 0x01])


def main() -> int:
    root_key = crypto.generate_private_key()
    key_a = crypto.generate_private_key()
    key_b = crypto.generate_private_key()
    key_revoked = crypto.generate_private_key()
    key_unregistered = crypto.generate_private_key()

    def trusted(licence, maker, key, *, status="active",
                valid_from="2020-01-01", valid_until="2099-12-31"):
        pub = key.public_key()
        return crypto.TrustedKey(
            mfg_licence_no=licence,
            manufacturer=maker,
            public_key_pem=crypto.public_key_to_pem(pub).decode("utf-8"),
            fingerprint=crypto.fingerprint(pub),
            valid_from=valid_from,
            valid_until=valid_until,
            status=status,
        )

    bundle = crypto.TrustBundle(
        [
            trusted(LICENCE_A, MAKER_A, key_a),
            trusted(LICENCE_B, MAKER_B, key_b),
            # Revoked: a real registered manufacturer whose key was withdrawn.
            # Must resolve to SIGNATURE_KEY_UNKNOWN, not to a valid signature.
            trusted(LICENCE_REVOKED, MAKER_REVOKED, key_revoked, status="revoked"),
        ],
        issued_at="2026-08-22T00:00:00Z",
    )

    signed_bundle_json = bundle.to_json(root_private_key=root_key)
    unsigned_bundle_json = bundle.to_json()

    # A bundle whose root signature does not match its body. Loading this must
    # fail: an attacker who can serve the bundle can otherwise insert a key.
    forged = json.loads(signed_bundle_json)
    forged["root_signature"] = flip_last_bit(
        bytes.fromhex(forged["root_signature"])
    ).hex()
    forged_bundle_json = json.dumps(forged, indent=2, ensure_ascii=False)

    # A bundle carrying an extra key the *signature does not cover* — the body
    # was edited after signing. Same failure, different tampering shape.
    injected = json.loads(signed_bundle_json)
    injected["keys"].append(trusted(LICENCE_UNREGISTERED, "Attacker Pharma",
                                    key_unregistered).to_dict())
    injected_bundle_json = json.dumps(injected, indent=2, ensure_ascii=False)

    cases: list[dict] = []

    def add(name, wire, *, verdict, severity, valid, error_code=None,
            checks=None, note="", product_id=None):
        cases.append({
            "name": name,
            "note": note,
            "wire": wire,
            "expect": {
                "valid": valid,
                "verdict": verdict,
                "severity": severity,
                "error_code": error_code,
                "checks": checks or {},
                "product_id": product_id,
            },
        })

    # ── 1. Honest, valid codes ────────────────────────────────────────────────
    med = medicine()
    add(
        "genuine_medicine_offline",
        crypto_wire(med, key_a),
        verdict="SIGNATURE_VALID_OFFLINE",
        severity="warn",
        valid=True,
        checks={"structure": "pass", "signature": "pass", "expiry": "pass"},
        note=("Valid signature, unexpired, no chain evidence. Must be amber, not "
              "green: §2.2 — a valid signature cannot rule out a photocopied QR."),
        product_id=med.product_id,
    )

    vac = vaccine()
    add(
        "genuine_vaccine_offline",
        crypto_wire(vac, key_b),
        verdict="SIGNATURE_VALID_OFFLINE",
        severity="warn",
        valid=True,
        checks={"structure": "pass", "signature": "pass", "expiry": "pass"},
        note="Same as above but tp=V, so cold chain becomes applicable online.",
        product_id=vac.product_id,
    )

    # Devanagari in a signed field. Canonical JSON is ensure_ascii=False, so
    # these are multi-byte UTF-8 inside the signed bytes — the case where a
    # JavaScript implementation that measures length in UTF-16 code units
    # instead of bytes silently breaks.
    hindi = medicine(
        product_id="AMOXICILLIN500MG_AMOXINOVA500_2026_000777",
        generic_name="Amoxicillin 500mg",
        brand_name="Amoxinova 500",
        manufacturer="संजीवनी फार्मा लिमिटेड, प्लॉट ४२ एमआईडीसी, पुणे ४११०१८",
        excipients=["मैज़ स्टार्च", "Povidone K30"],
    )
    add(
        "genuine_unicode_offline",
        crypto_wire(hindi, key_a),
        verdict="SIGNATURE_VALID_OFFLINE",
        severity="warn",
        valid=True,
        checks={"structure": "pass", "signature": "pass", "expiry": "pass"},
        note=("Devanagari in signed fields. Catches UTF-16 vs UTF-8 length and "
              "encoding bugs in the Node implementation."),
        product_id=hindi.product_id,
    )

    # Signed, but the payload keys are NOT in canonical order. Our generator
    # would never emit this, yet the signature is genuinely valid over the bytes
    # as sent, so a verifier that re-serialises before checking would wrongly
    # reject it — and, worse, a verifier that trusts its own re-serialisation
    # could be made to accept something else. Must verify.
    wire_dict = med.to_wire_dict()
    scrambled = json.dumps(
        {k: wire_dict[k] for k in reversed(list(wire_dict.keys()))},
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    add(
        "noncanonical_but_correctly_signed",
        encode(scrambled, crypto.sign(key_a, scrambled)),
        verdict="SIGNATURE_VALID_OFFLINE",
        severity="warn",
        valid=True,
        checks={"structure": "pass", "signature": "pass", "expiry": "pass"},
        note=("Keys in reverse order, signature valid over the received bytes. "
              "Verifying over a re-serialisation would break this — §1.5."),
        product_id=med.product_id,
    )

    # ── 2. Expiry ─────────────────────────────────────────────────────────────
    expired = medicine(
        product_id="METFORMIN500MG_GLUCONORM500_2023_000019",
        generic_name="Metformin 500mg",
        brand_name="Gluconorm 500",
        batch_no="SP23F0088",
        mfg_date="2023-02-01",
        expiry_date="2025-01-31",
    )
    add(
        "expired_medicine",
        crypto_wire(expired, key_a),
        verdict="EXPIRED",
        severity="warn",
        valid=False,
        error_code="EXPIRED",
        checks={"structure": "pass", "signature": "pass", "expiry": "fail"},
        note="Signature fine, 569 days past expiry as of the reference date.",
        product_id=expired.product_id,
    )

    expiring_soon = medicine(
        product_id="AMOXICILLIN500MG_AMOXINOVA500_2026_000501",
        generic_name="Amoxicillin 500mg",
        brand_name="Amoxinova 500",
        batch_no="SP26C0501",
        mfg_date="2026-01-10",
        expiry_date="2026-09-10",
    )
    add(
        "expiring_within_30_days",
        crypto_wire(expiring_soon, key_a),
        verdict="SIGNATURE_VALID_OFFLINE",
        severity="warn",
        valid=True,
        checks={"structure": "pass", "signature": "pass", "expiry": "pass"},
        note=("19 days left at the reference date. Still valid, but must carry an "
              "extra near-expiry warning."),
        product_id=expiring_soon.product_id,
    )

    # ── 3. Forgery ────────────────────────────────────────────────────────────
    good_wire = crypto_wire(med, key_a)
    prefix, payload_b64, sig_b64 = good_wire.split(".")

    add(
        "tampered_signature",
        ".".join([prefix, payload_b64,
                  b64u_encode(flip_last_bit(b64u_decode(sig_b64)))]),
        verdict="COUNTERFEIT",
        severity="critical",
        valid=False,
        error_code="SIGNATURE_INVALID",
        checks={"structure": "pass", "signature": "fail"},
        note="One bit flipped in the signature. Red, not amber.",
        product_id=med.product_id,
    )

    tampered = medicine(expiry_date="2030-12-31")  # attacker extends shelf life
    add(
        "tampered_payload_expiry_extended",
        ".".join([prefix, b64u_encode(tampered.canonical_json()), sig_b64]),
        verdict="COUNTERFEIT",
        severity="critical",
        valid=False,
        error_code="SIGNATURE_INVALID",
        checks={"structure": "pass", "signature": "fail"},
        note=("Expiry pushed out four years on an expired strip, signature left "
              "untouched. The classic relabelling attack."),
        product_id=tampered.product_id,
    )

    add(
        "signed_by_unregistered_key",
        crypto_wire(medicine(mfg_licence_no=LICENCE_UNREGISTERED),
                    key_unregistered),
        verdict="UNVERIFIABLE",
        severity="warn",
        valid=False,
        error_code="SIGNATURE_KEY_UNKNOWN",
        checks={"structure": "pass", "signature": "not_evaluated"},
        note=("Cryptographically sound signature under a key nobody registered. "
              "Amber on purpose — see verifier.py: a stale trust bundle is far "
              "likelier than a forgery, and red on genuine stock destroys trust."),
    )

    add(
        "signed_by_revoked_key",
        crypto_wire(medicine(mfg_licence_no=LICENCE_REVOKED), key_revoked),
        verdict="UNVERIFIABLE",
        severity="warn",
        valid=False,
        error_code="SIGNATURE_KEY_UNKNOWN",
        checks={"structure": "pass", "signature": "not_evaluated"},
        note="Registered licence, key marked revoked in the bundle.",
    )

    # ── 4. Structural rubbish ─────────────────────────────────────────────────
    for name, wire, code, note in [
        ("malformed_empty", "", "QR_MALFORMED", "Empty scan."),
        ("malformed_not_truemed", "https://example.org/pay?a=1", "QR_MALFORMED",
         "A UPI or poster QR caught in frame. Must not say COUNTERFEIT."),
        ("malformed_two_parts", f"{prefix}.{payload_b64}", "QR_MALFORMED",
         "Signature part missing entirely."),
        ("malformed_four_parts", f"{prefix}.{payload_b64}.{sig_b64}.extra",
         "QR_MALFORMED", "Trailing junk appended after the signature."),
        ("malformed_bad_base64", f"{prefix}.not+valid+b64url.{sig_b64}",
         "QR_MALFORMED",
         "'+' is outside base64url. Rejecting it prevents two wire strings "
         "decoding to one payload, which would undermine clone counting."),
        ("malformed_padded_base64", f"{prefix}.{payload_b64}==.{sig_b64}",
         "QR_MALFORMED", "Padding present; we strip it on encode."),
        ("malformed_short_signature", f"{prefix}.{payload_b64}.{sig_b64[:40]}",
         "QR_MALFORMED", "Signature decodes to fewer than 64 bytes."),
        ("unknown_version_tm2", f"TM2.{payload_b64}.{sig_b64}",
         "QR_UNKNOWN_VERSION",
         "A future format. Fail closed and tell the user to update the app."),
        ("unknown_version_tm9", f"TM9.{payload_b64}.{sig_b64}",
         "QR_UNKNOWN_VERSION", "Same, higher number."),
    ]:
        add(name, wire, verdict="UNVERIFIABLE", severity="warn", valid=False,
            error_code=code, checks={"structure": "fail"}, note=note)

    # Well-formed TM1 frame, payload is not the shape we require. Counterfeit
    # rather than unverifiable: QR error correction makes accidental corruption
    # that still decodes as base64 and parses as JSON vanishingly unlikely, so
    # this is fabrication.
    for name, payload_obj, note in [
        ("payload_missing_field", {k: v for k, v in wire_dict.items() if k != "ml"},
         "Manufacturing licence dropped — the field CDSCO requires."),
        ("payload_wrong_type", {**wire_dict, "ex": "Maize Starch,Talc"},
         "Excipients as a comma-joined string instead of an array — §1.3."),
        ("payload_bad_date", {**wire_dict, "ed": "29-02-2028"},
         "Expiry as DD-MM-YYYY. Strict ISO 8601 only."),
        ("payload_bad_version", {**wire_dict, "v": 2},
         "Payload claims contract v2 inside a TM1 frame."),
        ("payload_bad_type_flag", {**wire_dict, "tp": "X"},
         "Type flag is neither M nor V."),
        ("payload_expiry_before_mfg", {**wire_dict, "ed": "2026-03-14"},
         "Expiry one day before manufacture — impossible."),
    ]:
        raw = json.dumps(payload_obj, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False).encode("utf-8")
        add(name, encode(raw, crypto.sign(key_a, raw)),
            verdict="COUNTERFEIT", severity="critical", valid=False,
            error_code="PAYLOAD_INVALID", checks={"structure": "fail"}, note=note)

    add(
        "payload_not_json",
        encode(b"this is not json", crypto.sign(key_a, b"this is not json")),
        verdict="COUNTERFEIT", severity="critical", valid=False,
        error_code="PAYLOAD_INVALID", checks={"structure": "fail"},
        note="Correctly signed, but the payload is not JSON at all.",
    )

    out = {
        "_comment": (
            "Generated by backend/tests/fixtures/generate-fixtures.py from the "
            "Python signer in qr-generator/. Do not hand-edit: regenerate."
        ),
        "reference_date": TODAY.isoformat(),
        "trust_bundle_signed": json.loads(signed_bundle_json),
        "trust_bundle_unsigned": json.loads(unsigned_bundle_json),
        "trust_bundle_forged_signature": forged,
        "trust_bundle_injected_key": injected,
        "root_public_key_pem": crypto.public_key_to_pem(
            root_key.public_key()).decode("utf-8"),
        "root_fingerprint": crypto.fingerprint(root_key.public_key()),
        "licences": {
            "active_medicine": LICENCE_A,
            "active_vaccine": LICENCE_B,
            "revoked": LICENCE_REVOKED,
            "unregistered": LICENCE_UNREGISTERED,
        },
        "canonical_json_samples": [
            {
                "product_id": m.product_id,
                "canonical_json_utf8_hex": m.canonical_json().hex(),
                "byte_length": len(m.canonical_json()),
                "full_names": m.to_dict(),
            }
            for m in (med, vac, hindi)
        ],
        "cases": cases,
    }

    target = HERE / "fixtures.json"
    target.write_text(json.dumps(out, indent=2, ensure_ascii=False) + "\n",
                      encoding="utf-8")
    print(f"wrote {target.relative_to(REPO_ROOT)}: {len(cases)} cases, "
          f"{len(bundle)} trusted keys, {target.stat().st_size} bytes")
    return 0


def crypto_wire(med: MedicineData, key) -> str:
    """Sign a payload and assemble the wire string."""
    raw = med.canonical_json()
    return encode(raw, crypto.sign(key, raw))


if __name__ == "__main__":
    raise SystemExit(main())
