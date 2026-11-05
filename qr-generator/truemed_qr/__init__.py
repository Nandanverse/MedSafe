"""TrueMed — Truth in Every Medicine.

CDSCO-format QR code generation and offline verification for medicines and
vaccines, signed with ECDSA P-256.

The public surface, in the order you would normally use it::

    from truemed_qr import (
        MedicineData, make_product_id,          # build a payload
        generate_private_key, TrustBundle,      # key material
        generate,                               # sign + render a PNG
        verify_wire,                            # verify offline
    )

Modules are importable independently, and nothing in the verification path
depends on an image library — so ``verify_wire`` works in an environment with only
``cryptography`` installed, and the same logic ports cleanly to Dart for the
mobile app.
"""

from __future__ import annotations

__version__ = "1.0.0"
__all__ = [
    # payload
    "MedicineData",
    "make_product_id",
    "parse_iso_date",
    "CONTRACT_VERSION",
    "WIRE_PREFIX",
    "TYPE_MEDICINE",
    "TYPE_VACCINE",
    "VACCINE_TEMP_MIN_C",
    "VACCINE_TEMP_MAX_C",
    "MAX_PAYLOAD_BYTES",
    "QR_MAX_BYTES_ECC_H",
    # crypto
    "generate_private_key",
    "private_key_to_pem",
    "public_key_to_pem",
    "load_private_key",
    "load_public_key",
    "fingerprint",
    "sign",
    "verify",
    "TrustBundle",
    "TrustedKey",
    "new_api_key",
    "hash_api_key",
    # codec
    "encode",
    "decode",
    "looks_like_truemed",
    # generator
    "build_wire",
    "generate",
    "render_png",
    "GeneratedQR",
    # verifier
    "verify_wire",
    "verify_image",
    "merge_online_evidence",
    "VerificationResult",
    # demo data
    "demo_medicines",
    # errors
    "TrueMedError",
]

from .codec import decode, encode, looks_like_truemed
from .crypto import (
    TrustBundle,
    TrustedKey,
    fingerprint,
    generate_private_key,
    hash_api_key,
    load_private_key,
    load_public_key,
    new_api_key,
    private_key_to_pem,
    public_key_to_pem,
    sign,
    verify,
)
from .demo_data import demo_medicines
from .errors import TrueMedError
from .generator import GeneratedQR, build_wire, generate, render_png
from .payload import (
    CONTRACT_VERSION,
    MAX_PAYLOAD_BYTES,
    QR_MAX_BYTES_ECC_H,
    TYPE_MEDICINE,
    TYPE_VACCINE,
    VACCINE_TEMP_MAX_C,
    VACCINE_TEMP_MIN_C,
    WIRE_PREFIX,
    MedicineData,
    make_product_id,
    parse_iso_date,
)
from .verifier import (
    VerificationResult,
    merge_online_evidence,
    verify_image,
    verify_wire,
)
