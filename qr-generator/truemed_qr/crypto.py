"""ECDSA P-256 signing, verification, and the TrueMed trust hierarchy.

Two levels of key, which is the part worth understanding:

* **Manufacturer keys** sign individual QR payloads. One per manufacturing
  licence number. The private key never leaves the manufacturer's signing host.
* **A root key** (conceptually held by CDSCO) signs the *trust bundle* — the list
  of which manufacturer public keys are legitimate.

The root key exists to close an otherwise fatal hole. The mobile app has to learn
manufacturer public keys from somewhere, and if it simply trusts whatever
``GET /api/public-keys`` returns, then anyone who can impersonate that endpoint —
a compromised server, a hostile network, a tampered APK's config — can insert
their own key and mint QR codes that verify perfectly. Pinning a single root
public key inside the app binary and requiring the bundle to be root-signed means
an attacker must compromise the offline root key, not merely the API.

Signature encoding: raw ``r‖s``, 64 bytes, rather than the ASN.1 DER that
``cryptography`` emits natively. DER is variable-length (70–72 bytes typically)
and carries redundant structure; raw is fixed-length and 8 bytes shorter, which
matters when the budget is a printed square centimetre. DER also has a long
history of parser-differential bugs, and a fixed-length format has no parser.
"""

from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Final

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

from .errors import KeyStoreError, KeyUnknownError, SignatureInvalidError

#: P-256 field size in bytes. Each of r and s occupies exactly this.
COORD_LEN: Final[int] = 32
#: Total raw signature length.
SIGNATURE_LEN: Final[int] = COORD_LEN * 2

CURVE: Final[ec.EllipticCurve] = ec.SECP256R1()
HASH_ALGO: Final[hashes.HashAlgorithm] = hashes.SHA256()

TRUST_BUNDLE_VERSION: Final[int] = 1


# ── Key generation and storage ────────────────────────────────────────────────


def generate_private_key() -> ec.EllipticCurvePrivateKey:
    """Generate a fresh P-256 private key using the OS CSPRNG."""
    return ec.generate_private_key(CURVE)


def private_key_to_pem(
    private_key: ec.EllipticCurvePrivateKey, password: str | None = None
) -> bytes:
    """Serialise a private key to PKCS#8 PEM, encrypted if a password is given.

    An unencrypted private key on disk is how signing authority leaks. The CLI
    warns when you generate one without a password, and ``.gitignore`` excludes
    ``*.key`` and ``keys/`` so it cannot be committed by accident.
    """
    if password:
        encryption: serialization.KeySerializationEncryption = (
            serialization.BestAvailableEncryption(password.encode("utf-8"))
        )
    else:
        encryption = serialization.NoEncryption()
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )


def public_key_to_pem(public_key: ec.EllipticCurvePublicKey) -> bytes:
    """Serialise a public key to SubjectPublicKeyInfo PEM."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def load_private_key(pem: bytes, password: str | None = None) -> ec.EllipticCurvePrivateKey:
    """Load a P-256 private key from PEM, rejecting other key types."""
    try:
        key = serialization.load_pem_private_key(
            pem, password=password.encode("utf-8") if password else None
        )
    except (ValueError, TypeError) as exc:
        raise KeyStoreError(
            f"could not load private key: {exc}. If it is password-protected, set "
            "TRUEMED_KEY_PASSWORD or pass --key-password-file. There is deliberately "
            "no --key-password flag: argv is readable by every process on the machine."
        ) from exc
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise KeyStoreError(
            f"expected an EC private key, got {type(key).__name__}; TrueMed v1 "
            "signs with ECDSA P-256"
        )
    _assert_p256(key.curve, "private")
    return key


def load_public_key(pem: bytes) -> ec.EllipticCurvePublicKey:
    """Load a P-256 public key from PEM, rejecting other key types."""
    try:
        key = serialization.load_pem_public_key(pem)
    except (ValueError, TypeError) as exc:
        raise KeyStoreError(f"could not load public key: {exc}") from exc
    if not isinstance(key, ec.EllipticCurvePublicKey):
        raise KeyStoreError(
            f"expected an EC public key, got {type(key).__name__}; TrueMed v1 "
            "verifies ECDSA P-256"
        )
    _assert_p256(key.curve, "public")
    return key


def _assert_p256(curve: ec.EllipticCurve, which: str) -> None:
    """Pin the curve.

    Accepting whatever curve a key happens to carry would let an attacker
    downgrade to something weak. v1 is P-256, full stop.
    """
    if curve.name != CURVE.name:
        raise KeyStoreError(
            f"{which} key is on curve {curve.name}, but TrueMed v1 requires "
            f"{CURVE.name} (P-256)"
        )


def fingerprint(public_key: ec.EllipticCurvePublicKey) -> str:
    """Short stable identifier: first 8 bytes of SHA-256 over the DER SPKI.

    Used in logs, the trust bundle, and CLI output so a human can tell two keys
    apart without comparing whole PEM blocks. Not a security boundary — the
    signature check is.
    """
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()[:16]


# ── Signing and verification ──────────────────────────────────────────────────


def sign(private_key: ec.EllipticCurvePrivateKey, data: bytes) -> bytes:
    """Sign ``data`` and return a raw 64-byte ``r‖s`` signature.

    ECDSA is randomised: signing the same bytes twice yields different
    signatures, and both verify. That is expected, not a bug — the tests assert
    it explicitly so nobody later "fixes" it into a deterministic scheme by
    accident.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError(f"data must be bytes, got {type(data).__name__}")
    der = private_key.sign(bytes(data), ec.ECDSA(HASH_ALGO))
    r, s = decode_dss_signature(der)
    return r.to_bytes(COORD_LEN, "big") + s.to_bytes(COORD_LEN, "big")


def verify(
    public_key: ec.EllipticCurvePublicKey, data: bytes, signature: bytes
) -> bool:
    """Verify a raw 64-byte signature. Returns False rather than raising.

    Every failure mode — wrong length, wrong key, tampered data, zero-valued
    r or s — collapses to ``False``. Callers decide what a failure means; here it
    is uniformly "not authentic", so no timing or exception-type side channel
    distinguishes *why* a forgery failed.
    """
    if not isinstance(signature, (bytes, bytearray)) or len(signature) != SIGNATURE_LEN:
        return False
    r = int.from_bytes(signature[:COORD_LEN], "big")
    s = int.from_bytes(signature[COORD_LEN:], "big")
    # r = 0 or s = 0 is never a valid ECDSA signature, and some naive verifiers
    # have historically accepted them. decode/encode round-trip would also raise.
    if r == 0 or s == 0:
        return False
    try:
        der = encode_dss_signature(r, s)
        # Argument order is (signature, data, algorithm) — signature first. Getting
        # this backwards makes every verification fail closed, which is safe but
        # completely non-functional, and the symptom (everything is counterfeit)
        # looks like a key-management problem rather than a call-order bug.
        public_key.verify(der, bytes(data), ec.ECDSA(HASH_ALGO))
        return True
    except (InvalidSignature, ValueError):
        return False


def verify_or_raise(
    public_key: ec.EllipticCurvePublicKey, data: bytes, signature: bytes
) -> None:
    """Verify, raising :class:`SignatureInvalidError` on failure."""
    if not verify(public_key, data, signature):
        raise SignatureInvalidError(
            "ECDSA signature does not match the payload under the trusted key for "
            "this manufacturing licence — treat this item as counterfeit"
        )


# ── Trust bundle ──────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class TrustedKey:
    """One manufacturer signing key, as distributed to the app."""

    mfg_licence_no: str
    manufacturer: str
    public_key_pem: str
    fingerprint: str
    valid_from: str
    valid_until: str
    status: str = "active"  # active | revoked

    @property
    def public_key(self) -> ec.EllipticCurvePublicKey:
        return load_public_key(self.public_key_pem.encode("utf-8"))

    def is_valid_on(self, when: date) -> bool:
        if self.status != "active":
            return False
        return date.fromisoformat(self.valid_from) <= when <= date.fromisoformat(
            self.valid_until
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "mfg_licence_no": self.mfg_licence_no,
            "manufacturer": self.manufacturer,
            "public_key_pem": self.public_key_pem,
            "fingerprint": self.fingerprint,
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
            "status": self.status,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "TrustedKey":
        try:
            return cls(
                mfg_licence_no=raw["mfg_licence_no"],
                manufacturer=raw["manufacturer"],
                public_key_pem=raw["public_key_pem"],
                fingerprint=raw["fingerprint"],
                valid_from=raw["valid_from"],
                valid_until=raw["valid_until"],
                status=raw.get("status", "active"),
            )
        except KeyError as exc:
            raise KeyStoreError(f"trusted key entry missing field {exc.args[0]!r}") from exc


class TrustBundle:
    """The set of manufacturer public keys an app is willing to trust.

    Serialises to JSON, optionally signed by the root key. The app should ship
    with a bundle baked in *and* refresh it from ``GET /api/public-keys``,
    verifying the root signature every time. An unsigned bundle is accepted only
    when ``require_signature=False``, which exists for local development and is
    never the right choice in a build you hand to a patient.
    """

    def __init__(self, keys: list[TrustedKey], issued_at: str | None = None) -> None:
        self.keys = keys
        self.issued_at = issued_at or datetime.now(timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        self._by_licence: dict[str, TrustedKey] = {}
        for key in keys:
            if key.mfg_licence_no in self._by_licence:
                raise KeyStoreError(
                    f"duplicate manufacturing licence {key.mfg_licence_no!r} in trust "
                    "bundle — one licence maps to exactly one active signing key"
                )
            self._by_licence[key.mfg_licence_no] = key

    # -- lookup -------------------------------------------------------------

    def public_key_for(
        self, mfg_licence_no: str, when: date | None = None
    ) -> ec.EllipticCurvePublicKey:
        """Resolve a licence number to its trusted public key."""
        entry = self._by_licence.get(mfg_licence_no)
        if entry is None:
            raise KeyUnknownError(
                f"no trusted signing key registered for manufacturing licence "
                f"{mfg_licence_no!r}; either the trust bundle is stale or this QR "
                "was signed by an unregistered party"
            )
        if not entry.is_valid_on(when or date.today()):
            raise KeyUnknownError(
                f"signing key for licence {mfg_licence_no!r} is {entry.status} / outside "
                f"its validity window {entry.valid_from}..{entry.valid_until}"
            )
        return entry.public_key

    def __len__(self) -> int:
        return len(self.keys)

    def __contains__(self, mfg_licence_no: object) -> bool:
        return mfg_licence_no in self._by_licence

    # -- serialisation ------------------------------------------------------

    def _signable_bytes(self) -> bytes:
        """Canonical bytes covered by the root signature."""
        return json.dumps(
            {
                "version": TRUST_BUNDLE_VERSION,
                "issued_at": self.issued_at,
                "keys": [k.to_dict() for k in self.keys],
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")

    def to_json(self, root_private_key: ec.EllipticCurvePrivateKey | None = None) -> str:
        body: dict[str, Any] = {
            "version": TRUST_BUNDLE_VERSION,
            "issued_at": self.issued_at,
            "keys": [k.to_dict() for k in self.keys],
        }
        if root_private_key is not None:
            sig = sign(root_private_key, self._signable_bytes())
            body["root_signature"] = sig.hex()
            body["root_fingerprint"] = fingerprint(root_private_key.public_key())
        return json.dumps(body, indent=2, ensure_ascii=False)

    @classmethod
    def from_json(
        cls,
        blob: str | bytes,
        root_public_key: ec.EllipticCurvePublicKey | None = None,
        *,
        require_signature: bool = True,
    ) -> "TrustBundle":
        try:
            raw = json.loads(blob)
        except json.JSONDecodeError as exc:
            raise KeyStoreError(f"trust bundle is not valid JSON: {exc.msg}") from exc
        if not isinstance(raw, dict):
            raise KeyStoreError("trust bundle must be a JSON object")
        if raw.get("version") != TRUST_BUNDLE_VERSION:
            raise KeyStoreError(
                f"unsupported trust bundle version {raw.get('version')!r}; "
                f"this build understands version {TRUST_BUNDLE_VERSION}"
            )
        entries = raw.get("keys")
        if not isinstance(entries, list):
            raise KeyStoreError("trust bundle 'keys' must be an array")

        bundle = cls(
            [TrustedKey.from_dict(e) for e in entries], issued_at=raw.get("issued_at")
        )

        sig_hex = raw.get("root_signature")
        if require_signature:
            if root_public_key is None:
                raise KeyStoreError(
                    "require_signature=True but no root public key was supplied; "
                    "an unverified trust bundle is worthless — an attacker who can "
                    "serve it can insert their own signing key"
                )
            if not isinstance(sig_hex, str):
                raise KeyStoreError("trust bundle is unsigned and require_signature=True")
            try:
                sig = bytes.fromhex(sig_hex)
            except ValueError as exc:
                raise KeyStoreError("root_signature is not valid hex") from exc
            if not verify(root_public_key, bundle._signable_bytes(), sig):
                raise SignatureInvalidError(
                    "trust bundle root signature is invalid — refusing to load. "
                    "Either the bundle was tampered with in transit or it was signed "
                    "by a key this build does not pin."
                )
        return bundle

    # -- construction helpers ----------------------------------------------

    @classmethod
    def from_dir(
        cls, directory: Path, *, root_public_key: ec.EllipticCurvePublicKey | None = None,
        require_signature: bool = True,
    ) -> "TrustBundle":
        """Load ``trust-bundle.json`` from a directory."""
        path = Path(directory) / "trust-bundle.json"
        if not path.is_file():
            raise KeyStoreError(
                f"no trust-bundle.json in {directory}. Run "
                "`python main.py keygen --out keys/` to create a key set."
            )
        return cls.from_json(
            path.read_text(encoding="utf-8"),
            root_public_key=root_public_key,
            require_signature=require_signature,
        )

    @classmethod
    def single(
        cls,
        mfg_licence_no: str,
        manufacturer: str,
        public_key: ec.EllipticCurvePublicKey,
        *,
        valid_from: str = "2020-01-01",
        valid_until: str = "2099-12-31",
    ) -> "TrustBundle":
        """One-key bundle. Convenient in tests and single-manufacturer demos."""
        return cls(
            [
                TrustedKey(
                    mfg_licence_no=mfg_licence_no,
                    manufacturer=manufacturer,
                    public_key_pem=public_key_to_pem(public_key).decode("utf-8"),
                    fingerprint=fingerprint(public_key),
                    valid_from=valid_from,
                    valid_until=valid_until,
                )
            ]
        )


def new_api_key(role: str) -> str:
    """Generate an API key of the form ``tm_<role>_<32 hex>``.

    Lives here because it is CSPRNG-backed material and belongs beside the other
    secret generation. The server stores only ``sha256(key)``.
    """
    allowed = {"manufacturer", "distributor", "sensor", "regulator", "pharma"}
    if role not in allowed:
        raise ValueError(f"role must be one of {sorted(allowed)}, got {role!r}")
    return f"tm_{role}_{secrets.token_hex(16)}"


def hash_api_key(api_key: str) -> str:
    """SHA-256 hex of an API key, as stored in PostgreSQL.

    A plain hash rather than bcrypt/argon2 is deliberate and correct *here*: an
    API key is 128 bits of CSPRNG output, not a human-chosen password, so it has
    no dictionary to attack and stretching buys nothing while costing latency on
    every request. The reasoning does not transfer to user passwords.
    """
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()
