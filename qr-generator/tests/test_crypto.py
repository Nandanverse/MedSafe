"""ECDSA signing, key handling, and trust bundle tests.

The most important test in this file is
``TestVerify.test_argument_order_is_signature_first``. During development the
arguments to ``public_key.verify`` were transposed, which made every single
verification return False — genuine medicine reported as counterfeit, system-wide,
with a symptom that looks like a key-distribution problem. It failed closed, so
nothing unsafe happened, but the system was completely non-functional. That bug
must never come back silently.
"""

from __future__ import annotations

import json
from datetime import date

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from truemed_qr import crypto
from truemed_qr.errors import KeyStoreError, KeyUnknownError, SignatureInvalidError

DATA = b'{"bt":"SP26C0417","id":"X_Y_2026_000001"}'


class TestSign:
    def test_signature_is_64_raw_bytes(self, private_key):
        sig = crypto.sign(private_key, DATA)
        assert isinstance(sig, bytes)
        assert len(sig) == crypto.SIGNATURE_LEN == 64

    def test_ecdsa_is_randomised(self, private_key):
        # ECDSA draws a fresh nonce per signature, so two signatures over identical
        # bytes differ and both verify. Asserted explicitly so that nobody later
        # "fixes" the apparent non-determinism into something deterministic.
        a = crypto.sign(private_key, DATA)
        b = crypto.sign(private_key, DATA)
        assert a != b
        assert crypto.verify(private_key.public_key(), DATA, a)
        assert crypto.verify(private_key.public_key(), DATA, b)

    def test_empty_data_can_be_signed(self, private_key):
        sig = crypto.sign(private_key, b"")
        assert crypto.verify(private_key.public_key(), b"", sig)

    def test_rejects_str(self, private_key):
        with pytest.raises(TypeError, match="must be bytes"):
            crypto.sign(private_key, "not bytes")  # type: ignore[arg-type]

    def test_accepts_bytearray(self, private_key):
        sig = crypto.sign(private_key, bytearray(DATA))
        assert crypto.verify(private_key.public_key(), DATA, sig)


class TestVerify:
    def test_argument_order_is_signature_first(self, private_key, public_key):
        # Regression guard. If verify() ever calls the underlying library with
        # (data, signature) instead of (signature, data), this fails immediately.
        assert crypto.verify(public_key, DATA, crypto.sign(private_key, DATA)) is True

    def test_tampered_data_rejected(self, private_key, public_key):
        sig = crypto.sign(private_key, DATA)
        assert not crypto.verify(public_key, DATA + b" ", sig)
        assert not crypto.verify(public_key, DATA.replace(b"2026", b"2027"), sig)

    def test_wrong_key_rejected(self, private_key, other_private_key):
        sig = crypto.sign(private_key, DATA)
        assert not crypto.verify(other_private_key.public_key(), DATA, sig)

    @pytest.mark.parametrize("length", [0, 1, 32, 63, 65, 71, 128])
    def test_wrong_signature_length_rejected(self, public_key, length):
        assert not crypto.verify(public_key, DATA, b"\x01" * length)

    def test_der_signature_rejected(self, private_key, public_key):
        # We carry raw r‖s. A DER blob is the wrong wire encoding even though it
        # is a perfectly valid signature, and must not be silently accepted.
        der = private_key.sign(DATA, ec.ECDSA(crypto.HASH_ALGO))
        assert not crypto.verify(public_key, DATA, der)

    def test_zero_r_or_s_rejected(self, public_key):
        # r = 0 or s = 0 is never valid ECDSA; some naive verifiers have
        # historically accepted them, so it is checked before touching the library.
        zero = b"\x00" * 32
        one = b"\x00" * 31 + b"\x01"
        assert not crypto.verify(public_key, DATA, zero + one)
        assert not crypto.verify(public_key, DATA, one + zero)
        assert not crypto.verify(public_key, DATA, zero + zero)

    def test_all_ones_signature_rejected(self, public_key):
        assert not crypto.verify(public_key, DATA, b"\xff" * 64)

    def test_single_bit_flip_rejected(self, private_key, public_key):
        sig = bytearray(crypto.sign(private_key, DATA))
        sig[10] ^= 0x01
        assert not crypto.verify(public_key, DATA, bytes(sig))

    def test_non_bytes_signature_rejected(self, public_key):
        assert not crypto.verify(public_key, DATA, "signature")  # type: ignore[arg-type]

    def test_verify_or_raise_passes(self, private_key, public_key):
        crypto.verify_or_raise(public_key, DATA, crypto.sign(private_key, DATA))

    def test_verify_or_raise_fails(self, public_key):
        with pytest.raises(SignatureInvalidError, match="counterfeit"):
            crypto.verify_or_raise(public_key, DATA, b"\x01" * 64)


class TestKeySerialisation:
    def test_private_pem_round_trip(self, private_key):
        pem = crypto.private_key_to_pem(private_key)
        assert pem.startswith(b"-----BEGIN PRIVATE KEY-----")
        loaded = crypto.load_private_key(pem)
        # Same key means signatures cross-verify.
        assert crypto.verify(
            private_key.public_key(), DATA, crypto.sign(loaded, DATA)
        )

    def test_encrypted_private_pem_round_trip(self, private_key):
        pem = crypto.private_key_to_pem(private_key, password="s3cret")
        assert b"ENCRYPTED" in pem
        loaded = crypto.load_private_key(pem, password="s3cret")
        assert crypto.fingerprint(loaded.public_key()) == crypto.fingerprint(
            private_key.public_key()
        )

    def test_encrypted_key_wrong_password(self, private_key):
        pem = crypto.private_key_to_pem(private_key, password="s3cret")
        with pytest.raises(KeyStoreError, match="key-password|could not load"):
            crypto.load_private_key(pem, password="wrong")

    def test_encrypted_key_no_password(self, private_key):
        pem = crypto.private_key_to_pem(private_key, password="s3cret")
        with pytest.raises(KeyStoreError):
            crypto.load_private_key(pem)

    def test_public_pem_round_trip(self, public_key):
        pem = crypto.public_key_to_pem(public_key)
        assert pem.startswith(b"-----BEGIN PUBLIC KEY-----")
        assert crypto.fingerprint(crypto.load_public_key(pem)) == crypto.fingerprint(
            public_key
        )

    def test_garbage_pem_rejected(self):
        with pytest.raises(KeyStoreError, match="could not load"):
            crypto.load_public_key(b"-----BEGIN PUBLIC KEY-----\nnope\n")

    def test_rsa_key_rejected(self):
        # An RSA key is not merely unsupported: silently accepting it would mean
        # signatures of a different size and shape flowing through a wire format
        # that hard-codes 64 bytes.
        rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = rsa_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        with pytest.raises(KeyStoreError, match="expected an EC private key"):
            crypto.load_private_key(pem)

    def test_rsa_public_key_rejected(self):
        rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = rsa_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        with pytest.raises(KeyStoreError, match="expected an EC public key"):
            crypto.load_public_key(pem)

    def test_wrong_curve_rejected(self):
        # Curve agility is an attack surface, not a feature: without pinning, an
        # attacker could present a key on a weaker curve.
        p384 = ec.generate_private_key(ec.SECP384R1())
        pem = crypto.private_key_to_pem(p384)
        with pytest.raises(KeyStoreError, match="secp256r1"):
            crypto.load_private_key(pem)

    def test_wrong_curve_public_rejected(self):
        p384 = ec.generate_private_key(ec.SECP384R1())
        pem = crypto.public_key_to_pem(p384.public_key())
        with pytest.raises(KeyStoreError, match="secp256r1"):
            crypto.load_public_key(pem)


class TestFingerprint:
    def test_stable(self, public_key):
        assert crypto.fingerprint(public_key) == crypto.fingerprint(public_key)

    def test_16_hex_chars(self, public_key):
        fp = crypto.fingerprint(public_key)
        assert len(fp) == 16
        int(fp, 16)  # raises if not hex

    def test_different_keys_differ(self, public_key, other_private_key):
        assert crypto.fingerprint(public_key) != crypto.fingerprint(
            other_private_key.public_key()
        )

    def test_survives_pem_round_trip(self, public_key):
        reloaded = crypto.load_public_key(crypto.public_key_to_pem(public_key))
        assert crypto.fingerprint(reloaded) == crypto.fingerprint(public_key)


class TestTrustBundleLookup:
    def test_single_lookup(self, bundle, public_key):
        found = bundle.public_key_for("MH/25D/2019/187")
        assert crypto.fingerprint(found) == crypto.fingerprint(public_key)

    def test_len_and_contains(self, bundle):
        assert len(bundle) == 1
        assert "MH/25D/2019/187" in bundle
        assert "XX/99Z/1999/000" not in bundle

    def test_unknown_licence(self, bundle):
        with pytest.raises(KeyUnknownError, match="no trusted signing key"):
            bundle.public_key_for("XX/99Z/1999/000")

    def test_revoked_key_refused(self, public_key):
        revoked = crypto.TrustedKey(
            mfg_licence_no="MH/25D/2019/187",
            manufacturer="Sanjeevani Pharma Ltd",
            public_key_pem=crypto.public_key_to_pem(public_key).decode(),
            fingerprint=crypto.fingerprint(public_key),
            valid_from="2020-01-01",
            valid_until="2099-12-31",
            status="revoked",
        )
        b = crypto.TrustBundle([revoked])
        with pytest.raises(KeyUnknownError, match="revoked"):
            b.public_key_for("MH/25D/2019/187")

    def test_outside_validity_window(self, public_key):
        b = crypto.TrustBundle.single(
            "MH/25D/2019/187",
            "Sanjeevani Pharma Ltd",
            public_key,
            valid_from="2020-01-01",
            valid_until="2021-12-31",
        )
        with pytest.raises(KeyUnknownError, match="validity window"):
            b.public_key_for("MH/25D/2019/187", when=date(2026, 6, 1))
        # Inside the window it resolves fine.
        assert b.public_key_for("MH/25D/2019/187", when=date(2021, 1, 1)) is not None

    def test_validity_window_is_inclusive(self, public_key):
        b = crypto.TrustBundle.single(
            "L", "M", public_key, valid_from="2026-01-01", valid_until="2026-12-31"
        )
        assert b.public_key_for("L", when=date(2026, 1, 1)) is not None
        assert b.public_key_for("L", when=date(2026, 12, 31)) is not None

    def test_duplicate_licence_rejected(self, public_key, other_private_key):
        # One licence, one active signing key. Two would make "which key signed
        # this" ambiguous and give a leaked key somewhere to hide.
        a = crypto.TrustBundle.single("L", "M", public_key).keys[0]
        b = crypto.TrustBundle.single(
            "L", "M2", other_private_key.public_key()
        ).keys[0]
        with pytest.raises(KeyStoreError, match="duplicate manufacturing licence"):
            crypto.TrustBundle([a, b])

    def test_missing_field_in_entry(self):
        with pytest.raises(KeyStoreError, match="missing field"):
            crypto.TrustedKey.from_dict({"mfg_licence_no": "L"})


class TestTrustBundleSigning:
    def test_signed_round_trip(self, bundle, root_private_key):
        blob = bundle.to_json(root_private_key)
        loaded = crypto.TrustBundle.from_json(
            blob, root_public_key=root_private_key.public_key()
        )
        assert len(loaded) == 1
        assert "MH/25D/2019/187" in loaded

    def test_records_root_fingerprint(self, bundle, root_private_key):
        raw = json.loads(bundle.to_json(root_private_key))
        assert raw["root_fingerprint"] == crypto.fingerprint(
            root_private_key.public_key()
        )
        assert len(bytes.fromhex(raw["root_signature"])) == 64

    def test_tampered_key_detected(self, bundle, root_private_key, other_private_key):
        # The attack this defends against: swap in your own public key so your
        # forged QR codes verify. Without the root signature it works perfectly.
        raw = json.loads(bundle.to_json(root_private_key))
        raw["keys"][0]["public_key_pem"] = crypto.public_key_to_pem(
            other_private_key.public_key()
        ).decode()
        with pytest.raises(SignatureInvalidError, match="root signature is invalid"):
            crypto.TrustBundle.from_json(
                json.dumps(raw), root_public_key=root_private_key.public_key()
            )

    def test_added_key_detected(self, bundle, root_private_key, other_private_key):
        raw = json.loads(bundle.to_json(root_private_key))
        extra = crypto.TrustBundle.single(
            "XX/99Z/1999/000", "Evil Pharma", other_private_key.public_key()
        ).keys[0]
        raw["keys"].append(extra.to_dict())
        with pytest.raises(SignatureInvalidError):
            crypto.TrustBundle.from_json(
                json.dumps(raw), root_public_key=root_private_key.public_key()
            )

    def test_tampered_issued_at_detected(self, bundle, root_private_key):
        raw = json.loads(bundle.to_json(root_private_key))
        raw["issued_at"] = "2030-01-01T00:00:00Z"
        with pytest.raises(SignatureInvalidError):
            crypto.TrustBundle.from_json(
                json.dumps(raw), root_public_key=root_private_key.public_key()
            )

    def test_signed_by_wrong_root_detected(self, bundle, root_private_key, other_private_key):
        blob = bundle.to_json(other_private_key)
        with pytest.raises(SignatureInvalidError):
            crypto.TrustBundle.from_json(
                blob, root_public_key=root_private_key.public_key()
            )

    def test_unsigned_bundle_refused_by_default(self, bundle, root_private_key):
        with pytest.raises(KeyStoreError, match="unsigned"):
            crypto.TrustBundle.from_json(
                bundle.to_json(), root_public_key=root_private_key.public_key()
            )

    def test_no_root_key_supplied(self, bundle, root_private_key):
        with pytest.raises(KeyStoreError, match="no root public key"):
            crypto.TrustBundle.from_json(bundle.to_json(root_private_key))

    def test_unsigned_allowed_when_explicitly_opted_out(self, bundle):
        loaded = crypto.TrustBundle.from_json(
            bundle.to_json(), require_signature=False
        )
        assert len(loaded) == 1

    def test_bad_hex_signature(self, bundle, root_private_key):
        raw = json.loads(bundle.to_json(root_private_key))
        raw["root_signature"] = "not hex"
        with pytest.raises(KeyStoreError, match="not valid hex"):
            crypto.TrustBundle.from_json(
                json.dumps(raw), root_public_key=root_private_key.public_key()
            )

    def test_wrong_version_refused(self, bundle, root_private_key):
        raw = json.loads(bundle.to_json(root_private_key))
        raw["version"] = 99
        with pytest.raises(KeyStoreError, match="unsupported trust bundle version"):
            crypto.TrustBundle.from_json(
                json.dumps(raw), root_public_key=root_private_key.public_key()
            )

    def test_not_json(self):
        with pytest.raises(KeyStoreError, match="not valid JSON"):
            crypto.TrustBundle.from_json("{nope", require_signature=False)

    def test_not_an_object(self):
        with pytest.raises(KeyStoreError, match="must be a JSON object"):
            crypto.TrustBundle.from_json("[]", require_signature=False)

    def test_keys_not_an_array(self):
        with pytest.raises(KeyStoreError, match="must be an array"):
            crypto.TrustBundle.from_json(
                json.dumps({"version": 1, "keys": {}}), require_signature=False
            )

    def test_from_dir_missing_file(self, tmp_path):
        with pytest.raises(KeyStoreError, match="no trust-bundle.json"):
            crypto.TrustBundle.from_dir(tmp_path, require_signature=False)

    def test_from_dir_round_trip(self, tmp_path, bundle, root_private_key):
        (tmp_path / "trust-bundle.json").write_text(
            bundle.to_json(root_private_key), encoding="utf-8"
        )
        loaded = crypto.TrustBundle.from_dir(
            tmp_path, root_public_key=root_private_key.public_key()
        )
        assert "MH/25D/2019/187" in loaded


class TestAPIKeys:
    @pytest.mark.parametrize(
        "role", ["manufacturer", "distributor", "sensor", "regulator", "pharma"]
    )
    def test_format(self, role):
        key = crypto.new_api_key(role)
        assert key.startswith(f"tm_{role}_")
        assert len(key.rsplit("_", 1)[1]) == 32

    def test_unique(self):
        keys = {crypto.new_api_key("sensor") for _ in range(200)}
        assert len(keys) == 200

    def test_unknown_role(self):
        with pytest.raises(ValueError, match="role must be one of"):
            crypto.new_api_key("admin")

    def test_hash_is_sha256_hex(self):
        digest = crypto.hash_api_key("tm_sensor_" + "a" * 32)
        assert len(digest) == 64
        int(digest, 16)

    def test_hash_deterministic_and_distinguishing(self):
        a = crypto.new_api_key("sensor")
        b = crypto.new_api_key("sensor")
        assert crypto.hash_api_key(a) == crypto.hash_api_key(a)
        assert crypto.hash_api_key(a) != crypto.hash_api_key(b)
