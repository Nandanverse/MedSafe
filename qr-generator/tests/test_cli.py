"""End-to-end tests for the command-line interface.

These drive the real ``main(argv)`` entry point in-process rather than shelling
out: a failing assertion then points at a line of Python, and the suite runs in
the same interpreter so coverage and the air-gapped fallback runner both see it.

Two constraints shape the style here:

* The fallback runner in ``tools/run_tests.py`` implements ``tmp_path`` and
  ``monkeypatch`` but **not** ``capsys``, so output is captured with
  ``redirect_stdout`` / ``redirect_stderr`` instead. It also resolves fixtures
  from ``conftest`` only, so shared setup lives in module-level helper functions,
  not in ``@pytest.fixture`` definitions in this file.
* Everything a test verifies is signed by keys ``keygen`` actually wrote to disk
  and checked against the trust bundle it actually produced — the same objects a
  user handles. Nothing is signed by an in-memory key that no bundle knows about,
  because that would test a path the CLI never takes.
"""

from __future__ import annotations

import contextlib
import io
import json
import sys
from pathlib import Path
from typing import Any, Sequence

import pytest

from truemed_qr import crypto
from truemed_qr.cli import (
    EXIT_ERROR,
    EXIT_OK,
    EXIT_USAGE,
    EXIT_VERDICT_CRITICAL,
    EXIT_VERDICT_WARN,
    main,
)
from truemed_qr.codec import decode as decode_wire
from truemed_qr.codec import encode as encode_wire

# Manifest indices from demo_data.CATALOGUE, so a test can say "the expired one"
# without restating which brand that is.
IDX_VALID_MEDICINE = 0      # Paracip 500
IDX_EXPIRED = 2             # Glucomet 500, expired 45 days ago
IDX_VACCINE = 3            # Rakshak BCG, cold-chain applies
IDX_NEAR_EXPIRY = 4        # Suraksha MR, expires in 20 days

DEMO_TODAY = "2026-06-01"   # fixed so the expired/near-expiry samples stay put


def _run(argv: Sequence[str], stdin: str | None = None) -> tuple[int, str, str]:
    """Invoke the CLI, returning ``(exit_code, stdout, stderr)``.

    ``argparse`` raises ``SystemExit`` for ``--version`` and for usage errors;
    both are normalised to a return code here so a test never has to wrap the
    call in its own try/except.
    """
    out, err = io.StringIO(), io.StringIO()
    real_stdin = sys.stdin
    if stdin is not None:
        # StringIO.isatty() is False, so the CLI's "stdin is a terminal" guard is
        # not tripped and the piped value is read as intended.
        sys.stdin = io.StringIO(stdin)
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(list(argv))
    except SystemExit as exc:
        if exc.code is None:
            code = 0
        elif isinstance(exc.code, int):
            code = exc.code
        else:
            code = 1
    finally:
        sys.stdin = real_stdin
    return code, out.getvalue(), err.getvalue()


def _keygen(tmp_path: Path, *args: str) -> Path:
    """Create a key set under ``tmp_path/keys`` and return its directory."""
    keys_dir = tmp_path / "keys"
    code, _, err = _run(["keygen", "--out", str(keys_dir), *args])
    assert code == EXIT_OK, err
    return keys_dir


def _keyset_with_demo(tmp_path: Path, count: int = 5) -> tuple[Path, list[dict[str, Any]]]:
    """A key set plus a demo run, returning ``(keys_dir, manifest_items)``.

    The items carry the wire strings signed by the on-disk keys, which is what
    the verification tests consume.
    """
    keys_dir = _keygen(tmp_path)
    out_dir = tmp_path / "out"
    code, _, err = _run([
        "demo", "--keys", str(keys_dir), "--count", str(count),
        "--out", str(out_dir), "--no-png", "--today", DEMO_TODAY,
    ])
    assert code == EXIT_OK, err
    items = json.loads((out_dir / "manifest.json").read_text(encoding="utf-8"))["items"]
    assert len(items) == count
    return keys_dir, items


def _tamper(wire: str, find: bytes, replace: bytes) -> str:
    """Flip bytes inside the payload, keeping length so it stays valid JSON.

    A same-length edit forces the failure onto the signature check rather than
    the JSON parse, which is the case that proves signatures actually bind the
    content.
    """
    decoded = decode_wire(wire)
    mutated = decoded.payload_bytes.replace(find, replace)
    assert mutated != decoded.payload_bytes, "tamper fixture matched nothing"
    assert len(mutated) == len(decoded.payload_bytes), "tamper changed the length"
    return encode_wire(mutated, decoded.signature)


# ── keygen ──────────────────────────────────────────────────────────────────


class TestKeygen:
    def test_default_set_covers_every_demo_manufacturer(self, tmp_path):
        keys_dir = _keygen(tmp_path)
        keyset = json.loads((keys_dir / "keyset.json").read_text(encoding="utf-8"))
        # demo_medicines(5) spans four distinct licences, so the default set must
        # contain four signers or `demo` would fail to find a key.
        assert len(keyset["signers"]) == 4
        for name in ("root.key", "root.pub", "trust-bundle.json", "keyset.json"):
            assert (keys_dir / name).is_file()
        assert len(list((keys_dir / "signers").glob("*.key"))) == 4

    def test_bundle_is_root_signed(self, tmp_path):
        keys_dir = _keygen(tmp_path)
        bundle = json.loads((keys_dir / "trust-bundle.json").read_text(encoding="utf-8"))
        assert "root_signature" in bundle and bundle["root_signature"]
        # And it verifies under the root public key that was written alongside it.
        root_pub = crypto.load_public_key((keys_dir / "root.pub").read_bytes())
        loaded = crypto.TrustBundle.from_json(
            (keys_dir / "trust-bundle.json").read_text(encoding="utf-8"),
            root_public_key=root_pub,
            require_signature=True,
        )
        assert len(loaded) == 4

    def test_refuses_to_overwrite_without_force(self, tmp_path):
        keys_dir = _keygen(tmp_path)
        code, _, err = _run(["keygen", "--out", str(keys_dir)])
        assert code == EXIT_ERROR
        assert "already exists" in err
        assert "COUNTERFEIT" in err  # explains the consequence, not just "exists"

    def test_force_regenerates(self, tmp_path):
        keys_dir = _keygen(tmp_path)
        before = (keys_dir / "root.pub").read_text(encoding="utf-8")
        code, _, err = _run(["keygen", "--out", str(keys_dir), "--force"])
        assert code == EXIT_OK, err
        after = (keys_dir / "root.pub").read_text(encoding="utf-8")
        assert before != after, "forced regeneration must produce a new root key"

    def test_add_appends_and_keeps_the_root(self, tmp_path):
        keys_dir = _keygen(tmp_path)
        root_before = (keys_dir / "root.pub").read_text(encoding="utf-8")
        code, out, err = _run([
            "keygen", "--out", str(keys_dir), "--add",
            "--licence", "KA/25D/2022/509", "--manufacturer", "Nirmal Formulations Ltd",
        ])
        assert code == EXIT_OK, err
        keyset = json.loads((keys_dir / "keyset.json").read_text(encoding="utf-8"))
        assert len(keyset["signers"]) == 5
        # --add must reuse the root: rotating it would invalidate every bundle any
        # app has already pinned.
        assert (keys_dir / "root.pub").read_text(encoding="utf-8") == root_before

    def test_single_licence(self, tmp_path):
        keys_dir = tmp_path / "keys"
        code, _, err = _run([
            "keygen", "--out", str(keys_dir),
            "--licence", "MH/25D/2019/187", "--manufacturer", "Sanjeevani Pharma Ltd",
        ])
        assert code == EXIT_OK, err
        keyset = json.loads((keys_dir / "keyset.json").read_text(encoding="utf-8"))
        assert len(keyset["signers"]) == 1

    def test_licence_without_manufacturer_is_a_usage_error(self, tmp_path):
        code, _, err = _run(["keygen", "--out", str(tmp_path / "k"), "--licence", "X/1/2/3"])
        assert code == EXIT_USAGE
        assert "manufacturer" in err

    def test_licence_numbers_with_slashes_become_safe_filenames(self, tmp_path):
        keys_dir = _keygen(tmp_path)
        names = {p.name for p in (keys_dir / "signers").glob("*.key")}
        assert "MH-25D-2019-187.key" in names  # slashes collapsed to hyphens
        assert not any("/" in n for n in names)


# ── generate ──────────────────────────────────────────────────────────────────


def _generate_args(**overrides: str) -> list[str]:
    fields = {
        "--generic-name": "Amoxicillin 500mg",
        "--brand-name": "Amoxinova 500",
        "--manufacturer": "Sanjeevani Pharma Ltd, Plot 42 MIDC, Pune 411018",
        "--mfg-licence-no": "MH/25D/2019/187",
        "--batch-no": "SP26H0777",
        "--mfg-date": "2026-03-04",
        "--expiry-date": "2028-03-03",
        "--quantity": "10 capsules",
    }
    fields.update(overrides)
    args: list[str] = []
    for key, value in fields.items():
        args += [key, value]
    return args


class TestGenerate:
    def test_generate_without_png_needs_no_qrcode(self, tmp_path):
        keys_dir = _keygen(tmp_path)
        code, out, err = _run([
            "generate", "--keys", str(keys_dir), "--no-png", *_generate_args(),
        ])
        assert code == EXIT_OK, err
        assert "AMOXICILLIN500MG_AMOXINOVA500" in out

    def test_generate_signs_with_the_licence_key_and_verifies(self, tmp_path):
        keys_dir = _keygen(tmp_path)
        code, out, _ = _run([
            "generate", "--keys", str(keys_dir), "--no-png", "--json", *_generate_args(),
        ])
        assert code == EXIT_OK
        wire = json.loads(out)[0]["wire"]
        code, _, err = _run(["verify", "--keys", str(keys_dir), "--wire", wire])
        assert code == EXIT_OK, err  # SIGNATURE_VALID_OFFLINE exits 0

    def test_repeated_excipient_flags_are_not_comma_split(self, tmp_path):
        keys_dir = _keygen(tmp_path)
        code, out, _ = _run([
            "generate", "--keys", str(keys_dir), "--no-png", "--json",
            "--excipient", "Iron Oxide, Red", "--excipient", "Talc",
            *_generate_args(),
        ])
        assert code == EXIT_OK
        excipients = json.loads(out)[0]["data"]["excipients"]
        # "Iron Oxide, Red" must survive as one excipient, comma and all.
        assert excipients == ["Iron Oxide, Red", "Talc"]

    def test_unknown_licence_without_a_key_is_an_actionable_error(self, tmp_path):
        keys_dir = _keygen(tmp_path)
        code, _, err = _run([
            "generate", "--keys", str(keys_dir), "--no-png",
            *_generate_args(**{"--mfg-licence-no": "ZZ/99Z/9999/999"}),
        ])
        assert code == EXIT_ERROR
        assert "no signing key" in err and "--add" in err


# ── demo ──────────────────────────────────────────────────────────────────────


class TestDemo:
    def test_demo_writes_a_manifest_with_wire_strings(self, tmp_path):
        _, items = _keyset_with_demo(tmp_path, count=5)
        assert all(item["wire"].startswith("TM1.") for item in items)
        # The manifest is the seed the API and chain smoke test read; every item
        # needs the full data payload, not just the wire.
        assert all("data" in item and "product_id" in item for item in items)

    def test_manifest_written_even_without_png(self, tmp_path):
        keys_dir = _keygen(tmp_path)
        out_dir = tmp_path / "out"
        code, _, _ = _run([
            "demo", "--keys", str(keys_dir), "--count", "3",
            "--out", str(out_dir), "--no-png",
        ])
        assert code == EXIT_OK
        # Tying seed data to whether Pillow is installed would be absurd.
        assert (out_dir / "manifest.json").is_file()

    def test_count_beyond_the_catalogue_is_a_usage_error(self, tmp_path):
        keys_dir = _keygen(tmp_path)
        code, _, err = _run([
            "demo", "--keys", str(keys_dir), "--count", "99", "--no-png",
        ])
        assert code == EXIT_USAGE
        assert "demo items" in err


# ── verify ──────────────────────────────────────────────────────────────────


class TestVerify:
    def test_valid_code_is_offline_valid_and_exits_zero(self, tmp_path):
        keys_dir, items = _keyset_with_demo(tmp_path)
        code, out, _ = _run([
            "verify", "--keys", str(keys_dir), "--today", DEMO_TODAY,
            "--wire", items[IDX_VALID_MEDICINE]["wire"],
        ])
        assert code == EXIT_OK
        assert "SIGNATURE_VALID_OFFLINE" in out
        assert "GENUINE" not in out  # offline can never claim GENUINE

    def test_expired_code_is_a_warning(self, tmp_path):
        keys_dir, items = _keyset_with_demo(tmp_path)
        code, out, _ = _run([
            "verify", "--keys", str(keys_dir), "--today", DEMO_TODAY,
            "--wire", items[IDX_EXPIRED]["wire"],
        ])
        assert code == EXIT_VERDICT_WARN
        assert "EXPIRED" in out

    def test_tampered_payload_is_counterfeit(self, tmp_path):
        keys_dir, items = _keyset_with_demo(tmp_path)
        forged = _tamper(items[IDX_VALID_MEDICINE]["wire"], b'"Paracip 500"', b'"Paracip 501"')
        code, out, _ = _run([
            "verify", "--keys", str(keys_dir), "--today", DEMO_TODAY, "--wire", forged,
        ])
        assert code == EXIT_VERDICT_CRITICAL
        assert "COUNTERFEIT" in out

    def test_unrelated_qr_text_is_unverifiable_not_counterfeit(self, tmp_path):
        keys_dir = _keygen(tmp_path)
        code, out, _ = _run([
            "verify", "--keys", str(keys_dir), "--wire", "https://example.com/upi",
        ])
        assert code == EXIT_VERDICT_WARN
        assert "UNVERIFIABLE" in out

    def test_empty_wire_errors_rather_than_hanging_on_stdin(self, tmp_path):
        keys_dir = _keygen(tmp_path)
        # No stdin supplied: if the empty --wire fell through to reading stdin this
        # call would block forever. It must return promptly with an error instead.
        code, _, err = _run(["verify", "--keys", str(keys_dir), "--wire", ""])
        assert code == EXIT_ERROR
        assert "empty" in err

    def test_verify_reads_a_wire_string_from_stdin(self, tmp_path):
        keys_dir, items = _keyset_with_demo(tmp_path)
        code, out, _ = _run(
            ["verify", "--keys", str(keys_dir), "--today", DEMO_TODAY, "--stdin"],
            stdin=items[IDX_VALID_MEDICINE]["wire"] + "\n",
        )
        assert code == EXIT_OK
        assert "SIGNATURE_VALID_OFFLINE" in out

    def test_json_output_has_the_documented_shape(self, tmp_path):
        keys_dir, items = _keyset_with_demo(tmp_path)
        code, out, _ = _run([
            "verify", "--keys", str(keys_dir), "--today", DEMO_TODAY,
            "--wire", items[IDX_EXPIRED]["wire"], "--json",
        ])
        assert code == EXIT_VERDICT_WARN
        payload = json.loads(out)
        assert set(payload) >= {
            "valid", "verdict", "severity", "error_code", "checks", "warnings", "data"
        }
        assert payload["verdict"] == "EXPIRED"

    def test_signed_by_an_untrusted_key_is_counterfeit(self, tmp_path):
        keys_dir, items = _keyset_with_demo(tmp_path)
        # Write a key the bundle has never heard of, sign Paracip's own licence with
        # it, and confirm the bundle rejects it. This is the leaked-key attack.
        rogue = tmp_path / "rogue.key"
        rogue.write_bytes(crypto.private_key_to_pem(crypto.generate_private_key()))
        code, out, _ = _run([
            "generate", "--keys", str(keys_dir), "--no-png", "--json",
            "--key", str(rogue),
            *_generate_args(**{"--mfg-licence-no": "MH/25D/2019/187"}),
        ])
        assert code == EXIT_OK
        wire = json.loads(out)[0]["wire"]
        code, out, _ = _run([
            "verify", "--keys", str(keys_dir), "--today", DEMO_TODAY, "--wire", wire,
        ])
        assert code == EXIT_VERDICT_CRITICAL
        assert "COUNTERFEIT" in out

    def test_unknown_licence_is_unverifiable(self, tmp_path):
        keys_dir = _keygen(tmp_path)
        signer = next((keys_dir / "signers").glob("*.key"))
        # A well-formed, correctly signed code whose licence is absent from the
        # bundle: a stale bundle is likelier than forgery, so amber not red.
        code, out, _ = _run([
            "generate", "--keys", str(keys_dir), "--no-png", "--json", "--key", str(signer),
            *_generate_args(**{"--mfg-licence-no": "XX/25D/1999/000"}),
        ])
        assert code == EXIT_OK
        wire = json.loads(out)[0]["wire"]
        code, out, _ = _run(["verify", "--keys", str(keys_dir), "--wire", wire])
        assert code == EXIT_VERDICT_WARN
        assert "UNVERIFIABLE" in out


# ── verify --chain-json: the full verdict matrix, offline ──────────────────────


class TestChainEvidence:
    def _verify_with_chain(self, tmp_path, wire, evidence):
        keys_dir = tmp_path / "keys"  # created by the caller via _keyset_with_demo
        chain = tmp_path / "evidence.json"
        chain.write_text(json.dumps(evidence), encoding="utf-8")
        return _run([
            "verify", "--keys", str(keys_dir), "--today", DEMO_TODAY,
            "--wire", wire, "--chain-json", str(chain),
        ])

    def test_on_chain_and_healthy_is_genuine(self, tmp_path):
        keys_dir, items = _keyset_with_demo(tmp_path)
        code, out, _ = self._verify_with_chain(
            tmp_path, items[IDX_VALID_MEDICINE]["wire"],
            {"on_chain": True, "status": "at_pharmacy"},
        )
        assert code == EXIT_OK
        assert "GENUINE" in out

    def test_absent_from_ledger_is_counterfeit(self, tmp_path):
        keys_dir, items = _keyset_with_demo(tmp_path)
        code, out, _ = self._verify_with_chain(
            tmp_path, items[IDX_VALID_MEDICINE]["wire"], {"on_chain": False},
        )
        assert code == EXIT_VERDICT_CRITICAL
        assert "COUNTERFEIT" in out

    def test_recalled_stock(self, tmp_path):
        keys_dir, items = _keyset_with_demo(tmp_path)
        code, out, _ = self._verify_with_chain(
            tmp_path, items[IDX_VALID_MEDICINE]["wire"],
            {"on_chain": True, "status": "recalled"},
        )
        assert code == EXIT_VERDICT_CRITICAL
        assert "RECALLED" in out

    def test_clone_telemetry(self, tmp_path):
        keys_dir, items = _keyset_with_demo(tmp_path)
        code, out, _ = self._verify_with_chain(
            tmp_path, items[IDX_VALID_MEDICINE]["wire"],
            {"on_chain": True, "status": "at_pharmacy",
             "scan_count": 412, "distinct_districts": 9},
        )
        assert code == EXIT_VERDICT_CRITICAL
        assert "CLONE_SUSPECTED" in out

    def test_vaccine_cold_chain_breach(self, tmp_path):
        keys_dir, items = _keyset_with_demo(tmp_path)
        code, out, _ = self._verify_with_chain(
            tmp_path, items[IDX_VACCINE]["wire"],
            {"on_chain": True, "status": "in_transit",
             "temperature_readings": [{"temperature": 4.1}, {"temperature": 14.9}]},
        )
        assert code == EXIT_VERDICT_CRITICAL
        assert "COLD_CHAIN_BREACH" in out

    def test_temperature_on_a_non_vaccine_is_ignored(self, tmp_path):
        keys_dir, items = _keyset_with_demo(tmp_path)
        # A tablet is not cold-chain stock, so 31 C is not a breach.
        code, out, _ = self._verify_with_chain(
            tmp_path, items[IDX_VALID_MEDICINE]["wire"],
            {"on_chain": True, "status": "at_pharmacy",
             "temperature_readings": [{"temperature": 31.0}]},
        )
        assert code == EXIT_OK
        assert "GENUINE" in out

    def test_recalled_outranks_clone(self, tmp_path):
        keys_dir, items = _keyset_with_demo(tmp_path)
        code, out, _ = self._verify_with_chain(
            tmp_path, items[IDX_VALID_MEDICINE]["wire"],
            {"on_chain": True, "status": "recalled",
             "scan_count": 412, "distinct_districts": 9},
        )
        assert code == EXIT_VERDICT_CRITICAL
        assert "RECALLED" in out  # precedence: RECALLED before CLONE_SUSPECTED

    def test_chain_data_cannot_rescue_a_forged_signature(self, tmp_path):
        keys_dir, items = _keyset_with_demo(tmp_path)
        forged = _tamper(items[IDX_VALID_MEDICINE]["wire"], b'"Paracip 500"', b'"Paracip 501"')
        code, out, _ = self._verify_with_chain(
            tmp_path, forged, {"on_chain": True, "status": "at_pharmacy"},
        )
        assert code == EXIT_VERDICT_CRITICAL
        assert "COUNTERFEIT" in out

    def test_missing_on_chain_flag_is_rejected(self, tmp_path):
        keys_dir, items = _keyset_with_demo(tmp_path)
        code, _, err = self._verify_with_chain(
            tmp_path, items[IDX_VALID_MEDICINE]["wire"], {"status": "at_pharmacy"},
        )
        # Without on_chain there is no way to tell "absent from the ledger" from
        # "not asked", so guessing would be dangerous.
        assert code == EXIT_ERROR
        assert "on_chain" in err


# ── bundle trust ───────────────────────────────────────────────────────────────


class TestBundleTrust:
    def test_wrong_root_key_rejects_the_bundle(self, tmp_path):
        keys_dir, items = _keyset_with_demo(tmp_path)
        other = _keygen(tmp_path / "other")  # a different root
        code, _, err = _run([
            "verify", "--keys", str(keys_dir), "--today", DEMO_TODAY,
            "--wire", items[IDX_VALID_MEDICINE]["wire"],
            "--root-pub", str(other / "root.pub"),
        ])
        assert code == EXIT_ERROR
        assert "signature" in err.lower() or "root" in err.lower()

    def test_allow_unsigned_bundle_warns_loudly_but_works(self, tmp_path):
        keys_dir, items = _keyset_with_demo(tmp_path)
        code, out, err = _run([
            "verify", "--keys", str(keys_dir), "--today", DEMO_TODAY,
            "--wire", items[IDX_VALID_MEDICINE]["wire"], "--allow-unsigned-bundle",
        ])
        assert code == EXIT_OK
        assert "SIGNATURE_VALID_OFFLINE" in out
        assert "warning" in err.lower()  # the escape hatch must be noisy


# ── inspect ────────────────────────────────────────────────────────────────────


class TestInspect:
    def test_inspect_decodes_but_states_it_did_not_verify(self, tmp_path):
        keys_dir, items = _keyset_with_demo(tmp_path)
        code, out, _ = _run(["inspect", "--wire", items[IDX_VALID_MEDICINE]["wire"]])
        assert code == EXIT_OK
        assert "NOT CHECKED" in out  # must never be mistaken for a verification
        assert '"bn": "Paracip 500"' in out

    def test_inspect_json(self, tmp_path):
        keys_dir, items = _keyset_with_demo(tmp_path)
        code, out, _ = _run(["inspect", "--wire", items[IDX_VALID_MEDICINE]["wire"], "--json"])
        assert code == EXIT_OK
        payload = json.loads(out)
        assert payload["signature_checked"] is False
        assert payload["signature_bytes"] == 64  # raw r||s, not DER


# ── batch ──────────────────────────────────────────────────────────────────────


class TestBatch:
    def _write(self, tmp_path, obj) -> Path:
        path = tmp_path / "batch.json"
        path.write_text(json.dumps(obj), encoding="utf-8")
        return path

    def _record(self, **overrides) -> dict[str, Any]:
        record = {
            "product_id": "IBUPROFEN400MG_DARDNIL400_2026_000001",
            "generic_name": "Ibuprofen 400mg",
            "brand_name": "Dardnil 400",
            "manufacturer": "Sanjeevani Pharma Ltd, Plot 42 MIDC, Pune 411018",
            "mfg_licence_no": "MH/25D/2019/187",
            "batch_no": "SP26H0912",
            "mfg_date": "2026-05-02",
            "expiry_date": "2028-05-01",
            "quantity": "15 tablets",
            "excipients": ["Croscarmellose Sodium", "Talc"],
            "type": "medicine",
        }
        record.update(overrides)
        return record

    def test_grouped_input_and_partial_failure(self, tmp_path):
        keys_dir = _keygen(tmp_path)
        good = self._record()
        bad = self._record(product_id="CEFIXIME_BAD_2026_000002", expiry_date="not-a-date")
        path = self._write(tmp_path, {"medicines": [good, bad]})
        code, out, err = _run([
            "batch", "--keys", str(keys_dir), "--input", str(path),
            "--out", str(tmp_path / "b"), "--no-png",
        ])
        # One bad record must not discard the good one; exit 1 signals "some failed".
        assert code == EXIT_ERROR
        assert "Generated 1 of 2" in out
        assert "1 failed" in err
        manifest = json.loads((tmp_path / "b" / "manifest.json").read_text(encoding="utf-8"))
        assert manifest["count"] == 1

    def test_unknown_licence_is_collected_not_fatal(self, tmp_path):
        keys_dir = _keygen(tmp_path)
        path = self._write(tmp_path, [self._record(mfg_licence_no="KL/25D/2099/999")])
        code, _, err = _run([
            "batch", "--keys", str(keys_dir), "--input", str(path),
            "--out", str(tmp_path / "b"), "--no-png",
        ])
        assert code == EXIT_ERROR
        assert "no signing key" in err

    def test_all_records_invalid_is_a_single_clear_error(self, tmp_path):
        keys_dir = _keygen(tmp_path)
        path = self._write(tmp_path, [self._record(expiry_date="nope")])
        code, _, err = _run([
            "batch", "--keys", str(keys_dir), "--input", str(path),
            "--out", str(tmp_path / "b"), "--no-png",
        ])
        assert code == EXIT_ERROR
        assert "every one" in err


# ── top-level behaviour ────────────────────────────────────────────────────────


class TestTopLevel:
    def test_no_command_prints_help_and_exits_two(self, tmp_path):
        code, out, _ = _run([])
        assert code == EXIT_USAGE
        assert "COMMAND" in out or "usage" in out.lower()

    def test_version(self, tmp_path):
        code, out, _ = _run(["--version"])
        assert code == EXIT_OK
        assert "TrueMed" in out

    def test_selftest_passes(self, tmp_path):
        # The strongest single check: keygen, signing, tamper detection, verdict
        # precedence and the capacity gate all in one, in a temp dir of its own.
        code, out, _ = _run(["selftest"])
        assert code == EXIT_OK
        assert "failed 0" in out
