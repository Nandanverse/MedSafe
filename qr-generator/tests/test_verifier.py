"""Verification semantics: the tests that matter most.

This file encodes what a patient is told. A wrong answer here is not a crashed
program — it is someone taking a spoiled vaccine because the screen was green, or
throwing away good medicine because the screen was red. Every verdict path and
the precedence between them is pinned.
"""

from __future__ import annotations

from datetime import date

import pytest

from truemed_qr import codec, crypto, verifier
from truemed_qr.generator import build_wire
from truemed_qr.payload import VACCINE_TEMP_MAX_C, VACCINE_TEMP_MIN_C

from .conftest import TODAY, make_medicine

V = verifier


def signed(medicine, private_key) -> str:
    return build_wire(medicine, private_key)


class TestPrecedenceTable:
    def test_worst_verdict_picks_most_severe(self):
        assert V.worst_verdict([V.VERDICT_GENUINE, V.VERDICT_EXPIRED]) == V.VERDICT_EXPIRED
        assert (
            V.worst_verdict([V.VERDICT_EXPIRED, V.VERDICT_COLD_CHAIN])
            == V.VERDICT_COLD_CHAIN
        )
        assert (
            V.worst_verdict([V.VERDICT_COLD_CHAIN, V.VERDICT_RECALLED])
            == V.VERDICT_RECALLED
        )
        assert (
            V.worst_verdict([V.VERDICT_RECALLED, V.VERDICT_COUNTERFEIT])
            == V.VERDICT_COUNTERFEIT
        )

    def test_order_of_input_is_irrelevant(self):
        pair = [V.VERDICT_EXPIRED, V.VERDICT_CLONE]
        assert V.worst_verdict(pair) == V.worst_verdict(list(reversed(pair)))

    def test_empty_is_unverifiable_not_genuine(self):
        # Fail closed. "No verdicts" must never collapse to "fine".
        assert V.worst_verdict([]) == V.VERDICT_UNVERIFIABLE

    def test_every_verdict_has_a_severity(self):
        for verdict in V._PRECEDENCE:
            assert verdict in V._SEVERITY

    def test_only_genuine_is_ok(self):
        oks = [v for v, s in V._SEVERITY.items() if s == V.SEVERITY_OK]
        assert oks == [V.VERDICT_GENUINE]

    def test_offline_success_is_warn_not_ok(self):
        # A valid signature cannot rule out a photocopied QR, so an offline pass
        # must not render as an unqualified green tick.
        assert V.severity_for(V.VERDICT_OFFLINE_OK) == V.SEVERITY_WARN

    def test_unknown_verdict_defaults_to_warn(self):
        assert V.severity_for("SOMETHING_NEW") == V.SEVERITY_WARN


class TestOfflineHappyPath:
    def test_genuine_code_passes(self, medicine, private_key, bundle):
        result = V.verify_wire(signed(medicine, private_key), bundle, today=TODAY)
        assert result.valid is True
        assert result.verdict == V.VERDICT_OFFLINE_OK
        assert result.severity == V.SEVERITY_WARN
        assert result.error is None
        assert not result.is_critical

    def test_checks_recorded_honestly(self, medicine, private_key, bundle):
        checks = V.verify_wire(signed(medicine, private_key), bundle, today=TODAY).checks
        assert checks["structure"] == "pass"
        assert checks["signature"] == "pass"
        assert checks["expiry"] == "pass"
        # Network checks were not performed, and say so rather than claiming pass.
        assert checks["on_chain"] == "skipped_offline"
        assert checks["cold_chain"] == "skipped_offline"
        assert checks["clone_telemetry"] == "skipped_offline"

    def test_offline_caveat_is_surfaced(self, medicine, private_key, bundle):
        result = V.verify_wire(signed(medicine, private_key), bundle, today=TODAY)
        assert any("Offline verification only" in w for w in result.warnings)

    def test_data_block_populated(self, medicine, private_key, bundle):
        data = V.verify_wire(signed(medicine, private_key), bundle, today=TODAY).data
        assert data is not None
        assert data["brand_name"] == "Paracip 500"
        assert data["mfg_licence_no"] == "MH/25D/2019/187"
        assert data["days_to_expiry"] > 0
        assert data["is_vaccine"] is False
        assert len(data["signing_key_fingerprint"]) == 16

    def test_near_expiry_warning(self, private_key, bundle):
        soon = make_medicine(mfg_date="2026-01-01", expiry_date="2026-06-20")
        result = V.verify_wire(signed(soon, private_key), bundle, today=TODAY)
        assert result.valid is True
        assert any("Expires in 19 days" in w for w in result.warnings)

    def test_no_near_expiry_warning_when_far_off(self, medicine, private_key, bundle):
        result = V.verify_wire(signed(medicine, private_key), bundle, today=TODAY)
        assert not any("Expires in" in w for w in result.warnings)

    def test_as_dict_shape(self, medicine, private_key, bundle):
        d = V.verify_wire(signed(medicine, private_key), bundle, today=TODAY).as_dict()
        # {valid, error, data} is the shape named in the specification; the richer
        # fields sit alongside it rather than replacing it.
        assert {"valid", "error", "data"} <= set(d)
        assert set(d) == {
            "valid",
            "verdict",
            "severity",
            "error",
            "error_code",
            "checks",
            "warnings",
            "data",
        }

    def test_summary_line_reads_sensibly(self, medicine, private_key, bundle):
        line = V.verify_wire(signed(medicine, private_key), bundle, today=TODAY).summary_line()
        assert "Paracip 500" in line
        assert V.VERDICT_OFFLINE_OK in line


class TestOfflineForgery:
    def test_tampered_payload_is_counterfeit(self, medicine, private_key, bundle):
        # The realistic attack: take a genuine code, change the expiry date,
        # reprint. The signature no longer covers the payload.
        wire = signed(medicine, private_key)
        decoded = codec.decode(wire)
        forged_payload = decoded.payload_bytes.replace(b"2028-01-14", b"2029-01-14")
        assert forged_payload != decoded.payload_bytes
        forged = codec.encode(forged_payload, decoded.signature)

        result = V.verify_wire(forged, bundle, today=TODAY)
        assert result.valid is False
        assert result.verdict == V.VERDICT_COUNTERFEIT
        assert result.severity == V.SEVERITY_CRITICAL
        assert result.checks["signature"] == "fail"
        assert result.checks["structure"] == "pass"

    def test_signature_from_untrusted_key_is_counterfeit(
        self, medicine, other_private_key, bundle
    ):
        # Counterfeiter generates their own keypair and signs a plausible payload.
        # The licence number resolves to the registered key, which does not match.
        result = V.verify_wire(signed(medicine, other_private_key), bundle, today=TODAY)
        assert result.verdict == V.VERDICT_COUNTERFEIT
        assert result.checks["signature"] == "fail"

    def test_signature_swapped_between_products(self, private_key, bundle):
        a = make_medicine(product_id="PARACETAMOL500MG_PARACIP500_2026_000001")
        b = make_medicine(product_id="PARACETAMOL500MG_PARACIP500_2026_000002")
        sig_b = codec.decode(signed(b, private_key)).signature
        spliced = codec.encode(a.canonical_json(), sig_b)
        assert V.verify_wire(spliced, bundle, today=TODAY).verdict == V.VERDICT_COUNTERFEIT

    def test_malformed_payload_in_valid_frame_is_counterfeit(self, private_key, bundle):
        # A well-formed TM1 frame whose contents are not a valid payload is a
        # fabrication attempt, not a misread: QR error correction makes silent
        # corruption that still base64-decodes vanishingly unlikely.
        junk = b'{"v":1,"id":"nope"}'
        wire = codec.encode(junk, crypto.sign(private_key, junk))
        result = V.verify_wire(wire, bundle, today=TODAY)
        assert result.verdict == V.VERDICT_COUNTERFEIT
        assert result.checks["structure"] == "fail"

    def test_zeroed_signature(self, medicine, bundle):
        wire = codec.encode(medicine.canonical_json(), b"\x00" * 64)
        assert V.verify_wire(wire, bundle, today=TODAY).verdict == V.VERDICT_COUNTERFEIT

    def test_bit_flipped_signature(self, medicine, private_key, bundle):
        decoded = codec.decode(signed(medicine, private_key))
        sig = bytearray(decoded.signature)
        sig[0] ^= 0x80
        wire = codec.encode(decoded.payload_bytes, bytes(sig))
        assert V.verify_wire(wire, bundle, today=TODAY).verdict == V.VERDICT_COUNTERFEIT


class TestOfflineUnverifiable:
    @pytest.mark.parametrize(
        "junk",
        [
            "",
            "hello world",
            "upi://pay?pa=x@y",
            "TM1.onlytwo",
            "TM1..",
            "TM1.AA!.BB",
        ],
    )
    def test_junk_is_unverifiable_not_counterfeit(self, junk, bundle):
        # Scanning a WiFi sticker must not accuse anyone of counterfeiting.
        result = V.verify_wire(junk, bundle, today=TODAY)
        assert result.verdict == V.VERDICT_UNVERIFIABLE
        assert result.valid is False
        assert result.checks["structure"] == "fail"

    def test_future_format_is_unverifiable(self, medicine, private_key, bundle):
        wire = signed(medicine, private_key).replace("TM1", "TM2", 1)
        result = V.verify_wire(wire, bundle, today=TODAY)
        assert result.verdict == V.VERDICT_UNVERIFIABLE
        assert "Update the app" in (result.error or "")

    def test_unknown_licence_is_amber_not_red(self, private_key, public_key):
        # Deliberate design choice: a stale trust bundle is far likelier than a
        # forgery, and flashing red on genuine medicine because the app has not
        # refreshed its keys is the failure mode that destroys adoption.
        med = make_medicine(mfg_licence_no="KA/25D/2022/999")
        other_bundle = crypto.TrustBundle.single(
            "MH/25D/2019/187", "Sanjeevani Pharma Ltd", public_key
        )
        result = V.verify_wire(signed(med, private_key), other_bundle, today=TODAY)
        assert result.verdict == V.VERDICT_UNVERIFIABLE
        assert result.severity == V.SEVERITY_WARN
        # Nothing was asserted about authenticity, and the report says so.
        assert result.checks["signature"] == "not_evaluated"
        assert result.valid is False

    def test_revoked_key_is_unverifiable(self, private_key, public_key, medicine):
        revoked = crypto.TrustedKey(
            mfg_licence_no="MH/25D/2019/187",
            manufacturer="Sanjeevani Pharma Ltd",
            public_key_pem=crypto.public_key_to_pem(public_key).decode(),
            fingerprint=crypto.fingerprint(public_key),
            valid_from="2020-01-01",
            valid_until="2099-12-31",
            status="revoked",
        )
        result = V.verify_wire(
            signed(medicine, private_key), crypto.TrustBundle([revoked]), today=TODAY
        )
        assert result.verdict == V.VERDICT_UNVERIFIABLE

    def test_unevaluated_checks_are_never_reported_as_fail(self, private_key, public_key):
        # Reporting "expiry: fail" when verification aborted at the signature step
        # would send somebody debugging entirely the wrong thing.
        med = make_medicine(mfg_licence_no="KA/25D/2022/999")
        other_bundle = crypto.TrustBundle.single("MH/25D/2019/187", "X", public_key)
        checks = V.verify_wire(signed(med, private_key), other_bundle, today=TODAY).checks
        assert checks["signature"] == "not_evaluated"
        assert checks["expiry"] == "not_evaluated"


class TestOfflineExpiry:
    def test_expired_is_flagged(self, expired_medicine, private_key, bundle):
        result = V.verify_wire(signed(expired_medicine, private_key), bundle, today=TODAY)
        assert result.verdict == V.VERDICT_EXPIRED
        assert result.valid is False
        assert result.checks["signature"] == "pass"
        assert result.checks["expiry"] == "fail"
        assert "expired" in (result.error or "")

    def test_expiry_message_counts_days(self, private_key, bundle):
        med = make_medicine(mfg_date="2024-01-01", expiry_date="2026-05-31")
        result = V.verify_wire(signed(med, private_key), bundle, today=TODAY)
        assert "expired 1 day ago" in (result.error or "")

    def test_expiry_day_itself_still_valid(self, private_key, bundle):
        # A pharmacist reading "EXP 06/2026" treats the last day as usable.
        med = make_medicine(mfg_date="2024-01-01", expiry_date="2026-06-01")
        result = V.verify_wire(signed(med, private_key), bundle, today=TODAY)
        assert result.verdict == V.VERDICT_OFFLINE_OK

    def test_expired_still_returns_data(self, expired_medicine, private_key, bundle):
        # The app has to show *what* expired, so the payload must survive the
        # failure path.
        result = V.verify_wire(signed(expired_medicine, private_key), bundle, today=TODAY)
        assert result.data is not None
        assert result.data["days_to_expiry"] < 0


class TestOnlineMerge:
    def _offline(self, medicine, private_key, bundle):
        return V.verify_wire(signed(medicine, private_key), bundle, today=TODAY)

    def test_fully_genuine(self, medicine, private_key, bundle):
        result = V.merge_online_evidence(
            self._offline(medicine, private_key, bundle),
            on_chain=True,
            status="at_pharmacy",
            scan_count=2,
            distinct_districts=1,
            today=TODAY,
        )
        assert result.verdict == V.VERDICT_GENUINE
        assert result.valid is True
        assert result.severity == V.SEVERITY_OK
        assert result.error is None
        assert result.checks["on_chain"] == "pass"
        assert result.checks["clone_telemetry"] == "pass"

    def test_offline_caveat_dropped_once_online(self, medicine, private_key, bundle):
        result = V.merge_online_evidence(
            self._offline(medicine, private_key, bundle),
            on_chain=True,
            status="at_pharmacy",
            today=TODAY,
        )
        assert not any("Offline verification only" in w for w in result.warnings)

    def test_valid_signature_absent_from_chain_is_counterfeit(
        self, medicine, private_key, bundle
    ):
        # This is what a leaked signing key looks like from the outside: perfect
        # cryptography, no manufacturing record.
        result = V.merge_online_evidence(
            self._offline(medicine, private_key, bundle), on_chain=False, today=TODAY
        )
        assert result.verdict == V.VERDICT_COUNTERFEIT
        assert result.checks["on_chain"] == "fail"
        assert "does not exist on the blockchain" in (result.error or "")

    def test_recalled(self, medicine, private_key, bundle):
        result = V.merge_online_evidence(
            self._offline(medicine, private_key, bundle),
            on_chain=True,
            status="recalled",
            today=TODAY,
        )
        assert result.verdict == V.VERDICT_RECALLED
        assert result.is_critical
        assert "recalled" in (result.error or "")

    def test_non_vaccine_skips_cold_chain(self, medicine, private_key, bundle):
        result = V.merge_online_evidence(
            self._offline(medicine, private_key, bundle),
            on_chain=True,
            status="at_pharmacy",
            today=TODAY,
        )
        assert result.checks["cold_chain"] == "not_applicable"

    def test_vaccine_within_range_passes(self, vaccine, private_key, bundle):
        result = V.merge_online_evidence(
            self._offline(vaccine, private_key, bundle),
            on_chain=True,
            status="at_pharmacy",
            temperature_readings=[{"temperature": t} for t in (4.1, 5.0, 3.2)],
            today=TODAY,
        )
        assert result.verdict == V.VERDICT_GENUINE
        assert result.checks["cold_chain"] == "pass"

    @pytest.mark.parametrize("temp", [VACCINE_TEMP_MIN_C, VACCINE_TEMP_MAX_C, 2.0, 8.0])
    def test_range_boundaries_are_inclusive(self, temp, vaccine, private_key, bundle):
        result = V.merge_online_evidence(
            self._offline(vaccine, private_key, bundle),
            on_chain=True,
            status="at_pharmacy",
            temperature_readings=[{"temperature": temp}],
            today=TODAY,
        )
        assert result.checks["cold_chain"] == "pass", f"{temp}°C should be in range"

    @pytest.mark.parametrize("temp", [1.9, -0.5, 8.1, 25.0, 42.0])
    def test_out_of_range_is_a_breach(self, temp, vaccine, private_key, bundle):
        result = V.merge_online_evidence(
            self._offline(vaccine, private_key, bundle),
            on_chain=True,
            status="at_pharmacy",
            temperature_readings=[{"temperature": temp}],
            today=TODAY,
        )
        assert result.verdict == V.VERDICT_COLD_CHAIN
        assert result.is_critical
        assert result.valid is False
        assert result.checks["cold_chain"] == "fail"

    def test_breach_message_quotes_the_range_seen(self, vaccine, private_key, bundle):
        result = V.merge_online_evidence(
            self._offline(vaccine, private_key, bundle),
            on_chain=True,
            status="at_pharmacy",
            temperature_readings=[{"temperature": t} for t in (4.0, 14.5, 6.0)],
            today=TODAY,
        )
        assert "4.0" in (result.error or "") and "14.5" in (result.error or "")

    def test_chaincode_flag_is_authoritative(self, vaccine, private_key, bundle):
        # The chaincode's sticky breach flag remembers excursions that fell outside
        # the window of readings the app happens to have fetched. It wins.
        result = V.merge_online_evidence(
            self._offline(vaccine, private_key, bundle),
            on_chain=True,
            status="at_pharmacy",
            temperature_readings=[{"temperature": 4.0}],
            cold_chain_breached=True,
            today=TODAY,
        )
        assert result.verdict == V.VERDICT_COLD_CHAIN

    def test_no_readings_is_unconfirmed_not_pass(self, vaccine, private_key, bundle):
        result = V.merge_online_evidence(
            self._offline(vaccine, private_key, bundle),
            on_chain=True,
            status="at_pharmacy",
            temperature_readings=[],
            today=TODAY,
        )
        assert result.checks["cold_chain"] == "skipped_offline"
        assert any("unconfirmed" in w for w in result.warnings)

    def test_malformed_readings_ignored_not_crashing(self, vaccine, private_key, bundle):
        # Sensor data comes from the field. A missing key must not take down
        # verification for a patient standing at a counter.
        result = V.merge_online_evidence(
            self._offline(vaccine, private_key, bundle),
            on_chain=True,
            status="at_pharmacy",
            temperature_readings=[{"temp": 4.0}, {"temperature": 5.0}, "garbage"],
            today=TODAY,
        )
        assert result.checks["cold_chain"] == "pass"

    def test_clone_by_scan_count(self, medicine, private_key, bundle):
        result = V.merge_online_evidence(
            self._offline(medicine, private_key, bundle),
            on_chain=True,
            status="at_pharmacy",
            scan_count=V.CLONE_SCAN_THRESHOLD + 1,
            distinct_districts=1,
            today=TODAY,
        )
        assert result.verdict == V.VERDICT_CLONE
        assert result.checks["clone_telemetry"] == "fail"

    def test_clone_by_district_spread(self, medicine, private_key, bundle):
        # One physical strip cannot be in five districts at once.
        result = V.merge_online_evidence(
            self._offline(medicine, private_key, bundle),
            on_chain=True,
            status="at_pharmacy",
            scan_count=6,
            distinct_districts=V.CLONE_DISTRICT_THRESHOLD + 1,
            today=TODAY,
        )
        assert result.verdict == V.VERDICT_CLONE

    def test_threshold_itself_is_not_a_clone(self, medicine, private_key, bundle):
        result = V.merge_online_evidence(
            self._offline(medicine, private_key, bundle),
            on_chain=True,
            status="at_pharmacy",
            scan_count=V.CLONE_SCAN_THRESHOLD,
            distinct_districts=V.CLONE_DISTRICT_THRESHOLD,
            today=TODAY,
        )
        assert result.verdict == V.VERDICT_GENUINE

    def test_telemetry_echoed_into_data(self, medicine, private_key, bundle):
        result = V.merge_online_evidence(
            self._offline(medicine, private_key, bundle),
            on_chain=True,
            status="in_transit",
            scan_count=3,
            distinct_districts=2,
            today=TODAY,
        )
        assert result.data is not None
        assert result.data["status"] == "in_transit"
        assert result.data["scan_count"] == 3
        assert result.data["distinct_districts"] == 2


class TestMergePrecedence:
    def _offline(self, medicine, private_key, bundle):
        return V.verify_wire(signed(medicine, private_key), bundle, today=TODAY)

    def test_recall_beats_expiry(self, expired_medicine, private_key, bundle):
        result = V.merge_online_evidence(
            self._offline(expired_medicine, private_key, bundle),
            on_chain=True,
            status="recalled",
            today=TODAY,
        )
        assert result.verdict == V.VERDICT_RECALLED
        # Both problems are still reported to the user, even though one verdict wins.
        assert "expired" in (result.error or "")
        assert "recalled" in (result.error or "")

    def test_clone_beats_cold_chain(self, vaccine, private_key, bundle):
        result = V.merge_online_evidence(
            self._offline(vaccine, private_key, bundle),
            on_chain=True,
            status="at_pharmacy",
            temperature_readings=[{"temperature": 19.0}],
            scan_count=400,
            distinct_districts=14,
            today=TODAY,
        )
        assert result.verdict == V.VERDICT_CLONE
        assert "cold chain breach" in (result.error or "")

    def test_cold_chain_beats_expiry(self, private_key, bundle):
        near = make_medicine(
            product_id="BCGVACCINE_RAKSHAKBCG_2026_000004",
            med_type="vaccine",
            mfg_date="2024-01-01",
            expiry_date="2026-05-01",
        )
        result = V.merge_online_evidence(
            self._offline(near, private_key, bundle),
            on_chain=True,
            status="at_pharmacy",
            temperature_readings=[{"temperature": 15.0}],
            today=TODAY,
        )
        assert result.verdict == V.VERDICT_COLD_CHAIN

    def test_counterfeit_cannot_be_rescued_by_chain_data(
        self, medicine, other_private_key, bundle
    ):
        # No amount of good chain data makes a forged signature acceptable.
        offline = V.verify_wire(signed(medicine, other_private_key), bundle, today=TODAY)
        result = V.merge_online_evidence(
            offline,
            on_chain=True,
            status="at_pharmacy",
            scan_count=1,
            distinct_districts=1,
            today=TODAY,
        )
        assert result.verdict == V.VERDICT_COUNTERFEIT

    def test_unverifiable_is_not_upgraded(self, bundle):
        offline = V.verify_wire("garbage", bundle, today=TODAY)
        result = V.merge_online_evidence(offline, on_chain=True, today=TODAY)
        assert result.verdict == V.VERDICT_UNVERIFIABLE

    def test_error_code_accompanies_every_bad_verdict(self, expired_medicine, private_key, bundle):
        result = V.merge_online_evidence(
            self._offline(expired_medicine, private_key, bundle),
            on_chain=True,
            status="recalled",
            today=TODAY,
        )
        assert result.error_code == "RECALLED"

    def test_genuine_has_no_error_code(self, medicine, private_key, bundle):
        result = V.merge_online_evidence(
            self._offline(medicine, private_key, bundle),
            on_chain=True,
            status="at_pharmacy",
            today=TODAY,
        )
        assert result.error_code is None


class TestImageDecoding:
    def test_missing_file(self, bundle):
        from truemed_qr.errors import TrueMedError

        with pytest.raises(TrueMedError, match="no such image file"):
            V.decode_qr_image("/nonexistent/path/qr.png")

    def test_round_trip_through_png(self, medicine, private_key, bundle, tmp_path):
        # Needs both an encoder and a decoder; skipped rather than failed where
        # they are unavailable, because neither is required for verification.
        pytest.importorskip("qrcode")
        pytest.importorskip("cv2")
        from truemed_qr.generator import generate

        result = generate(medicine, private_key, tmp_path, with_caption=False)
        assert result.png_path is not None
        verified = V.verify_image(result.png_path, bundle, today=TODAY)
        assert verified.verdict == V.VERDICT_OFFLINE_OK
        assert verified.data is not None
        assert verified.data["product_id"] == medicine.product_id
