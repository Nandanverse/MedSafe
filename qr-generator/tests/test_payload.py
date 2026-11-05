"""Payload validation, canonicalisation, and product ID tests."""

from __future__ import annotations

import json
from datetime import date

import pytest

from truemed_qr.errors import PayloadError
from truemed_qr.payload import (
    CONTRACT_VERSION,
    TYPE_MEDICINE,
    TYPE_VACCINE,
    MedicineData,
    make_product_id,
    parse_iso_date,
)

from .conftest import make_medicine


class TestMakeProductID:
    def test_documented_example(self):
        assert (
            make_product_id("Paracetamol 500mg", "Paracip 500", 2026, 1)
            == "PARACETAMOL500MG_PARACIP500_2026_000001"
        )

    def test_serial_is_zero_padded_to_six(self):
        assert make_product_id("A", "B", 2026, 42).endswith("_000042")

    def test_punctuation_is_removed_not_replaced(self):
        # Replacing with underscores would inject a fifth segment and make the
        # four-part structure unparseable.
        pid = make_product_id("Co-trimoxazole 80/400", "Septran-DS", 2026, 7)
        assert pid == "COTRIMOXAZOLE80400_SEPTRANDS_2026_000007"
        assert pid.count("_") == 3

    @pytest.mark.parametrize("serial", [0, -1, 1_000_000])
    def test_serial_out_of_range(self, serial):
        with pytest.raises(PayloadError, match="serial"):
            make_product_id("A", "B", 2026, serial)

    @pytest.mark.parametrize("year", [99, 3000, "2026"])
    def test_bad_year(self, year):
        with pytest.raises(PayloadError, match="year"):
            make_product_id("A", "B", year, 1)

    def test_name_with_no_alphanumerics(self):
        with pytest.raises(PayloadError, match="alphanumeric"):
            make_product_id("!!!", "Brand", 2026, 1)

    def test_overlong_id_rejected(self):
        with pytest.raises(PayloadError, match="over the"):
            make_product_id("X" * 60, "Y" * 60, 2026, 1)


class TestParseISODate:
    def test_valid(self):
        assert parse_iso_date("2026-03-15", "d") == date(2026, 3, 15)

    def test_leap_day_accepted(self):
        assert parse_iso_date("2028-02-29", "d") == date(2028, 2, 29)

    @pytest.mark.parametrize(
        "bad",
        [
            "20260315",      # compact form: accepted by fromisoformat on 3.11+, not by us
            "2026-3-15",     # unpadded
            "15-03-2026",    # wrong order
            "2026-02-30",    # not a real date
            "2026-13-01",    # month out of range
            "",
            None,
            20260315,
        ],
    )
    def test_rejected(self, bad):
        with pytest.raises(PayloadError):
            parse_iso_date(bad, "d")


class TestMedicineDataValidation:
    def test_valid_payload_constructs(self, medicine):
        assert medicine.product_id.startswith("PARACETAMOL500MG_")
        assert medicine.contract_version == CONTRACT_VERSION

    def test_frozen(self, medicine):
        # Immutability closes the window between signing and encoding in which a
        # mutation bug could hide.
        with pytest.raises(Exception):
            medicine.brand_name = "Other"  # type: ignore[misc]

    def test_whitespace_stripped(self):
        med = make_medicine(brand_name="  Paracip 500  ")
        assert med.brand_name == "Paracip 500"

    @pytest.mark.parametrize(
        "field_name", ["generic_name", "brand_name", "manufacturer", "batch_no", "quantity"]
    )
    def test_empty_required_field(self, field_name):
        with pytest.raises(PayloadError, match="must not be empty"):
            make_medicine(**{field_name: "   "})

    @pytest.mark.parametrize("bad", ["Para\ncip", "Para\x00cip", "Para\tcip"])
    def test_control_characters_rejected(self, bad):
        # Newlines and NULs in signed fields are how payload-smuggling and
        # log-injection start; no real excipient or brand contains one.
        with pytest.raises(PayloadError, match="control character"):
            make_medicine(brand_name=bad)

    def test_overlong_field_rejected(self):
        with pytest.raises(PayloadError, match="exceeding"):
            make_medicine(manufacturer="X" * 200)

    def test_expiry_must_follow_manufacture(self):
        with pytest.raises(PayloadError, match="must be after"):
            make_medicine(mfg_date="2026-06-01", expiry_date="2026-05-01")

    def test_expiry_equal_to_manufacture_rejected(self):
        with pytest.raises(PayloadError, match="must be after"):
            make_medicine(mfg_date="2026-06-01", expiry_date="2026-06-01")

    def test_bad_product_id_format(self):
        with pytest.raises(PayloadError, match="does not match"):
            make_medicine(product_id="not-a-valid-id")

    def test_product_id_needs_six_digit_serial(self):
        with pytest.raises(PayloadError, match="does not match"):
            make_medicine(product_id="PARA_BRAND_2026_1")

    def test_type_must_be_known(self):
        with pytest.raises(PayloadError, match="type must be"):
            make_medicine(med_type="syrup")

    def test_contract_version_pinned(self):
        with pytest.raises(PayloadError, match="contract_version"):
            make_medicine(contract_version=2)

    def test_excipients_must_be_list(self):
        # A comma-joined string is genuinely unparseable, because excipient names
        # can themselves contain commas.
        with pytest.raises(PayloadError, match="JSON array"):
            make_medicine(excipients="Starch, Talc")

    def test_empty_excipients_allowed(self):
        assert make_medicine(excipients=[]).excipients == []

    def test_too_many_excipients(self):
        with pytest.raises(PayloadError, match="over the"):
            make_medicine(excipients=[f"E{i}" for i in range(20)])

    def test_excipient_entries_validated(self):
        with pytest.raises(PayloadError):
            make_medicine(excipients=["Starch", ""])

    def test_excipient_must_be_string(self):
        with pytest.raises(PayloadError, match="must be a string"):
            make_medicine(excipients=["Starch", 42])


class TestExpiry:
    def test_not_expired_well_before(self, medicine):
        assert not medicine.is_expired(date(2026, 1, 1))

    def test_expiry_day_itself_is_still_valid(self):
        # A pharmacist reading "EXP 02/2028" treats that day as usable.
        med = make_medicine(mfg_date="2026-01-01", expiry_date="2028-02-29")
        assert not med.is_expired(date(2028, 2, 29))
        assert med.days_to_expiry(date(2028, 2, 29)) == 0

    def test_day_after_expiry_is_expired(self):
        med = make_medicine(mfg_date="2026-01-01", expiry_date="2028-02-29")
        assert med.is_expired(date(2028, 3, 1))
        assert med.days_to_expiry(date(2028, 3, 1)) == -1

    def test_days_to_expiry_counts_forward(self):
        med = make_medicine(mfg_date="2026-01-01", expiry_date="2026-01-31")
        assert med.days_to_expiry(date(2026, 1, 1)) == 30


class TestCanonicalJSON:
    def test_is_byte_exactly_canonical(self, medicine):
        # Substring searching for ", " cannot work here: the manufacturer address
        # legitimately contains ", ". The only sound check is structural — parse
        # it, re-serialise it canonically, and require identical bytes.
        blob = medicine.canonical_json()
        reserialised = json.dumps(
            json.loads(blob.decode("utf-8")),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        assert blob == reserialised

    def test_keys_sorted(self, medicine):
        parsed = json.loads(medicine.canonical_json().decode("utf-8"))
        assert list(parsed.keys()) == sorted(parsed.keys())

    def test_separators_are_exact(self, medicine):
        blob = medicine.canonical_json()
        # No space after the colon, no space after the comma, between elements.
        assert b'"v":1' in blob
        assert b'"tp":"M"' in blob
        assert b'"ed":"2028-01-14","ex":[' in blob

    def test_deterministic(self, medicine):
        assert medicine.canonical_json() == medicine.canonical_json()

    def test_identical_payloads_serialise_identically(self):
        a = make_medicine()
        b = make_medicine()
        assert a.canonical_json() == b.canonical_json()

    def test_excipient_order_is_significant(self):
        # Order is part of the signed data, so reordering must change the bytes.
        a = make_medicine(excipients=["Starch", "Talc"])
        b = make_medicine(excipients=["Talc", "Starch"])
        assert a.canonical_json() != b.canonical_json()

    def test_no_trailing_newline(self, medicine):
        assert not medicine.canonical_json().endswith(b"\n")

    def test_unicode_preserved_not_escaped(self):
        # ensure_ascii=False keeps Devanagari as UTF-8 rather than \uXXXX, which
        # matters for Hindi manufacturer names in Phase 2.
        med = make_medicine(manufacturer="संजीवनी फार्मा, Pune 411018")
        blob = med.canonical_json()
        assert "संजीवनी".encode("utf-8") in blob
        assert b"\\u" not in blob


class TestRoundTrip:
    def test_wire_dict_round_trip(self, medicine):
        assert MedicineData.from_wire_dict(medicine.to_wire_dict()) == medicine

    def test_canonical_json_round_trip(self, medicine):
        assert MedicineData.from_canonical_json(medicine.canonical_json()) == medicine

    def test_full_dict_round_trip(self, medicine):
        assert MedicineData.from_dict(medicine.to_dict()) == medicine

    def test_wire_type_is_single_char(self, medicine):
        assert medicine.to_wire_dict()["tp"] == "M"

    def test_vaccine_wire_type(self):
        assert make_medicine(med_type=TYPE_VACCINE).to_wire_dict()["tp"] == "V"

    def test_full_dict_uses_long_names(self, medicine):
        d = medicine.to_dict()
        assert d["type"] == TYPE_MEDICINE
        assert "mfg_licence_no" in d
        assert "ml" not in d

    @pytest.mark.parametrize(
        "key", ["v", "id", "gn", "bn", "mf", "ml", "bt", "md", "ed", "qt", "ex", "tp"]
    )
    def test_missing_wire_key_rejected(self, medicine, key):
        raw = medicine.to_wire_dict()
        del raw[key]
        with pytest.raises(PayloadError, match="missing required keys"):
            MedicineData.from_wire_dict(raw)

    def test_bad_utf8_rejected(self):
        with pytest.raises(PayloadError, match="UTF-8"):
            MedicineData.from_canonical_json(b"\xff\xfe not utf8")

    def test_bad_json_rejected(self):
        with pytest.raises(PayloadError, match="not valid JSON"):
            MedicineData.from_canonical_json(b"{not json")

    def test_json_array_rejected(self):
        with pytest.raises(PayloadError, match="must be a JSON object"):
            MedicineData.from_canonical_json(b"[1,2,3]")

    def test_bool_version_rejected(self):
        # In Python, True == 1 and isinstance(True, int); without an explicit
        # bool guard a payload with "v": true would sail through.
        raw = make_medicine().to_wire_dict()
        raw["v"] = True
        with pytest.raises(PayloadError, match="must be an integer"):
            MedicineData.from_wire_dict(raw)


class TestVaccineProperties:
    def test_is_vaccine_flag(self):
        assert make_medicine(med_type=TYPE_VACCINE).is_vaccine
        assert not make_medicine(med_type=TYPE_MEDICINE).is_vaccine

    def test_date_objects(self, medicine):
        assert medicine.mfg_date_obj == date.fromisoformat(medicine.mfg_date)
        assert medicine.expiry_date_obj == date.fromisoformat(medicine.expiry_date)
