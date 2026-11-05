"""Generator tests.

Rendering tests need ``qrcode`` and Pillow and are skipped where those are
absent — deliberately, because none of the security-critical logic depends on an
image library, and the suite must stay runnable in a minimal environment.

The signing tests below have no such dependency and always run.
"""

from __future__ import annotations

import pytest

from truemed_qr import codec, crypto, generator
from truemed_qr.errors import CapacityError, PayloadError
from truemed_qr.payload import MAX_PAYLOAD_BYTES, QR_MAX_BYTES_ECC_H

from .conftest import make_medicine


class TestBuildWire:
    def test_signs_the_bytes_it_transmits(self, medicine, private_key):
        # The single most important invariant in the generator. Signing one
        # serialisation and shipping another produces a system where every
        # signature fails in the field but passes in a unit test that happens to
        # re-serialise the same way.
        wire = generator.build_wire(medicine, private_key)
        decoded = codec.decode(wire)
        assert decoded.payload_bytes == medicine.canonical_json()
        assert crypto.verify(
            private_key.public_key(), decoded.payload_bytes, decoded.signature
        )

    def test_output_is_scannable_ascii(self, medicine, private_key):
        wire = generator.build_wire(medicine, private_key)
        assert wire.startswith("TM1.")
        wire.encode("ascii")

    def test_fits_well_inside_the_capacity_ceiling(self, medicine, private_key):
        # The argument for choosing ECDSA P-256 over RSA-2048 rests on this number.
        # An RSA-2048 signature alone is 256 bytes (342 base64) against a 1273-byte
        # ceiling at ECC level H; P-256 costs 64 bytes (86 base64).
        size = len(generator.build_wire(medicine, private_key).encode("ascii"))
        assert size < QR_MAX_BYTES_ECC_H
        assert size < QR_MAX_BYTES_ECC_H // 2, (
            f"{size} bytes leaves little headroom for longer manufacturer addresses"
        )

    def test_each_call_differs_but_both_verify(self, medicine, private_key):
        # ECDSA nonce randomness means two codes for the same unit are not
        # byte-identical. That is fine, and worth pinning so nobody treats the
        # wire string as a stable identifier — product_id is the identifier.
        a = generator.build_wire(medicine, private_key)
        b = generator.build_wire(medicine, private_key)
        assert a != b
        for wire in (a, b):
            d = codec.decode(wire)
            assert crypto.verify(private_key.public_key(), d.payload_bytes, d.signature)

    def test_realistic_worst_case_fits(self, private_key):
        # A verbose but entirely plausible Indian pharma record: long registered
        # address, eight excipients with real chemical names.
        realistic = make_medicine(
            generic_name="Amoxicillin 500mg + Potassium Clavulanate 125mg",
            brand_name="Amoxinova-CV 625 Duo",
            manufacturer=(
                "Sanjeevani Pharmaceuticals Ltd, Plot 42-B MIDC Industrial Area, "
                "Chakan, Pune 411018"
            ),
            excipients=[
                "Microcrystalline Cellulose",
                "Sodium Starch Glycolate",
                "Colloidal Silicon Dioxide",
                "Magnesium Stearate",
                "Hypromellose",
                "Titanium Dioxide",
                "Polyethylene Glycol 6000",
                "Purified Talc",
            ],
        )
        size = len(generator.build_wire(realistic, private_key).encode("ascii"))
        assert size < QR_MAX_BYTES_ECC_H, f"{size} bytes exceeds the QR ceiling"

    def test_unprintable_payload_is_refused_at_construction(self):
        # Every field at its documented character maximum encodes to 1462 bytes,
        # 189 over the QR ceiling. That must fail while someone is entering data,
        # with a message naming the fix — not halfway through a print run.
        with pytest.raises(PayloadError, match="over the .* budget that fits a QR"):
            make_medicine(
                product_id="A" * 40 + "_" + "B" * 24 + "_2026_000001",
                generic_name="G" * 64,
                brand_name="B" * 48,
                manufacturer="M" * 120,
                mfg_licence_no="L" * 32,
                batch_no="N" * 24,
                quantity="Q" * 32,
                excipients=["E" * 40] * 12,
            )

    def test_budget_is_derived_not_guessed(self):
        # If someone changes the ceiling or the signature size, the budget must
        # follow rather than silently drifting out of agreement with it.
        overhead = len("TM1") + 2 + 86  # prefix + two separators + b64(64 bytes)
        assert MAX_PAYLOAD_BYTES == ((QR_MAX_BYTES_ECC_H - overhead) // 4) * 3
        # And a payload at exactly the budget must still produce a printable wire.
        assert (MAX_PAYLOAD_BYTES + 2) // 3 * 4 + overhead <= QR_MAX_BYTES_ECC_H

    def test_devanagari_costs_three_bytes_per_character(self, private_key):
        # The reason the budget is counted in bytes. Phase 2 puts Hindi in these
        # fields, and a character-based limit would let an unprintable payload
        # through.
        latin = make_medicine(manufacturer="S" * 60)
        hindi = make_medicine(manufacturer="स" * 60)
        assert len(hindi.canonical_json()) - len(latin.canonical_json()) == 120

    def test_unicode_payload_fits(self, private_key):
        med = make_medicine(manufacturer="संजीवनी फार्मास्युटिकल्स लिमिटेड, पुणे")
        size = len(generator.build_wire(med, private_key).encode("ascii"))
        assert size < QR_MAX_BYTES_ECC_H


class TestGenerateWithoutFiles:
    def test_no_out_dir_means_no_png(self, medicine, private_key):
        # The mode a real production line uses: codes stream to a label printer or
        # an API, never to disk.
        result = generator.generate(medicine, private_key, None)
        assert result.png_path is None
        assert result.qr_version is None
        assert result.product_id == medicine.product_id
        assert result.wire_bytes == len(result.wire.encode("ascii"))

    def test_as_dict_is_json_safe(self, medicine, private_key):
        import json

        d = generator.generate(medicine, private_key, None).as_dict()
        json.dumps(d)  # raises TypeError if a Path leaked through
        assert d["png_path"] is None


class TestCapacityGuard:
    def test_oversized_payload_raises(self, medicine, private_key, monkeypatch):
        # The per-field limits make an over-capacity payload unreachable in
        # practice, so the ceiling is lowered to prove the guard actually fires
        # rather than being dead code nobody has ever executed.
        monkeypatch.setattr(generator, "QR_MAX_BYTES_ECC_H", 100)
        with pytest.raises(CapacityError, match="over the 100-byte ceiling"):
            generator.build_wire(medicine, private_key)


class TestRendering:
    def test_png_written(self, medicine, private_key, tmp_path):
        pytest.importorskip("qrcode")
        result = generator.generate(medicine, private_key, tmp_path)
        assert result.png_path is not None
        assert result.png_path.is_file()
        assert result.png_path.name == f"{medicine.product_id}.png"
        assert result.png_path.read_bytes()[:8] == b"\x89PNG\r\n\x1a\n"

    def test_geometry_reported(self, medicine, private_key, tmp_path):
        pytest.importorskip("qrcode")
        result = generator.generate(medicine, private_key, tmp_path, with_caption=False)
        assert result.qr_version is not None
        assert result.modules_per_side == result.qr_version * 4 + 17

    def test_stays_under_recommended_version(self, medicine, private_key, tmp_path):
        pytest.importorskip("qrcode")
        result = generator.generate(medicine, private_key, tmp_path, with_caption=False)
        assert result.qr_version is not None
        assert result.qr_version <= generator.MAX_RECOMMENDED_VERSION, (
            "a typical payload should fit a QR that scans on a low-end phone"
        )
        assert result.warnings == []

    def test_caption_makes_the_image_taller(self, medicine, private_key, tmp_path):
        pytest.importorskip("qrcode")
        pytest.importorskip("PIL")
        from PIL import Image

        plain = generator.generate(
            medicine, private_key, tmp_path / "plain", with_caption=False
        )
        captioned = generator.generate(
            medicine, private_key, tmp_path / "cap", with_caption=True
        )
        assert plain.png_path and captioned.png_path
        with Image.open(plain.png_path) as a, Image.open(captioned.png_path) as b:
            assert b.height > a.height
            assert b.width == a.width

    def test_nested_output_directory_created(self, medicine, private_key, tmp_path):
        pytest.importorskip("qrcode")
        target = tmp_path / "a" / "b" / "c"
        result = generator.generate(medicine, private_key, target)
        assert result.png_path is not None and result.png_path.is_file()

    def test_border_below_spec_refused(self, medicine, private_key, tmp_path):
        # Below 4 modules of quiet zone the code violates the QR specification and
        # becomes measurably less reliable — a common cause of "why won't this scan".
        pytest.importorskip("qrcode")
        wire = generator.build_wire(medicine, private_key)
        with pytest.raises(ValueError, match="quiet-zone"):
            generator.render_png(wire, tmp_path / "x.png", border=2)

    def test_scale_must_be_positive(self, medicine, private_key, tmp_path):
        pytest.importorskip("qrcode")
        wire = generator.build_wire(medicine, private_key)
        with pytest.raises(ValueError, match="scale must be"):
            generator.render_png(wire, tmp_path / "x.png", scale=0)

    def test_scale_changes_pixel_size(self, medicine, private_key, tmp_path):
        pytest.importorskip("qrcode")
        pytest.importorskip("PIL")
        from PIL import Image

        wire = generator.build_wire(medicine, private_key)
        small = generator.render_png(wire, tmp_path / "s.png", scale=4)
        large = generator.render_png(wire, tmp_path / "l.png", scale=12)
        assert small.png_path and large.png_path
        with Image.open(small.png_path) as a, Image.open(large.png_path) as b:
            assert b.width == a.width * 3


class TestDemoData:
    def test_catalogue_size_and_default_count(self):
        from truemed_qr.demo_data import CATALOGUE, demo_medicines

        assert len(CATALOGUE) == 8
        # The default is a demo-sized slice, not the whole catalogue.
        assert len(demo_medicines()) == 5

    def test_asking_for_more_than_exists_raises(self):
        # Silently returning fewer items than asked for would make a demo script
        # quietly generate 8 codes when the operator asked for 99 and thought it
        # had worked.
        from truemed_qr.demo_data import CATALOGUE, demo_medicines

        with pytest.raises(ValueError, match="only 8 demo items"):
            demo_medicines(count=len(CATALOGUE) + 1)

    def test_all_catalogue_items_are_valid_and_signable(self, private_key):
        from truemed_qr.demo_data import CATALOGUE, demo_medicines

        for med in demo_medicines(count=len(CATALOGUE)):
            wire = generator.build_wire(med, private_key)
            d = codec.decode(wire)
            assert crypto.verify(private_key.public_key(), d.payload_bytes, d.signature)

    def test_dates_are_relative_so_the_set_never_goes_stale(self):
        from datetime import date

        from truemed_qr.demo_data import demo_medicines

        # Generated against two different "todays", the expiry dates must move.
        a = demo_medicines(today=date(2026, 1, 1))
        b = demo_medicines(today=date(2027, 1, 1))
        assert [m.expiry_date for m in a] != [m.expiry_date for m in b]

    def test_catalogue_includes_an_expired_item(self):
        from datetime import date

        from truemed_qr.demo_data import CATALOGUE, demo_medicines

        today = date(2026, 6, 1)
        meds = demo_medicines(count=len(CATALOGUE), today=today)
        assert any(m.is_expired(today) for m in meds), (
            "the demo set must contain an expired item so the EXPIRED verdict is "
            "demonstrable without waiting two years"
        )

    def test_catalogue_includes_a_near_expiry_item(self):
        from datetime import date

        from truemed_qr.demo_data import CATALOGUE, demo_medicines

        today = date(2026, 6, 1)
        meds = demo_medicines(count=len(CATALOGUE), today=today)
        assert any(0 <= m.days_to_expiry(today) <= 30 for m in meds)

    def test_catalogue_includes_a_vaccine(self):
        from truemed_qr.demo_data import demo_medicines

        assert any(m.is_vaccine for m in demo_medicines())

    def test_product_ids_unique(self):
        from truemed_qr.demo_data import CATALOGUE, demo_medicines

        ids = [m.product_id for m in demo_medicines(count=len(CATALOGUE))]
        assert len(set(ids)) == len(ids)

    def test_every_item_fits_a_scannable_qr(self, private_key):
        from truemed_qr.demo_data import CATALOGUE, demo_medicines

        for med in demo_medicines(count=len(CATALOGUE)):
            size = len(generator.build_wire(med, private_key).encode("ascii"))
            assert size < QR_MAX_BYTES_ECC_H // 2, (
                f"{med.brand_name} encodes to {size} bytes — demo data should sit "
                "comfortably inside the ceiling"
            )
