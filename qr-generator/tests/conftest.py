"""Shared fixtures.

``make_medicine`` builds a valid payload with any field overridden, so a test that
cares about one bad field does not have to restate the other ten.
"""

from __future__ import annotations

from datetime import date
from typing import Any

import pytest

from truemed_qr import crypto
from truemed_qr.payload import TYPE_MEDICINE, MedicineData

#: A fixed reference date so tests never depend on when they are run. Any test
#: about expiry passes an explicit date rather than relying on today().
TODAY = date(2026, 6, 1)

_DEFAULTS: dict[str, Any] = {
    "product_id": "PARACETAMOL500MG_PARACIP500_2026_000001",
    "generic_name": "Paracetamol 500mg",
    "brand_name": "Paracip 500",
    "manufacturer": "Sanjeevani Pharma Ltd, Plot 42 MIDC, Pune 411018",
    "mfg_licence_no": "MH/25D/2019/187",
    "batch_no": "SP26C0417",
    "mfg_date": "2026-01-15",
    "expiry_date": "2028-01-14",
    "quantity": "10 tablets",
    "excipients": ["Maize Starch", "Povidone K30", "Magnesium Stearate", "Talc"],
    "med_type": TYPE_MEDICINE,
}


def make_medicine(**overrides: Any) -> MedicineData:
    """Valid payload with overrides applied."""
    fields = dict(_DEFAULTS)
    fields.update(overrides)
    return MedicineData(**fields)


@pytest.fixture
def medicine() -> MedicineData:
    return make_medicine()


@pytest.fixture
def expired_medicine() -> MedicineData:
    return make_medicine(mfg_date="2023-01-01", expiry_date="2025-01-01")


@pytest.fixture
def vaccine() -> MedicineData:
    return make_medicine(
        product_id="BCGVACCINE_RAKSHAKBCG_2026_000004",
        generic_name="BCG Vaccine",
        brand_name="Rakshak BCG",
        med_type="vaccine",
        quantity="1 vial (20 doses)",
        excipients=["Sodium Glutamate", "Water for Injection"],
    )


@pytest.fixture
def private_key():
    return crypto.generate_private_key()


@pytest.fixture
def public_key(private_key):
    return private_key.public_key()


@pytest.fixture
def other_private_key():
    """A second, untrusted key — stands in for a counterfeiter."""
    return crypto.generate_private_key()


@pytest.fixture
def bundle(public_key) -> crypto.TrustBundle:
    return crypto.TrustBundle.single(
        _DEFAULTS["mfg_licence_no"], "Sanjeevani Pharma Ltd", public_key
    )


@pytest.fixture
def root_private_key():
    return crypto.generate_private_key()


@pytest.fixture
def wire(medicine, private_key) -> str:
    from truemed_qr.generator import build_wire

    return build_wire(medicine, private_key)
