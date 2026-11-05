"""Sample data for demos and tests.

**Real generic names, fictional brands and manufacturers.** The molecules
(Paracetamol, Amoxicillin, Metformin, BCG, Measles-Rubella) are real so the demo
is clinically credible to a pharmacist or CDSCO officer. Every brand name,
company name, address, and manufacturing licence number is invented.

That is a deliberate policy, not caution for its own sake. This project gets
presented to regulators and pharmaceutical companies, and attaching fabricated
counterfeit-detection records or cold-chain failures to a real company's
trademark in that room would be indefensible. Fictional brands cost the
demonstration nothing.

Licence numbers follow the shape CDSCO actually uses — ``{STATE}/{FORM}/{YEAR}/
{SERIAL}``, where form 25D covers allopathic manufacture and 28B covers
biologicals including vaccines — so the format is realistic even though the
numbers are not real.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, timedelta
from typing import Final

from .payload import TYPE_MEDICINE, TYPE_VACCINE, MedicineData, make_product_id


@dataclass(frozen=True)
class Manufacturer:
    name: str
    address: str
    licence_no: str

    @property
    def full(self) -> str:
        """``manufacturer`` field: name and address, comma-separated."""
        return f"{self.name}, {self.address}"


MANUFACTURERS: Final[tuple[Manufacturer, ...]] = (
    Manufacturer(
        name="Sanjeevani Pharma Ltd",
        address="Plot 42 MIDC, Pune 411018",
        licence_no="MH/25D/2019/187",
    ),
    Manufacturer(
        name="Aarogya Labs Ltd",
        address="Sector 9 GIDC, Ahmedabad 382445",
        licence_no="GJ/25D/2018/301",
    ),
    Manufacturer(
        name="Bharat Biologics Pvt Ltd",
        address="Genome Valley, Hyderabad 500078",
        licence_no="TG/28B/2020/044",
    ),
    Manufacturer(
        name="Jeevan Vaccines Ltd",
        address="SIPCOT Industrial Park, Chennai 602105",
        licence_no="TN/28B/2021/156",
    ),
)


@dataclass(frozen=True)
class CatalogueItem:
    generic_name: str
    brand_name: str
    med_type: str
    quantity: str
    excipients: tuple[str, ...]
    manufacturer_index: int
    #: Days from today until expiry. Negative means already expired.
    expiry_offset_days: int
    #: Days from today back to manufacture.
    mfg_offset_days: int
    note: str = ""


#: Ordered so that `demo_medicines(n)` gives useful coverage at every n:
#: n=1 a plain valid medicine, n=3 adds an expired one, n=5 adds both vaccine
#: cases including one near expiry.
CATALOGUE: Final[tuple[CatalogueItem, ...]] = (
    CatalogueItem(
        generic_name="Paracetamol 500mg",
        brand_name="Paracip 500",
        med_type=TYPE_MEDICINE,
        quantity="10 tablets",
        excipients=("Maize Starch", "Povidone K30", "Magnesium Stearate", "Talc"),
        manufacturer_index=0,
        expiry_offset_days=545,
        mfg_offset_days=160,
        note="valid antipyretic, the happy path",
    ),
    CatalogueItem(
        generic_name="Amoxicillin 500mg",
        brand_name="Amoxinova 500",
        med_type=TYPE_MEDICINE,
        quantity="10 capsules",
        excipients=("Sodium Starch Glycolate", "Colloidal Silicon Dioxide", "Gelatin"),
        manufacturer_index=1,
        expiry_offset_days=430,
        mfg_offset_days=95,
        note="valid antibiotic; antibiotics are among the most-counterfeited classes",
    ),
    CatalogueItem(
        generic_name="Metformin 500mg",
        brand_name="Glucomet 500",
        med_type=TYPE_MEDICINE,
        quantity="15 tablets",
        excipients=("Hypromellose", "Povidone K90", "Magnesium Stearate"),
        manufacturer_index=1,
        expiry_offset_days=-45,
        mfg_offset_days=760,
        note="EXPIRED 45 days ago — demonstrates the amber verdict",
    ),
    CatalogueItem(
        generic_name="BCG Vaccine",
        brand_name="Rakshak BCG",
        med_type=TYPE_VACCINE,
        quantity="1 vial (20 doses)",
        excipients=("Sodium Glutamate", "Water for Injection"),
        manufacturer_index=2,
        expiry_offset_days=290,
        mfg_offset_days=75,
        note="valid vaccine — cold-chain checks apply to this one",
    ),
    CatalogueItem(
        generic_name="Measles-Rubella Vaccine",
        brand_name="Suraksha MR",
        med_type=TYPE_VACCINE,
        quantity="1 vial (5 doses)",
        excipients=("Sorbitol", "Hydrolysed Gelatin", "Water for Injection"),
        manufacturer_index=3,
        expiry_offset_days=20,
        mfg_offset_days=340,
        note="expires in 20 days — demonstrates the near-expiry warning",
    ),
    CatalogueItem(
        generic_name="Azithromycin 250mg",
        brand_name="Azinova 250",
        med_type=TYPE_MEDICINE,
        quantity="6 tablets",
        excipients=("Pregelatinised Starch", "Croscarmellose Sodium", "Talc"),
        manufacturer_index=0,
        expiry_offset_days=620,
        mfg_offset_days=40,
        note="valid antibiotic",
    ),
    CatalogueItem(
        generic_name="Oral Polio Vaccine",
        brand_name="Jeevan OPV",
        med_type=TYPE_VACCINE,
        quantity="1 vial (20 doses)",
        excipients=("Magnesium Chloride", "Phenol Red", "Water for Injection"),
        manufacturer_index=3,
        expiry_offset_days=180,
        mfg_offset_days=120,
        note="valid vaccine",
    ),
    CatalogueItem(
        generic_name="Insulin Glargine 100IU",
        brand_name="Glarnova 100",
        med_type=TYPE_VACCINE,  # cold-chain product; treated as vaccine for 2-8C rules
        quantity="1 cartridge (3 ml)",
        excipients=("Zinc Chloride", "Metacresol", "Glycerol", "Water for Injection"),
        manufacturer_index=2,
        expiry_offset_days=400,
        mfg_offset_days=60,
        note="insulin needs 2-8C like a vaccine, so it uses the vaccine type",
    ),
)


def demo_medicines(count: int = 5, today: date | None = None) -> list[MedicineData]:
    """Build ``count`` sample payloads.

    Dates are relative to ``today`` so the demo set never goes stale — the
    "expired" sample stays expired and the "expires soon" sample keeps expiring
    soon, whenever you run it. That matters for a demo you will re-run over
    several months.

    Serial numbers are the 1-based catalogue index, so a given catalogue entry
    always yields the same ``product_id``. Reproducible IDs make it possible to
    write the accompanying blockchain and API test scripts against fixed keys.
    """
    if not isinstance(count, int) or count < 1:
        raise ValueError(f"count must be a positive integer, got {count!r}")
    if count > len(CATALOGUE):
        raise ValueError(
            f"only {len(CATALOGUE)} demo items are defined; asked for {count}. "
            "Add entries to CATALOGUE in demo_data.py."
        )

    today = today or date.today()
    out: list[MedicineData] = []

    for index, item in enumerate(CATALOGUE[:count], start=1):
        maker = MANUFACTURERS[item.manufacturer_index]
        mfg_date = today - timedelta(days=item.mfg_offset_days)
        expiry_date = today + timedelta(days=item.expiry_offset_days)

        out.append(
            MedicineData(
                product_id=make_product_id(
                    item.generic_name, item.brand_name, mfg_date.year, index
                ),
                generic_name=item.generic_name,
                brand_name=item.brand_name,
                manufacturer=maker.full,
                mfg_licence_no=maker.licence_no,
                batch_no=_batch_no(maker, mfg_date, index),
                mfg_date=mfg_date.isoformat(),
                expiry_date=expiry_date.isoformat(),
                quantity=item.quantity,
                excipients=list(item.excipients),
                med_type=item.med_type,
            )
        )
    return out


def _batch_no(maker: Manufacturer, mfg_date: date, index: int) -> str:
    """Plausible batch number: maker initials, 2-digit year, month letter, serial.

    e.g. ``SP26C0417`` — Sanjeevani Pharma, 2026, March, unit 0417. Real batch
    numbering is manufacturer-specific and opaque; this just needs to look right.
    """
    initials = "".join(word[0] for word in maker.name.split()[:2]).upper()
    month_letter = "ABCDEFGHIJKL"[mfg_date.month - 1]
    return f"{initials}{mfg_date.year % 100:02d}{month_letter}{index:04d}"


def notes_for(count: int = 5) -> list[str]:
    """Human-readable description of what each demo item exercises."""
    return [
        f"{i}. {item.brand_name} ({item.generic_name}) — {item.note}"
        for i, item in enumerate(CATALOGUE[:count], start=1)
    ]
