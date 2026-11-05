"""QR code rendering.

Kept separate from :mod:`truemed_qr.verifier` and :mod:`truemed_qr.crypto` so the
security-critical logic has no dependency on an image library. That separation is
practical, not cosmetic: it means the whole verification path can be tested, and
the offline verifier can be ported to Dart, without ``qrcode`` or Pillow
anywhere near it.

``qrcode`` is imported lazily inside the render functions so that
``import truemed_qr`` works — and the test suite runs — in an environment where
only ``cryptography`` is installed.

**Error correction is fixed at level H** (~30% recoverable). Medicine strips get
crushed in pockets, scratched by blister foil, and printed on curved vial labels.
Level H roughly doubles the code's size versus level L, which is precisely why the
payload is kept small: capacity spent on redundancy is capacity that survives a
scuffed print.
"""

from __future__ import annotations

import io
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

from .codec import encode
from .errors import CapacityError, DependencyMissingError, TrueMedError
from .payload import QR_MAX_BYTES_ECC_H, MedicineData

if TYPE_CHECKING:  # pragma: no cover
    from cryptography.hazmat.primitives.asymmetric import ec

#: Above this fitted QR version, density starts to defeat cheap phone cameras and
#: low-resolution label printers. Not a hard failure — a warning, because a
#: verbose excipient list is a data problem to fix upstream, not a reason to
#: refuse to print.
MAX_RECOMMENDED_VERSION: Final[int] = 20

#: Pixels per QR module. 10 gives a ~410px code for a version-13 payload, which
#: prints crisply at 300 dpi on a 35mm label.
DEFAULT_SCALE: Final[int] = 10
#: Quiet-zone width in modules. The QR specification mandates 4; scanners are
#: measurably less reliable below that, and it is a common cause of "why won't
#: this scan" on tightly-cropped labels.
DEFAULT_BORDER: Final[int] = 4


@dataclass
class GeneratedQR:
    """What came out of a generation run."""

    product_id: str
    wire: str
    png_path: Path | None
    qr_version: int | None
    wire_bytes: int
    modules_per_side: int | None = None
    warnings: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "product_id": self.product_id,
            "wire": self.wire,
            "png_path": str(self.png_path) if self.png_path else None,
            "qr_version": self.qr_version,
            "wire_bytes": self.wire_bytes,
            "modules_per_side": self.modules_per_side,
            "warnings": list(self.warnings),
        }


def build_wire(medicine: MedicineData, private_key: "ec.EllipticCurvePrivateKey") -> str:
    """Sign a payload and assemble the wire string.

    This is the only place a payload gets signed. Note the ordering: canonical
    bytes are produced once, signed, and the *same* bytes are encoded. Signing one
    serialisation and transmitting another is a classic way to ship a system where
    every signature fails in production but passes in tests.
    """
    from . import crypto  # local import keeps module import order simple

    payload_bytes = medicine.canonical_json()
    signature = crypto.sign(private_key, payload_bytes)
    wire = encode(payload_bytes, signature)

    if len(wire.encode("ascii")) > QR_MAX_BYTES_ECC_H:
        raise CapacityError(
            f"payload for {medicine.product_id} encodes to {len(wire)} bytes, over the "
            f"{QR_MAX_BYTES_ECC_H}-byte ceiling for a QR code at error-correction "
            "level H. Shorten the manufacturer address or trim the excipient list."
        )
    return wire


def _load_qrcode_module():
    try:
        import qrcode  # type: ignore[import-not-found]
        import qrcode.constants  # noqa: F401
    except ImportError as exc:
        raise DependencyMissingError(
            "QR image rendering needs the 'qrcode' package:\n"
            "  pip install 'qrcode[pil]'\n"
            "Signing and verifying payload strings work without it."
        ) from exc
    return qrcode


def _to_pil_image(qr_image: Any):
    """Get a real PIL Image out of whatever ``qrcode`` handed back.

    ``qrcode`` returns a thin wrapper rather than a PIL Image. ``get_image()`` is
    the documented accessor, but the wrapper class has changed across releases, so
    fall back to a PNG round-trip through memory — which works with any factory
    that can save itself.
    """
    from PIL import Image

    getter = getattr(qr_image, "get_image", None)
    if callable(getter):
        try:
            return getter()
        except Exception:  # noqa: BLE001 - fall through to the universal path
            pass

    buffer = io.BytesIO()
    qr_image.save(buffer, format="PNG")
    buffer.seek(0)
    return Image.open(buffer).convert("RGB")


def _pick_font(size: int):
    """Best available font, degrading to Pillow's bitmap default.

    Caption text is a convenience for printed demo sheets, so a missing TrueType
    font must never stop a QR from being generated.
    """
    from PIL import ImageFont

    for candidate in (
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
        "C:/Windows/Fonts/arial.ttf",
        "/System/Library/Fonts/Helvetica.ttc",
    ):
        if Path(candidate).is_file():
            try:
                return ImageFont.truetype(candidate, size)
            except OSError:
                continue
    return ImageFont.load_default()


def render_png(
    wire: str,
    out_path: str | Path,
    *,
    scale: int = DEFAULT_SCALE,
    border: int = DEFAULT_BORDER,
    caption: list[str] | None = None,
) -> GeneratedQR:
    """Render a wire string to a PNG at error-correction level H.

    Args:
        wire: The ``TM1...`` string.
        out_path: Destination ``.png``. Parent directories are created.
        scale: Pixels per module.
        border: Quiet-zone width in modules. Below 4 breaks the QR spec.
        caption: Optional human-readable lines drawn beneath the code. Useful on a
            printed demo sheet so a viewer can see what each code contains, and
            harmless in production because the caption is outside the QR area.

    Returns:
        :class:`GeneratedQR` with the fitted version and pixel geometry.
    """
    qrcode = _load_qrcode_module()

    if scale < 1:
        raise ValueError(f"scale must be >= 1, got {scale}")
    if border < 4:
        raise ValueError(
            f"border must be >= 4 modules to satisfy the QR quiet-zone requirement, "
            f"got {border}"
        )

    path = Path(out_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    qr = qrcode.QRCode(
        version=None,  # fit=True chooses the smallest version that holds the data
        error_correction=qrcode.constants.ERROR_CORRECT_H,
        box_size=scale,
        border=border,
    )
    qr.add_data(wire)
    try:
        qr.make(fit=True)
    except Exception as exc:  # qrcode raises DataOverflowError, not in our namespace
        raise CapacityError(
            f"payload of {len(wire)} bytes will not fit in any QR version at "
            f"error-correction level H: {exc}"
        ) from exc

    version = int(qr.version)
    modules = version * 4 + 17

    warnings: list[str] = []
    if version > MAX_RECOMMENDED_VERSION:
        warnings.append(
            f"QR fitted to version {version} ({modules}x{modules} modules), above the "
            f"recommended maximum of {MAX_RECOMMENDED_VERSION}. It will scan on a good "
            "camera but may struggle on low-end phones or small labels. Shorten the "
            "manufacturer address or excipient list to bring it down."
        )

    image = _to_pil_image(qr.make_image(fill_color="black", back_color="white"))

    if caption:
        image = _add_caption(image, caption, scale)

    try:
        image.save(path, format="PNG", optimize=True)
    except OSError as exc:
        raise TrueMedError(
            f"could not write {path}: {exc}", code="FILE_WRITE_FAILED"
        ) from exc

    return GeneratedQR(
        product_id="",
        wire=wire,
        png_path=path,
        qr_version=version,
        wire_bytes=len(wire.encode("ascii")),
        modules_per_side=modules,
        warnings=warnings,
    )


def _add_caption(image, lines: list[str], scale: int):
    """Draw caption lines beneath the QR on a white strip."""
    from PIL import Image, ImageDraw

    font_size = max(11, scale + 2)
    font = _pick_font(font_size)
    draw = ImageDraw.Draw(image)

    line_height = font_size + 4
    padding = 8
    caption_height = padding * 2 + line_height * len(lines)

    canvas = Image.new(
        "RGB", (image.width, image.height + caption_height), color="white"
    )
    canvas.paste(image, (0, 0))
    draw = ImageDraw.Draw(canvas)

    y = image.height + padding
    for line in lines:
        # textlength is Pillow >= 8; fall back to a rough estimate if absent.
        try:
            width = draw.textlength(line, font=font)
        except AttributeError:  # pragma: no cover
            width = len(line) * font_size * 0.55
        draw.text(
            ((canvas.width - width) / 2, y), line, fill="black", font=font
        )
        y += line_height

    return canvas


def generate(
    medicine: MedicineData,
    private_key: "ec.EllipticCurvePrivateKey",
    out_dir: str | Path | None = None,
    *,
    scale: int = DEFAULT_SCALE,
    border: int = DEFAULT_BORDER,
    with_caption: bool = True,
) -> GeneratedQR:
    """Sign a payload and, if ``out_dir`` is given, write ``{product_id}.png``.

    With ``out_dir=None`` this only produces the wire string, which is the useful
    mode for a production line that pushes codes straight to a label printer or an
    API rather than to files.
    """
    wire = build_wire(medicine, private_key)

    if out_dir is None:
        return GeneratedQR(
            product_id=medicine.product_id,
            wire=wire,
            png_path=None,
            qr_version=None,
            wire_bytes=len(wire.encode("ascii")),
        )

    caption = None
    if with_caption:
        caption = [
            f"{medicine.brand_name} — {medicine.generic_name}",
            f"B.No {medicine.batch_no}   MFG {medicine.mfg_date}   EXP {medicine.expiry_date}",
            "TrueMed · Truth in Every Medicine",
        ]

    result = render_png(
        wire,
        Path(out_dir) / f"{medicine.product_id}.png",
        scale=scale,
        border=border,
        caption=caption,
    )
    result.product_id = medicine.product_id
    return result
