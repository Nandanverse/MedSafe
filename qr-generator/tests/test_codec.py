"""Wire format encode/decode tests.

The codec is the system's attack surface: every byte a stranger can put in front
of the camera arrives here first. So most of this file is malformed input.
"""

from __future__ import annotations

import pytest

from truemed_qr import codec
from truemed_qr.errors import QRMalformedError, UnknownFormatVersionError
from truemed_qr.payload import WIRE_PREFIX

SIG = bytes(range(64))
PAYLOAD = b'{"id":"X_Y_2026_000001"}'


class TestBase64URL:
    def test_no_padding_emitted(self):
        for length in range(1, 40):
            assert "=" not in codec.b64u_encode(b"x" * length)

    @pytest.mark.parametrize("length", [0, 1, 2, 3, 4, 5, 31, 32, 64, 65, 511])
    def test_round_trip(self, length):
        raw = bytes((i * 7 + 3) % 256 for i in range(length))
        assert codec.b64u_decode(codec.b64u_encode(raw)) == raw

    def test_uses_url_safe_alphabet(self):
        # These bytes produce '+' and '/' under standard base64. If either leaks
        # into the output the QR drops out of alphanumeric mode and grows.
        raw = bytes([0xFB, 0xFF, 0xFE])
        encoded = codec.b64u_encode(raw)
        assert "+" not in encoded and "/" not in encoded
        assert set(encoded) <= set(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        )

    @pytest.mark.parametrize("bad", ["AA+A", "AA/A", "AA=A", "AA A", "AA!A", "AAéA"])
    def test_non_alphabet_characters_rejected(self, bad):
        # '+' and '/' matter specifically: base64's altchars translation happens
        # *before* validation, so without an explicit alphabet check "A-AA" and
        # "A+AA" would decode to identical bytes — two wire strings, one payload.
        with pytest.raises(QRMalformedError, match="base64url alphabet"):
            codec.b64u_decode(bad)

    def test_plus_and_dash_are_not_interchangeable(self):
        raw = bytes([0xFB, 0xFF, 0xFE])
        encoded = codec.b64u_encode(raw)  # contains '-' and '_'
        assert "-" in encoded or "_" in encoded
        confusable = encoded.replace("-", "+").replace("_", "/")
        if confusable != encoded:
            with pytest.raises(QRMalformedError):
                codec.b64u_decode(confusable)

    def test_wrong_length_rejected(self):
        with pytest.raises(QRMalformedError, match="not valid unpadded base64url"):
            codec.b64u_decode("A")  # 1 char can never be a valid base64 group

    def test_error_names_the_part(self):
        with pytest.raises(QRMalformedError, match="signature contains"):
            codec.b64u_decode("AA!A", what="signature")


class TestEncode:
    def test_shape(self):
        wire = codec.encode(PAYLOAD, SIG)
        parts = wire.split(".")
        assert len(parts) == 3
        assert parts[0] == WIRE_PREFIX == "TM1"

    def test_wire_is_ascii(self):
        # Non-ASCII in the wire string would force byte mode in the QR encoder.
        wire = codec.encode('{"mf":"संजीवनी"}'.encode("utf-8"), SIG)
        wire.encode("ascii")  # raises if not

    def test_rejects_wrong_signature_length(self):
        with pytest.raises(ValueError, match="exactly 64 raw bytes"):
            codec.encode(PAYLOAD, b"\x01" * 63)

    def test_rejects_str_payload(self):
        with pytest.raises(TypeError, match="payload_bytes must be bytes"):
            codec.encode("payload", SIG)  # type: ignore[arg-type]

    def test_rejects_str_signature(self):
        with pytest.raises(TypeError, match="signature must be bytes"):
            codec.encode(PAYLOAD, "sig")  # type: ignore[arg-type]

    def test_accepts_bytearray(self):
        assert codec.encode(bytearray(PAYLOAD), bytearray(SIG)) == codec.encode(
            PAYLOAD, SIG
        )


class TestDecode:
    def test_round_trip(self):
        decoded = codec.decode(codec.encode(PAYLOAD, SIG))
        assert decoded.prefix == WIRE_PREFIX
        assert decoded.payload_bytes == PAYLOAD
        assert decoded.signature == SIG

    def test_payload_bytes_are_verbatim(self):
        # The whole reason DecodedQR exists: the verifier must check the signature
        # over exactly these bytes, never over a re-serialisation of its own parse.
        weird = b'{"b":1,"a":2}'  # deliberately unsorted keys
        assert codec.decode(codec.encode(weird, SIG)).payload_bytes == weird

    def test_surrounding_whitespace_tolerated(self):
        # Scanners and clipboards routinely add newlines.
        wire = codec.encode(PAYLOAD, SIG)
        assert codec.decode(f"  {wire}\n").payload_bytes == PAYLOAD

    def test_total_wire_length_matches(self):
        wire = codec.encode(PAYLOAD, SIG)
        assert codec.decode(wire).total_wire_length == len(wire)

    @pytest.mark.parametrize("bad", ["", "   ", "\n"])
    def test_empty_rejected(self, bad):
        with pytest.raises(QRMalformedError, match="empty"):
            codec.decode(bad)

    def test_non_string_rejected(self):
        with pytest.raises(QRMalformedError, match="expected a string"):
            codec.decode(b"TM1.AA.BB")  # type: ignore[arg-type]

    def test_absurdly_long_rejected_before_work(self):
        with pytest.raises(QRMalformedError, match="beyond any real QR"):
            codec.decode("TM1." + "A" * 5000 + ".BB")

    @pytest.mark.parametrize(
        "bad",
        [
            "TM1",
            "TM1.onlytwo",
            "TM1.a.b.c",
            "TM1.....",
        ],
    )
    def test_wrong_part_count(self, bad):
        with pytest.raises(QRMalformedError, match="3 dot-separated parts"):
            codec.decode(bad)

    @pytest.mark.parametrize(
        "foreign",
        [
            "upi://pay?pa=someone@bank.x",
            "WIFI:S:clinic;T:WPA;P:hunter2;;",
            "https://example.org/promo",
            "....",
            "00012345678905",
        ],
    )
    def test_unrelated_qr_rejected_clearly(self, foreign):
        # A pharmacy counter has UPI stickers, WiFi cards and barcodes in frame.
        # The message must say "not ours", not "expected 3 dot-separated parts" —
        # a developer's sentence leaking onto a patient's screen.
        with pytest.raises(QRMalformedError, match="not a TrueMed QR code"):
            codec.decode(foreign)

    @pytest.mark.parametrize("prefix", ["TM2", "TM10", "tm9"])
    def test_future_format_version_is_distinguished(self, prefix):
        # "Update your app" is a different message from "this is a fake", and
        # conflating them would either scare patients or hide real forgeries.
        wire = codec.encode(PAYLOAD, SIG).replace(WIRE_PREFIX, prefix, 1)
        with pytest.raises(UnknownFormatVersionError, match="Update the app"):
            codec.decode(wire)

    def test_empty_payload_part(self):
        with pytest.raises(QRMalformedError, match="payload part is empty"):
            codec.decode(f"{WIRE_PREFIX}..{codec.b64u_encode(SIG)}")

    def test_empty_signature_part(self):
        with pytest.raises(QRMalformedError, match="signature part is empty"):
            codec.decode(f"{WIRE_PREFIX}.{codec.b64u_encode(PAYLOAD)}.")

    @pytest.mark.parametrize("length", [1, 32, 63, 65, 71, 128])
    def test_wrong_signature_length_rejected(self, length):
        wire = "{}.{}.{}".format(
            WIRE_PREFIX,
            codec.b64u_encode(PAYLOAD),
            codec.b64u_encode(b"\x01" * length),
        )
        with pytest.raises(QRMalformedError, match="raw ECDSA P-256 signature"):
            codec.decode(wire)

    def test_corrupt_base64_in_payload(self):
        wire = f"{WIRE_PREFIX}.not*valid*b64.{codec.b64u_encode(SIG)}"
        with pytest.raises(QRMalformedError, match="payload"):
            codec.decode(wire)


class TestLooksLikeTrueMed:
    @pytest.mark.parametrize(
        "text",
        ["TM1.abc.def", "  TM1.abc.def  ", "TM1.x.y\n"],
    )
    def test_accepts_ours(self, text):
        assert codec.looks_like_truemed(text)

    @pytest.mark.parametrize(
        "text",
        [
            "upi://pay?pa=x@y",
            "WIFI:S:cafe;T:WPA;P:hunter2;;",
            "https://example.org",
            "TM1",           # prefix without separator
            "TM10.a.b",      # different format, not ours
            "TM2.a.b",
            "",
            None,
            123,
        ],
    )
    def test_rejects_others(self, text):
        # The camera sees every QR in frame. Anything not ours must be ignored
        # silently rather than producing a red "counterfeit" screen.
        assert not codec.looks_like_truemed(text)  # type: ignore[arg-type]
