/// Strict, canonical base64url (RFC 4648 §5, unpadded).
///
/// Dart mirror of `backend/src/core/base64url.js`.
///
/// The strictness is not pedantry, and it is worth being explicit about what it
/// buys. A lenient decoder accepts many encodings of the same bytes: `A`, `AA`
/// and `AA==` can all yield one byte, and the low bits of a final character can
/// be non-zero and simply discarded. If this app accepted those, an attacker
/// could take one genuine QR string and produce thousands of textually distinct
/// variants that all decode to the same payload and therefore all verify under
/// the same signature. Nothing about the medicine changes — but the *clone
/// telemetry* keys on what was scanned, and §2.2 makes scan telemetry the entire
/// defence against a photocopied QR. Signature malleability here would hand out
/// unlimited free scans without ever tripping the clone counter.
///
/// So: one encoding, one string, or refuse.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'errors.dart';

/// The RFC 4648 §5 alphabet and nothing else. In particular not `+`, not `/`,
/// not `=`, not whitespace.
final RegExp _alphabet = RegExp(r'^[A-Za-z0-9_-]*$');
final RegExp _stray = RegExp(r'[^A-Za-z0-9_-]');

/// Decode unpadded base64url, rejecting anything non-canonical.
///
/// [what] names the part being decoded so the message points at the right half of
/// the QR string rather than saying "decode failed".
Uint8List decodeB64u(String text, String what) {
  final RegExpMatch? stray = _stray.firstMatch(text);
  if (stray != null || !_alphabet.hasMatch(text)) {
    final int at = stray?.start ?? 0;
    final String ch = stray == null ? '?' : text.substring(at, at + 1);
    throw qrMalformed(
      '$what contains "$ch" at position $at, which is not a base64url '
      'character; TrueMed QR codes use only A-Z a-z 0-9 - _ with no padding',
    );
  }

  // A base64 group of one character cannot exist: 6 bits is not a byte. Length
  // 4n+1 is therefore never valid, and the platform decoder's behaviour on it is
  // not something to rely on.
  if (text.length % 4 == 1) {
    throw qrMalformed(
      '$what is ${text.length} characters long, which is not a valid base64url '
      'length (a trailing group of one character encodes nothing)',
    );
  }

  Uint8List decoded;
  try {
    // `base64Url.decode` insists on padding, so it is added here. The alphabet
    // check above already guarantees the input carried none of its own.
    final int remainder = text.length % 4;
    final String padded =
        remainder == 0 ? text : text + '=' * (4 - remainder);
    decoded = base64Url.decode(padded);
  } on FormatException catch (err) {
    throw qrMalformed('$what is not valid base64url: ${err.message}');
  }

  // Round-trip: re-encode and require the exact same characters back. This is
  // what rejects `AA` versus `AB` for one byte — the non-zero discarded bits
  // case — and it is the check that makes the encoding canonical rather than
  // merely valid.
  final String reencoded = encodeB64u(decoded);
  if (reencoded != text) {
    throw qrMalformed(
      '$what is not canonically encoded unpadded base64url; it decodes to bytes '
      'that re-encode as a different string, so it is a rewritten copy of a '
      'valid code rather than the original',
    );
  }

  return decoded;
}

/// Encode to unpadded base64url. The inverse of [decodeB64u].
String encodeB64u(List<int> bytes) {
  final String padded = base64Url.encode(bytes);
  int end = padded.length;
  while (end > 0 && padded.codeUnitAt(end - 1) == 0x3d) {
    end -= 1;
  }
  return padded.substring(0, end);
}

/// Lowercase hex, for fingerprints and HMACs.
String toHex(List<int> bytes) {
  final StringBuffer out = StringBuffer();
  for (final int byte in bytes) {
    out.write((byte & 0xff).toRadixString(16).padLeft(2, '0'));
  }
  return out.toString();
}

final RegExp _hex = RegExp(r'^[0-9a-fA-F]*$');

/// Parse lowercase or uppercase hex. Used for the trust bundle's root signature,
/// which crypto.py expresses as hex rather than base64url.
///
/// The whole string is checked against the hex alphabet before any parsing,
/// because `int.tryParse` accepts a leading sign: without this, `-1` would parse
/// to -1 and land in the byte array as 0xff, silently turning a malformed
/// signature into a well-formed one.
Uint8List fromHex(String text, String what) {
  if (!_hex.hasMatch(text)) {
    throw trustBundleError('$what is not valid hex');
  }
  if (text.length % 2 != 0) {
    throw trustBundleError('$what has an odd number of hex digits');
  }
  final Uint8List out = Uint8List(text.length ~/ 2);
  for (int i = 0; i < out.length; i += 1) {
    out[i] = int.parse(text.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return out;
}
