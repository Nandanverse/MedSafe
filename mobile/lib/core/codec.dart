/// The `TM1.<payload>.<signature>` wire format. DATA-CONTRACT.md §1.1.
///
/// Dart mirror of `backend/src/core/codec.js`.
///
/// The order of the checks in [decodeWire] is copied from the Node version
/// deliberately and must not be rewritten into something that reads more
/// naturally. Two orderings matter:
///
/// 1. The `TM` prefix test comes **before** the part-count test. `TM2.a.b.c` has
///    four parts, and reporting that as QR_MALFORMED would tell a patient their
///    QR is damaged when in fact their app is too old. QR_UNKNOWN_VERSION sends
///    them to the app store instead of back to the pharmacy.
/// 2. The signature-length test comes **last**, after both parts decode, so a
///    truncated payload is reported as a payload problem rather than as a
///    signature problem.
///
/// Getting either wrong changes what the patient is told to do, which is the only
/// output of this app that matters.
library;

import 'dart:typed_data';

import 'base64url.dart';
import 'errors.dart';

/// The `1` in `TM1` is the payload contract version, whose canonical definition
/// is `contractVersion` in `payload.dart`. It is deliberately not re-declared
/// here: two constants that must agree are one constant that can drift.
const String wirePrefix = 'TM1';
const String wireSeparator = '.';

/// Raw `r||s` for P-256: 32 bytes each.
const int signatureLength = 64;

/// A QR v40 at ECC level H holds 1273 bytes in byte mode. Anything longer than a
/// generous multiple of that did not come off a medicine strip, and refusing it
/// early keeps a pasted wall of text out of the regexes and the decoder.
const int maxWireLength = 4096;

/// A decoded but not yet verified QR string.
class WireFrame {
  const WireFrame({
    required this.raw,
    required this.payloadB64,
    required this.signatureB64,
    required this.payloadBytes,
    required this.signatureBytes,
  });

  /// The string exactly as scanned, trimmed. Kept because a counterfeit report
  /// must carry the original text, not a reconstruction of it.
  final String raw;

  final String payloadB64;
  final String signatureB64;

  /// The bytes the signature covers. Verification uses **these**, never a
  /// re-serialisation of a parse of them. §1.5.
  final Uint8List payloadBytes;

  final Uint8List signatureBytes;
}

/// Cheap test for "does this look like one of ours at all".
///
/// Used by the scanner to ignore the shop's UPI QR without lighting up a red
/// COUNTERFEIT banner: a code that never claimed to be TrueMed is not a forgery,
/// it is simply a different code.
bool looksLikeTrueMed(String? text) =>
    text != null && text.trim().startsWith(wirePrefix + wireSeparator);

/// Split and decode a scanned string. Throws [TrueMedException] with
/// QR_MALFORMED or QR_UNKNOWN_VERSION; never returns a partially valid frame.
WireFrame decodeWire(String? scanned) {
  if (scanned == null) {
    throw qrMalformed('no QR content was decoded from the camera frame');
  }

  final String text = scanned.trim();

  if (text.isEmpty) {
    throw qrMalformed('the QR code is empty');
  }
  if (text.length > maxWireLength) {
    throw qrMalformed(
      'the scanned code is ${text.length} characters, far longer than any '
      'TrueMed QR (the format ceiling is $maxWireLength)',
    );
  }

  final List<String> parts = text.split(wireSeparator);

  // Prefix before part count — see the note at the top of this file.
  if (!parts[0].toUpperCase().startsWith('TM')) {
    throw qrMalformed(
      'this is not a TrueMed QR code: it does not begin with "$wirePrefix."',
    );
  }
  if (parts.length != 3) {
    throw qrMalformed(
      'a TrueMed QR has three dot-separated parts, this has ${parts.length}',
    );
  }

  final String prefix = parts[0];
  if (prefix != wirePrefix) {
    throw qrUnknownVersion(
      'this QR uses format version "$prefix", which this version of the app '
      'does not understand. Update TrueMed and scan again. It has NOT been '
      'verified, and it has NOT been shown to be fake.',
    );
  }

  if (parts[1].isEmpty) {
    throw qrMalformed('the QR code carries no data between the dots');
  }
  if (parts[2].isEmpty) {
    throw qrMalformed('the QR code carries no signature after the last dot');
  }

  final Uint8List payloadBytes = decodeB64u(parts[1], 'the QR data part');
  final Uint8List signatureBytes =
      decodeB64u(parts[2], 'the QR signature part');

  if (signatureBytes.length != signatureLength) {
    throw qrMalformed(
      'the signature is ${signatureBytes.length} bytes, but a TrueMed signature '
      'is exactly $signatureLength (P-256 r and s, 32 bytes each)',
    );
  }

  return WireFrame(
    raw: text,
    payloadB64: parts[1],
    signatureB64: parts[2],
    payloadBytes: payloadBytes,
    signatureBytes: signatureBytes,
  );
}

/// Reassemble a wire string from its parts. Used by the tests and by the
/// developer tools screen; the app never mints QR codes.
String encodeWire(List<int> payloadBytes, List<int> signatureBytes) {
  if (signatureBytes.length != signatureLength) {
    throw qrMalformed(
      'refusing to encode a ${signatureBytes.length}-byte signature; '
      'TrueMed signatures are $signatureLength bytes',
    );
  }
  return '$wirePrefix$wireSeparator${encodeB64u(payloadBytes)}'
      '$wireSeparator${encodeB64u(signatureBytes)}';
}
