/// Canonical JSON, byte-identical to Python's
/// `json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)`.
///
/// Dart mirror of `backend/src/core/canonical.js`.
///
/// The app needs this for exactly one thing: recomputing the bytes the CDSCO root
/// key signed over a trust bundle, so the root signature can be checked before any
/// manufacturer key inside is trusted. It is deliberately *not* used for the QR
/// payload — DATA-CONTRACT.md §1.5 requires verifying over the received bytes, and
/// re-serialising a parse of them is the classic signature-bypass bug.
///
/// Where Dart already agrees with Python, and why:
///
/// - [jsonEncode] emits no whitespace, matching `separators=(",", ":")`.
/// - Neither escapes non-ASCII once Python has `ensure_ascii=False`, so Hindi text
///   is raw UTF-8 in both.
/// - Both use the short forms `\b \t \n \f \r` and `\u00xx` with **lowercase**
///   hex for the remaining C0 controls.
/// - Neither escapes `/`, U+2028, U+2029, or DEL.
/// - Dart's default map is insertion-ordered, so writing keys in sorted order is
///   enough to fix the output order.
///
/// Where they could diverge, and what is done about it:
///
/// - **Key order.** Python sorts by Unicode code point. Dart's [String.compareTo]
///   compares UTF-16 code units, which differ for characters above the BMP: an
///   emoji key sorts before `￿` by code point and after it by code unit. A
///   code-point comparator is used instead.
/// - **Nesting.** Python's `sort_keys` is recursive, so this is too.
/// - **Integral doubles.** `jsonEncode(4.0)` is `"4.0"` in Dart but `"4"` in both
///   Python (for `int` 4) and JavaScript (for `4.0`). An integral double is
///   therefore narrowed to an int before encoding.
/// - **Floats and big integers.** Python's `repr` and Dart's `toString` both
///   produce a shortest round-tripping form, but they switch to exponential
///   notation at different magnitudes, Python ints are arbitrary-precision while
///   Dart ints are 64-bit (and 53-bit on the web), and no JSON dialect can carry
///   NaN or Infinity. Nothing TrueMed signs contains a float or a large integer,
///   so rather than pretend to handle them, anything outside the ±2^53 range that
///   all four languages agree on is rejected.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'errors.dart';

/// The range every language in TrueMed represents identically: JavaScript's
/// `Number.MAX_SAFE_INTEGER`.
const int maxSafeInteger = 9007199254740991;

/// Compare by Unicode code point, as Python's `sorted()` does.
int compareByCodePoint(String a, String b) {
  final List<int> ar = a.runes.toList();
  final List<int> br = b.runes.toList();
  final int n = ar.length < br.length ? ar.length : br.length;
  for (int i = 0; i < n; i += 1) {
    final int d = ar[i] - br[i];
    if (d != 0) return d;
  }
  return ar.length - br.length;
}

Object? _canonicalise(Object? value, String path) {
  if (value == null || value is String || value is bool) return value;

  if (value is num) {
    if (value is double) {
      if (!value.isFinite) {
        throw payloadInvalid('$path is $value, which JSON cannot represent');
      }
      // 4.0 must encode as "4", not "4.0". Narrowing here rather than at write
      // time keeps the whole decision in one place.
      if (value != value.roundToDouble()) {
        throw payloadInvalid(
          '$path is $value, which canonical JSON in TrueMed does not carry: '
          'only integers within +/-2^53 are permitted, because Dart, Python and '
          'JavaScript do not agree on the shortest representation of every '
          'float, and a signature covers bytes',
        );
      }
      if (value.abs() > maxSafeInteger.toDouble()) {
        throw payloadInvalid(
          '$path is $value, which is outside the +/-2^53 range every TrueMed '
          'component represents identically',
        );
      }
      return value.toInt();
    }
    final int asInt = value as int;
    if (asInt > maxSafeInteger || asInt < -maxSafeInteger) {
      throw payloadInvalid(
        '$path is $asInt, which is outside the +/-2^53 range every TrueMed '
        'component represents identically; past 1e21 JavaScript switches to '
        'exponential notation while Python does not, and a signature covers bytes',
      );
    }
    return asInt;
  }

  if (value is List) {
    // Array order is preserved: excipient order is part of the signed data
    // (§1.5 rule 4), so sorting here would break signatures.
    final List<Object?> out = <Object?>[];
    for (int i = 0; i < value.length; i += 1) {
      out.add(_canonicalise(value[i], '$path[$i]'));
    }
    return out;
  }

  if (value is Map) {
    final List<String> keys = <String>[];
    for (final Object? key in value.keys) {
      if (key is! String) {
        throw payloadInvalid(
          '$path has a non-string key ($key); JSON object keys are strings',
        );
      }
      keys.add(key);
    }
    keys.sort(compareByCodePoint);
    final Map<String, Object?> out = <String, Object?>{};
    for (final String key in keys) {
      final Object? child = value[key];
      out[key] = _canonicalise(child, path.isEmpty ? key : '$path.$key');
    }
    return out;
  }

  throw payloadInvalid(
    '$path is a ${value.runtimeType}, which cannot be serialised to JSON',
  );
}

String canonicalJSONString(Object? value) => jsonEncode(_canonicalise(value, ''));

/// The exact bytes that get signed.
Uint8List canonicalJSONBytes(Object? value) =>
    Uint8List.fromList(utf8.encode(canonicalJSONString(value)));
