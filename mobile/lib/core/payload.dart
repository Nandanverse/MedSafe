/// The signed payload inside a TrueMed QR: 12 wire fields, CDSCO's 9 mandatory
/// data elements plus a version and a type flag. DATA-CONTRACT.md §1.2–§1.4.
///
/// Dart mirror of `backend/src/core/payload.js` and
/// `qr-generator/truemed_qr/payload.py`.
///
/// **This module validates a field that has already been signed, so it must never
/// be stricter than the signer.** That asymmetry is the governing rule of the
/// whole file, and it is inverted from every other validator in the app. Being
/// stricter than the Python generator here does not make TrueMed safer: it makes
/// genuine medicine read as COUNTERFEIT, because `verifier.dart` turns any
/// [MedicineData.fromCanonicalJSON] failure into that verdict. A pharmacist told
/// that a real strip of paracetamol is fake stops trusting the app, and an app
/// nobody trusts protects nobody.
///
/// Three consequences of that rule are easy to miss:
///
/// - Every parameter is [Object?] rather than [String] or [List]. Typed
///   parameters would look tidier and would be wrong: `payload_wrong_type` in the
///   fixtures carries `"ex": "Maize Starch,Talc"`, a string where a list belongs,
///   and a typed parameter would surface that as a Dart `TypeError` escaping as
///   INTERNAL_ERROR instead of the PAYLOAD_INVALID the contract requires. The
///   validator, not the type system, produces the verdict.
/// - The dates are handed straight to [parseDate] and are **not** trimmed first.
///   `parseDate` pins them to exactly `^\d{4}-\d{2}-\d{2}$`, and the signer does
///   the same, so trimming here would accept `" 2026-03-15"` — a payload Node and
///   Python both reject. Leniency is the safe direction for a *signed* field only
///   when the signer shares it.
/// - The version check accepts an integral `double`. Dart's [jsonDecode] returns
///   `1` for `"v":1` but `1.0` for `"v":1.0`, and `1.0 is int` is false — whereas
///   JavaScript's `1.0 === 1` is true and Python's `1.0 == 1` is true. A bare
///   `is int` test would therefore reject a payload the other two would accept.
///   Nothing in the fixtures exercises it (all 26 cases use `1` or `2`), which is
///   exactly why it is written down here rather than left to a test.
///
/// The errors are [Codes.payloadInvalid], never [Codes.validationError], so the
/// helpers in `rules.dart` that raise VALIDATION_ERROR are not reused for the
/// signed fields — [_requireStr] below is the payload-specific twin of
/// `validateText`. The distinction is load-bearing: PAYLOAD_INVALID maps to
/// verdict COUNTERFEIT through `verdictToErrorCode`, VALIDATION_ERROR maps to no
/// verdict at all.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'canonical.dart' as canonical;
import 'errors.dart';
import 'rules.dart';

/// The only payload format version this build understands.
///
/// `wirePrefix` in `codec.dart` embeds the same number as `TM1`; the two must move
/// together, and a `TM2` QR is refused by the codec long before this constant is
/// consulted.
const int contractVersion = 1;

/// A QR version 40 symbol at error-correction level H holds 1273 bytes in byte
/// mode. Level H is not negotiable for TrueMed: a medicine strip gets creased,
/// wet, and rubbed against other strips in a pocket, and H recovers from roughly
/// 30% damage where L recovers from 7%.
const int qrMaxBytesEccH = 1273;

/// What the wrapper costs: `TM1` + `.` + `.` + 86 characters of base64url for a
/// 64-byte signature.
const int _wireOverhead = 3 + 1 + 1 + 86;

/// Hard ceiling on the **canonical payload in bytes**.
///
/// Bytes, not characters: a 64-character Devanagari generic name occupies 192
/// bytes of UTF-8, so a character budget would let a Hindi payload sail past the
/// limit and produce a QR that cannot be printed. The `~/ 4 * 3` undoes the
/// base64 expansion.
///
/// This is enforced on the *verify* path, which is only safe because
/// `qr-generator/truemed_qr/payload.py` computes the identical number from the
/// identical formula and refuses to sign anything larger. If that ever diverges,
/// this gate must be deleted rather than adjusted — see the rule at the top.
const int maxPayloadBytes = ((qrMaxBytesEccH - _wireOverhead) ~/ 4) * 3;

/// CDSCO does not cap the ingredient list; the QR does.
const int maxExcipients = 12;

/// Wire keys, short to save QR capacity. Order here is the human-readable order,
/// not the canonical one — [MedicineData.canonicalJSON] sorts.
const List<String> requiredWireKeys = <String>[
  'v',
  'id',
  'gn',
  'bn',
  'mf',
  'ml',
  'bt',
  'md',
  'ed',
  'qt',
  'ex',
  'tp',
];

/// The same fields under their full names, as the API and the UI use them.
const List<String> requiredFullKeys = <String>[
  'product_id',
  'generic_name',
  'brand_name',
  'manufacturer',
  'mfg_licence_no',
  'batch_no',
  'mfg_date',
  'expiry_date',
  'quantity',
  'excipients',
  'type',
];

/// Name the type of a rejected value the way the Node and Python versions do, so
/// the same bad QR produces the same sentence in all three implementations.
String _typeOf(Object? value) {
  if (value == null) return 'null';
  if (value is List) return 'list';
  if (value is String) return 'string';
  if (value is bool) return 'boolean';
  if (value is num) return 'number';
  if (value is Map) return 'object';
  return value.runtimeType.toString();
}

/// Quote a value for an error message without letting a hostile payload inject
/// quotes of its own into the sentence, and without pasting a 4 KB blob into a
/// log line.
String _quote(Object? value) {
  if (value == null) return 'null';
  final String text = value.toString();
  final String clipped = text.runes.length > 40
      ? '${String.fromCharCodes(text.runes.take(40))}...'
      : text;
  return '"${clipped.replaceAll('"', "'")}"';
}

/// Trim, reject empty, reject control characters, enforce the code-point limit —
/// and raise PAYLOAD_INVALID rather than VALIDATION_ERROR.
///
/// The trim is not cosmetic here, unlike on the dates: the signer trims these
/// seven fields before signing, so the bytes on the strip already hold the
/// trimmed form, and trimming again is what makes a round-trip through
/// [MedicineData.toWireDict] byte-identical to what was signed.
String _requireStr(Object? raw, String fieldName, [int? maxLen]) {
  if (raw is! String) {
    throw payloadInvalid('$fieldName must be a string, got ${_typeOf(raw)}');
  }
  final String value = raw.trim();
  if (value.isEmpty) {
    throw payloadInvalid('$fieldName must not be empty');
  }
  final ControlChar? control = findControlChar(value);
  if (control != null) {
    throw payloadInvalid(
      '$fieldName contains a control character (${control.label}) at position '
      '${control.index}; a printed medicine label cannot contain one, so this '
      'payload was assembled by something other than the CDSCO generator',
    );
  }
  final int? limit = maxLen ?? limits[fieldName];
  // Code points, not UTF-16 units: see validateText in rules.dart for why the two
  // disagree on Devanagari and why the user's count is the one that wins.
  final int length = value.runes.length;
  if (limit != null && length > limit) {
    throw payloadInvalid(
      '$fieldName is $length characters, over the $limit-character limit',
    );
  }
  return value;
}

/// One medicine or vaccine unit, as signed.
///
/// Immutable: every field is final and [excipients] is an unmodifiable view. The
/// Node version calls `Object.freeze`; this is the Dart equivalent, and it matters
/// for the same reason — a verdict is computed from these fields and then rendered
/// asynchronously, so a mutation in between would show the patient a verdict that
/// does not describe what they are holding.
class MedicineData {
  /// Validate and construct. Throws [TrueMedException] with PAYLOAD_INVALID.
  ///
  /// The order of the checks is copied from `payload.js` and should not be
  /// rearranged: the first failure is the one reported, and a payload with both a
  /// malformed product ID and a bad date ought to name the same problem in every
  /// implementation, or the three test suites disagree about a QR they all
  /// correctly reject.
  factory MedicineData({
    required Object? productId,
    required Object? genericName,
    required Object? brandName,
    required Object? manufacturer,
    required Object? mfgLicenceNo,
    required Object? batchNo,
    required Object? mfgDate,
    required Object? expiryDate,
    required Object? quantity,
    required Object? excipients,
    required Object? type,
    Object? version = contractVersion,
  }) {
    final String id = _requireStr(productId, 'product_id');
    final String generic = _requireStr(genericName, 'generic_name');
    final String brand = _requireStr(brandName, 'brand_name');
    final String maker = _requireStr(manufacturer, 'manufacturer');
    final String licence = _requireStr(mfgLicenceNo, 'mfg_licence_no');
    final String batch = _requireStr(batchNo, 'batch_no');
    final String qty = _requireStr(quantity, 'quantity');

    if (!productIdRe.hasMatch(id)) {
      throw payloadInvalid(
        'product_id ${_quote(id)} does not match '
        '{GENERIC}_{BRAND}_{YEAR}_{SERIAL} with a 4-digit year and 6-digit '
        'serial',
      );
    }

    // Accepts an integral double as well as an int; see the header.
    final bool versionIsInteger = version is int ||
        (version is double &&
            version.isFinite &&
            version == version.roundToDouble());
    if (!versionIsInteger || (version as num).toInt() != contractVersion) {
      throw payloadInvalid(
        'contract_version must be $contractVersion for prefix TM1, got '
        '${_quote(version)}',
      );
    }

    if (type is! String || !MedType.toWire.containsKey(type)) {
      throw payloadInvalid(
        'type must be one of ${MedType.toWire.keys.join(', ')}, got '
        '${_quote(type)}',
      );
    }

    // parseDate raises PAYLOAD_INVALID and rejects rollover dates like
    // 2026-02-31, so all three languages refuse the same set of dates. The raw
    // values are passed through untrimmed on purpose — see the header.
    final DateTime mfg = parseDate('mfg_date', mfgDate);
    final DateTime exp = parseDate('expiry_date', expiryDate);
    if (!exp.isAfter(mfg)) {
      throw payloadInvalid(
        'expiry_date ($expiryDate) must be after mfg_date ($mfgDate)',
      );
    }

    if (excipients is! List) {
      throw payloadInvalid(
        'excipients must be a JSON array of strings, not '
        '${_typeOf(excipients)}; a comma-joined string is unparseable because '
        'excipient names may themselves contain commas',
      );
    }
    if (excipients.length > maxExcipients) {
      throw payloadInvalid(
        'excipients has ${excipients.length} entries, over the $maxExcipients '
        'limit; list only the declared inactive ingredients',
      );
    }
    final List<String> cleanExcipients = <String>[];
    for (final Object? item in excipients) {
      cleanExcipients.add(_requireStr(item, 'excipient', limits['excipient']));
    }

    final MedicineData built = MedicineData._(
      productId: id,
      genericName: generic,
      brandName: brand,
      manufacturer: maker,
      mfgLicenceNo: licence,
      batchNo: batch,
      // parseDate has already proved these are strings in exactly the right
      // shape, so the cast cannot fail.
      mfgDate: mfgDate as String,
      expiryDate: expiryDate as String,
      quantity: qty,
      excipients: List<String>.unmodifiable(cleanExcipients),
      type: type,
      contractVersion: contractVersion,
    );

    // Capacity gate last, because it needs every field in its final form.
    final int size = built.canonicalJSON().length;
    if (size > maxPayloadBytes) {
      throw payloadInvalid(
        'payload encodes to $size bytes, over the $maxPayloadBytes-byte budget '
        'that fits a QR code at error-correction level H (overflow: '
        '${size - maxPayloadBytes} bytes). Note that non-Latin text costs up to '
        '3 bytes per character, so a Devanagari field uses far more of the '
        'budget than its character count suggests.',
      );
    }

    return built;
  }

  const MedicineData._({
    required this.productId,
    required this.genericName,
    required this.brandName,
    required this.manufacturer,
    required this.mfgLicenceNo,
    required this.batchNo,
    required this.mfgDate,
    required this.expiryDate,
    required this.quantity,
    required this.excipients,
    required this.type,
    required this.contractVersion,
  });

  /// Rebuild from the short-key wire form found inside a QR code.
  factory MedicineData.fromWireDict(Object? raw) {
    if (raw is! Map) {
      throw payloadInvalid(
        'QR payload must be a JSON object, got ${_typeOf(raw)}',
      );
    }

    final List<String> missing = <String>[];
    for (final String key in requiredWireKeys) {
      if (!raw.containsKey(key)) missing.add(key);
    }
    if (missing.isNotEmpty) {
      throw payloadInvalid(
        'QR payload is missing required keys: ${missing.join(', ')}',
      );
    }

    // `true is num` is false in Dart, so this one test rejects both a boolean and
    // a fractional version, matching the `typeof` + `Number.isInteger` pair in
    // the Node original. It runs before the `tp` check so that a payload broken
    // in both places names the same problem in every implementation.
    final Object? version = raw['v'];
    final bool versionIsInteger = version is int ||
        (version is double &&
            version.isFinite &&
            version == version.roundToDouble());
    if (!versionIsInteger) {
      throw payloadInvalid(
        "payload key 'v' must be an integer, got ${_quote(version)}",
      );
    }

    final Object? wireType = raw['tp'];
    if (wireType is! String || !MedType.fromWire.containsKey(wireType)) {
      throw payloadInvalid(
        "payload key 'tp' must be one of ${MedType.fromWire.keys.join(', ')}, "
        'got ${_quote(wireType)}',
      );
    }

    return MedicineData(
      version: version,
      productId: raw['id'],
      genericName: raw['gn'],
      brandName: raw['bn'],
      manufacturer: raw['mf'],
      mfgLicenceNo: raw['ml'],
      batchNo: raw['bt'],
      mfgDate: raw['md'],
      expiryDate: raw['ed'],
      quantity: raw['qt'],
      excipients: raw['ex'],
      type: MedType.fromWire[wireType],
    );
  }

  /// Rebuild from the full-key form: an API response body, or a cached scan.
  factory MedicineData.fromDict(Object? raw) {
    if (raw is! Map) {
      throw payloadInvalid(
        'medicine data must be a JSON object, got ${_typeOf(raw)}',
      );
    }
    final List<String> missing = <String>[];
    for (final String key in requiredFullKeys) {
      if (!raw.containsKey(key)) missing.add(key);
    }
    if (missing.isNotEmpty) {
      throw payloadInvalid(
        'medicine data is missing required keys: ${missing.join(', ')}',
      );
    }
    return MedicineData(
      version: raw.containsKey('contract_version')
          ? raw['contract_version']
          : contractVersion,
      productId: raw['product_id'],
      genericName: raw['generic_name'],
      brandName: raw['brand_name'],
      manufacturer: raw['manufacturer'],
      mfgLicenceNo: raw['mfg_licence_no'],
      batchNo: raw['batch_no'],
      mfgDate: raw['mfg_date'],
      expiryDate: raw['expiry_date'],
      quantity: raw['quantity'],
      excipients: raw['excipients'],
      type: raw['type'],
    );
  }

  /// Parse signed payload bytes.
  ///
  /// Note the asymmetry with [canonicalJSON]: this does **not** require that
  /// [blob] was canonically encoded. Verification signs over the received bytes,
  /// so a non-canonical but correctly-signed payload is still authentic — it just
  /// could not have come from our generator. `noncanonical_but_correctly_signed`
  /// in the fixtures is exactly that case, and it must verify.
  ///
  /// [utf8.decode] is called with `allowMalformed: false` — its default, spelled
  /// out because the alternative is silently wrong rather than noisily wrong. With
  /// `allowMalformed: true` an invalid byte sequence becomes U+FFFD, so the JSON
  /// that gets parsed is *different text* from the bytes the signature covers.
  /// This is the same reason `payload.js` constructs its `TextDecoder` with
  /// `{fatal: true}` and Python lets `UnicodeDecodeError` escape.
  factory MedicineData.fromCanonicalJSON(List<int> blob) {
    String text;
    try {
      text = utf8.decode(blob, allowMalformed: false);
    } on FormatException catch (err) {
      throw payloadInvalid(
        'QR payload is not valid UTF-8 (${err.message}), so it cannot be the '
        'text that was signed',
      );
    }

    Object? parsed;
    try {
      parsed = jsonDecode(text);
    } on FormatException catch (err) {
      throw payloadInvalid('QR payload is not valid JSON: ${err.message}');
    }

    return MedicineData.fromWireDict(parsed);
  }

  /// `GENERIC_BRAND_YYYY_NNNNNN`, unique per unit.
  final String productId;

  /// The molecule. CDSCO requires it, and it is the field a patient can check
  /// against a prescription.
  final String genericName;
  final String brandName;

  /// Name and full manufacturing address.
  final String manufacturer;

  /// State drug-licence number, e.g. `MH/25D/2019/187`.
  final String mfgLicenceNo;
  final String batchNo;

  /// `YYYY-MM-DD`.
  final String mfgDate;

  /// `YYYY-MM-DD`. Strictly after [mfgDate].
  final String expiryDate;

  /// Pack size as printed, e.g. `10 tablets`, `1 vial (0.5 ml)`.
  final String quantity;

  /// Unmodifiable. **Order is part of the signed data** (§1.5 rule 4), so it is
  /// preserved on the wire and must not be sorted for display either — a screen
  /// that re-sorts and then hands the list back to a signer would produce a
  /// payload that fails verification.
  final List<String> excipients;

  /// [MedType.medicine] or [MedType.vaccine]. Decides whether the cold-chain
  /// check applies at all.
  final String type;

  final int contractVersion;

  /// True when the 2-8 degrees C cold chain applies to this unit.
  bool get isVaccine => type == MedType.vaccine;

  /// Whole days until [expiryDate]; negative once expired, 0 on the expiry day.
  int daysRemaining({DateTime? asOf}) => daysToExpiry(expiryDate, asOf: asOf);

  /// True once the calendar date is past [expiryDate]. The expiry day itself is
  /// still usable, as a pharmacist reads it.
  bool expired({DateTime? asOf}) => isExpired(expiryDate, asOf: asOf);

  /// The short-key form that goes into a QR.
  Map<String, Object?> toWireDict() => <String, Object?>{
        'v': contractVersion,
        'id': productId,
        'gn': genericName,
        'bn': brandName,
        'mf': manufacturer,
        'ml': mfgLicenceNo,
        'bt': batchNo,
        'md': mfgDate,
        'ed': expiryDate,
        'qt': quantity,
        'ex': excipients.toList(growable: false),
        'tp': MedType.toWire[type],
      };

  /// The full-key form used by the API and the UI. §5 of the data contract: the
  /// wire is snake_case, Dart is lowerCamelCase, and the mapping lives here.
  Map<String, Object?> toDict() => <String, Object?>{
        'product_id': productId,
        'generic_name': genericName,
        'brand_name': brandName,
        'manufacturer': manufacturer,
        'mfg_licence_no': mfgLicenceNo,
        'batch_no': batchNo,
        'mfg_date': mfgDate,
        'expiry_date': expiryDate,
        'quantity': quantity,
        'excipients': excipients.toList(growable: false),
        'type': type,
        'contract_version': contractVersion,
      };

  /// The canonical JSON string of the wire form, for logging and fixtures.
  String canonicalJSONString() => canonical.canonicalJSONString(toWireDict());

  /// The bytes a signature covers **when signing**.
  ///
  /// Not what verification uses: see [MedicineData.fromCanonicalJSON] and §1.5.
  Uint8List canonicalJSON() => canonical.canonicalJSONBytes(toWireDict());

  /// Two payloads are equal when they canonicalise to the same bytes. Used by the
  /// test suite and by the scan-history de-duplicator.
  @override
  bool operator ==(Object other) =>
      other is MedicineData &&
      other.canonicalJSONString() == canonicalJSONString();

  @override
  int get hashCode => canonicalJSONString().hashCode;

  @override
  String toString() =>
      'MedicineData($productId, $brandName, $type, exp $expiryDate)';
}
