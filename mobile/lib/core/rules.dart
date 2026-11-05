/// Shared rules, enums, limits and date arithmetic.
///
/// Dart mirror of `backend/src/core/rules.js`, which is itself the mirror of
/// `blockchain/chaincode/internal/rules/rules.go` and the constants in
/// `qr-generator/truemed_qr/`. Four implementations of one rulebook is a drift
/// risk, so each language keeps its copy in exactly one file and the values are
/// cross-checked in tests rather than trusted. `test/rules_test.dart` asserts
/// every threshold in here against the numbers baked into the shared fixtures.
///
/// Nothing in this file touches the network, the filesystem, or Flutter. Every
/// rule a patient's verdict depends on is a pure function, testable with
/// `dart test` and no device attached.
library;

import 'errors.dart';

// ── Enumerations ─────────────────────────────────────────────────────────────

/// Custody statuses. DATA-CONTRACT.md §3.1.
abstract final class Status {
  static const String manufactured = 'manufactured';
  static const String inTransit = 'in_transit';
  static const String atPharmacy = 'at_pharmacy';
  static const String dispensed = 'dispensed';
  static const String recalled = 'recalled';

  static const List<String> all = <String>[
    manufactured,
    inTransit,
    atPharmacy,
    dispensed,
    recalled,
  ];

  static bool isKnown(String status) => all.contains(status);

  static bool isTerminal(String status) =>
      status == dispensed || status == recalled;

  /// Human label for the custody timeline. Kept beside the enum so a new status
  /// cannot be added without someone noticing the label is missing.
  static String label(String status) {
    switch (status) {
      case manufactured:
        return 'Manufactured';
      case inTransit:
        return 'In transit';
      case atPharmacy:
        return 'At pharmacy';
      case dispensed:
        return 'Dispensed';
      case recalled:
        return 'Recalled';
      default:
        return status;
    }
  }
}

abstract final class MedType {
  static const String medicine = 'medicine';
  static const String vaccine = 'vaccine';

  /// Wire flag → full name. `tp` in the QR payload.
  static const Map<String, String> fromWire = <String, String>{
    'M': medicine,
    'V': vaccine,
  };

  static const Map<String, String> toWire = <String, String>{
    medicine: 'M',
    vaccine: 'V',
  };
}

abstract final class Verdict {
  static const String genuine = 'GENUINE';
  static const String offlineOk = 'SIGNATURE_VALID_OFFLINE';
  static const String expired = 'EXPIRED';
  static const String coldChain = 'COLD_CHAIN_BREACH';
  static const String clone = 'CLONE_SUSPECTED';
  static const String recalled = 'RECALLED';
  static const String counterfeit = 'COUNTERFEIT';
  static const String unverifiable = 'UNVERIFIABLE';

  /// All eight verdicts, **most severe first**. This ordering is the one
  /// [worstVerdict] resolves against, so the list is both the enumeration and the
  /// precedence table — kept as one list because two lists of the same eight
  /// values is a drift waiting to happen.
  ///
  /// A bad signature dominates everything else: the batch number on a forged strip
  /// is whatever the forger typed, so no other field is worth reporting.
  ///
  /// `unverifiable` is in here, which is easy to leave out and important. A list
  /// that omits it has no ordering to resolve `['UNVERIFIABLE']` with and falls
  /// through to the default, which in practice means a patient holding genuine
  /// medicine sees a red counterfeit warning because their trust bundle is a week
  /// out of date. See the §7.1 amendment dated 2026-08-22.
  static const List<String> all = <String>[
    counterfeit,
    recalled,
    clone,
    coldChain,
    expired,
    unverifiable,
    offlineOk,
    genuine,
  ];

  /// False for a verdict this build has never heard of — which is a live case, not
  /// a theoretical one: the API can be newer than an installed APK. Callers that
  /// receive a verdict from the network must treat an unknown one as
  /// [unverifiable] rather than ignoring it, because [worstVerdict] can only rank
  /// values it knows and would otherwise drop it silently.
  static bool isKnown(String? verdict) =>
      verdict != null && all.contains(verdict);
}

abstract final class Severity {
  static const String ok = 'ok';
  static const String warn = 'warn';
  static const String critical = 'critical';
}

/// DATA-CONTRACT.md §2.3.
const Map<String, String> _severityOf = <String, String>{
  Verdict.genuine: Severity.ok,
  Verdict.offlineOk: Severity.warn,
  Verdict.expired: Severity.warn,
  Verdict.unverifiable: Severity.warn,
  Verdict.coldChain: Severity.critical,
  Verdict.clone: Severity.critical,
  Verdict.recalled: Severity.critical,
  Verdict.counterfeit: Severity.critical,
};

/// Most severe first. Defined once, on [Verdict.all].
const List<String> _precedence = Verdict.all;

/// Check outcomes reported in `data.checks`.
abstract final class Check {
  static const String pass = 'pass';
  static const String fail = 'fail';
  static const String skippedOffline = 'skipped_offline';
  static const String notApplicable = 'not_applicable';
  static const String notEvaluated = 'not_evaluated';
  static const String skippedNoPayload = 'skipped_no_payload';
}

/// The five checks of §2.1, in the order they are displayed.
abstract final class CheckName {
  static const String structure = 'structure';
  static const String signature = 'signature';
  static const String expiry = 'expiry';
  static const String onChain = 'on_chain';
  static const String coldChain = 'cold_chain';
  static const String cloneTelemetry = 'clone_telemetry';

  static const List<String> ordered = <String>[
    structure,
    signature,
    expiry,
    onChain,
    coldChain,
    cloneTelemetry,
  ];

  static String label(String name) {
    switch (name) {
      case structure:
        return 'QR structure';
      case signature:
        return 'Digital signature';
      case expiry:
        return 'Expiry date';
      case onChain:
        return 'Blockchain record';
      case coldChain:
        return 'Cold chain';
      case cloneTelemetry:
        return 'Duplicate scans';
      default:
        return name;
    }
  }
}

// ── Thresholds ───────────────────────────────────────────────────────────────

/// WHO cold chain for routine vaccines. Inclusive at both ends. §3.3.
const double vaccineTempMinC = 2.0;
const double vaccineTempMaxC = 8.0;

/// DS18B20 rated range. Outside it is a wiring fault, not a cold-chain event: a
/// disconnected one-wire bus reads -127 °C or +85 °C, and rendering those as
/// breaches would bury real excursions under hardware noise.
const double sensorTempMinC = -55.0;
const double sensorTempMaxC = 125.0;

const int cloneScanThreshold = 25;
const int cloneDistrictThreshold = 3;

const int maxEmbeddedReadings = 48;
const int maxCustodyEvents = 64;
const int maxDistinctDistricts = 32;
const int maxRecallPerTx = 500;

const int defaultPageSize = 50;
const int maxPageSize = 500;

/// Per-field character limits. Mirrors `LIMITS` in rules.js, `_MAX_LEN` in
/// payload.py and rules.go.
const Map<String, int> limits = <String, int>{
  'product_id': 80,
  'generic_name': 64,
  'brand_name': 48,
  'manufacturer': 120,
  'mfg_licence_no': 32,
  'batch_no': 24,
  'quantity': 32,
  'excipient': 40,
  'excipients': 12,
  'location': 32,
  'sensor_id': 32,
  'district': 48,
  'state': 48,
  'pharmacy_name': 120,
  'reason': 200,
  'notes': 500,
  'reporter_contact': 120,
};

/// Deliberately identical to `PRODUCT_ID_RE` in rules.js and `_PRODUCT_ID_RE` in
/// payload.py, down to the unbounded segments and the permissive 4-digit year.
///
/// Validation of a *signed* field must never be stricter than the signer. If
/// Python will sign `AAAA…(50 chars)_BRAND_2100_000001` and this app rejects it,
/// the patient sees COUNTERFEIT on genuine medicine — the one failure mode that
/// destroys trust in the whole system. Overall length is bounded by
/// `limits['product_id']` instead, exactly as Python bounds it.
final RegExp productIdRe = RegExp(r'^[A-Z0-9]+_[A-Z0-9]+_\d{4}_\d{6}$');
final RegExp dateRe = RegExp(r'^\d{4}-\d{2}-\d{2}$');
final RegExp locationRe = RegExp(r'^[A-Z0-9][A-Z0-9_-]{1,31}$');
final RegExp sensorIdRe = RegExp(r'^TM-SENSOR-[A-Z0-9]{2,12}$');
final RegExp rfc3339Re = RegExp(
  r'^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:[Zz]|[+-]\d{2}:\d{2})$',
);

/// `tm_{role}_{32 hex}`, §4.2. Checked in the app so a mistyped key is caught
/// before it costs a round trip and a rate-limit slot.
///
/// `pharma` and `pharmacy` are both here and they are not the same role: `pharma`
/// is a manufacturer's read-only analytics key, `pharmacy` is a retail chemist's
/// write key for the `at_pharmacy` and `dispensed` transitions.
///
/// The alternation lists `pharmacy` before `pharma`, which is *not* required for
/// correctness and is worth being precise about, because the obvious reason to do it
/// is wrong. Dart's regular expressions backtrack, and this pattern is anchored at
/// both ends, so `pharma|pharmacy` also matches a pharmacy key and also captures
/// `pharmacy`: the engine tries `pharma`, fails to match `_` against `c`, and
/// retries the alternation. Order would only matter if the pattern were unanchored
/// or the alternation were matched on its own — in which case `pharma` would win and
/// [roleOfApiKey] would silently report a chemist's key as a manufacturer analytics
/// key. Longest-first ordering costs nothing and removes that trap for whoever next
/// copies this alternation somewhere without the anchors.
final RegExp apiKeyRe = RegExp(
  r'^tm_(manufacturer|distributor|sensor|regulator|pharmacy|pharma)_[0-9a-f]{32}$',
);

/// The role embedded in an API key, or null if the key is not well-formed.
///
/// Read locally so a screen can refuse to start a regulator workflow with a
/// pharmacy key before making a request that would fail with FORBIDDEN. The
/// server's answer is the authoritative one; this only saves the user a round trip
/// and a confusing error.
String? roleOfApiKey(String? key) {
  if (key == null) return null;
  final RegExpMatch? match = apiKeyRe.firstMatch(key.trim());
  return match?.group(1);
}

/// Custody transitions a retail pharmacy may assert (§4.3).
///
/// Enforced server-side; duplicated here only for the error message. Without the
/// status restriction a chemist's key could rewind a unit to `in_transit` and route
/// it elsewhere, so the role check alone is not sufficient.
const List<String> pharmacyStatuses = <String>[
  Status.atPharmacy,
  Status.dispensed,
];

// ── Verdicts ─────────────────────────────────────────────────────────────────

String severityFor(String verdict) => _severityOf[verdict] ?? Severity.critical;

/// The most severe verdict in the list.
///
/// Falls back to UNVERIFIABLE for an unrecognised verdict, matching
/// `worstVerdict` in rules.js and `worst_verdict` in verifier.py. Two wrong
/// answers were available and both are worse: GENUINE would assert safety about
/// something we do not understand, and COUNTERFEIT would show a red counterfeit
/// warning for what is most likely an app older than the API. UNVERIFIABLE
/// asserts nothing, which is the honest answer.
String worstVerdict(List<String> verdicts) {
  if (verdicts.isEmpty) return Verdict.genuine;
  for (final String candidate in _precedence) {
    if (verdicts.contains(candidate)) return candidate;
  }
  return Verdict.unverifiable;
}

/// Verdict → `error.code`, or null when the verdict is not a failure.
String? verdictToErrorCode(String verdict) {
  switch (verdict) {
    case Verdict.counterfeit:
      return Codes.signatureInvalid;
    case Verdict.recalled:
      return Codes.recalled;
    case Verdict.clone:
      return Codes.cloneSuspected;
    case Verdict.coldChain:
      return Codes.coldChainBreach;
    case Verdict.expired:
      return Codes.expired;
    case Verdict.unverifiable:
      return Codes.payloadInvalid;
    default:
      return null;
  }
}

bool cloneSuspected(int scanCount, int distinctDistricts) =>
    scanCount > cloneScanThreshold ||
    distinctDistricts > cloneDistrictThreshold;

/// Only vaccines have a cold chain; medicines log temperature without breaching.
bool breachesColdChain(String medType, double temperature) =>
    medType == MedType.vaccine &&
    (temperature < vaccineTempMinC || temperature > vaccineTempMaxC);

// ── Dates ────────────────────────────────────────────────────────────────────

const int _msPerDay = 86400000;

/// Parse a strict `YYYY-MM-DD` date to UTC midnight.
///
/// The regex is not redundant with [DateTime.parse], which accepts `2026-03-15
/// 10:00`, treats a bare date as *local* midnight, and — like `Date.UTC` in
/// JavaScript — silently rolls `2026-02-31` into 3 March. A date inside a signed
/// payload must have exactly one representation, and an expiry that rolls forward
/// by two days is an expiry check that can be gamed.
DateTime parseDate(String field, Object? value) {
  if (value is! String || !dateRe.hasMatch(value)) {
    throw payloadInvalid('$field must be exactly YYYY-MM-DD (got ${_show(value)})');
  }
  final int year = int.parse(value.substring(0, 4));
  final int month = int.parse(value.substring(5, 7));
  final int day = int.parse(value.substring(8, 10));
  final DateTime parsed = DateTime.utc(year, month, day);
  // Reject 2026-02-31 and friends: DateTime.utc rolls them over instead of
  // failing, exactly as Date.UTC does in Node.
  if (parsed.year != year || parsed.month != month || parsed.day != day) {
    throw payloadInvalid('$field is not a real calendar date: $value');
  }
  return parsed;
}

/// UTC midnight of the day containing [when].
DateTime dayOf(DateTime when) {
  final DateTime utc = when.toUtc();
  return DateTime.utc(utc.year, utc.month, utc.day);
}

/// Format a [DateTime] back to `YYYY-MM-DD`.
String formatDate(DateTime when) {
  final DateTime utc = when.toUtc();
  final String y = utc.year.toString().padLeft(4, '0');
  final String m = utc.month.toString().padLeft(2, '0');
  final String d = utc.day.toString().padLeft(2, '0');
  return '$y-$m-$d';
}

/// Whole days remaining; negative once expired, 0 on the expiry day itself.
int daysToExpiry(String expiryDate, {DateTime? asOf}) {
  final DateTime expiry = parseDate('expiry_date', expiryDate);
  final DateTime today = dayOf(asOf ?? DateTime.now());
  final int deltaMs =
      expiry.millisecondsSinceEpoch - today.millisecondsSinceEpoch;
  // Both operands are exact UTC midnights, so this division is exact and the
  // rounding is belt-and-braces against a future change to either side.
  return (deltaMs / _msPerDay).round();
}

/// True once the calendar date is past the printed expiry.
///
/// The expiry day itself is still usable — a pharmacist reading `EXP 02/2028`
/// dispenses on 29 February 2028 without hesitation, and calling that unit
/// expired would be wrong in a way that undermines every other verdict.
bool isExpired(String expiryDate, {DateTime? asOf}) =>
    daysToExpiry(expiryDate, asOf: asOf) < 0;

void validateDateOrder(String mfgDate, String expiryDate) {
  final DateTime mfg = parseDate('mfg_date', mfgDate);
  final DateTime exp = parseDate('expiry_date', expiryDate);
  if (!exp.isAfter(mfg)) {
    throw payloadInvalid(
      'expiry_date $expiryDate must be after mfg_date $mfgDate',
    );
  }
}

/// Parse an RFC 3339 instant.
///
/// The regex pins the format before [DateTime.parse] sees it, for the same
/// reason as above: a timestamp of `2026-08-21 10:00` (space, no zone) would
/// otherwise be read in the *phone's* local time, silently shifting a
/// temperature reading by hours and moving an excursion out of the window a
/// regulator is looking at.
DateTime parseInstant(String field, Object? value) {
  if (value is! String || !rfc3339Re.hasMatch(value)) {
    throw validationError(
      '$field must be an RFC 3339 timestamp with a timezone, '
      'e.g. 2026-08-21T10:00:00Z (got ${_show(value)})',
    );
  }
  final DateTime? parsed = DateTime.tryParse(value);
  if (parsed == null) {
    throw validationError('$field is not a valid instant: $value');
  }
  return parsed.toUtc();
}

/// RFC 3339 UTC, second precision — the format every timestamp uses on the wire.
///
/// Built by hand rather than by slicing [DateTime.toIso8601String], which emits
/// milliseconds and, for a non-UTC DateTime, no zone designator at all. Slicing
/// the first 19 characters of a local-time ISO string and appending `Z` is a
/// silent timezone bug: it would relabel 15:30 IST as 15:30 UTC.
String stamp([DateTime? when]) {
  final DateTime utc = (when ?? DateTime.now()).toUtc();
  final String y = utc.year.toString().padLeft(4, '0');
  final String mo = utc.month.toString().padLeft(2, '0');
  final String d = utc.day.toString().padLeft(2, '0');
  final String h = utc.hour.toString().padLeft(2, '0');
  final String mi = utc.minute.toString().padLeft(2, '0');
  final String s = utc.second.toString().padLeft(2, '0');
  return '$y-$mo-${d}T$h:$mi:${s}Z';
}

// ── Field validation ─────────────────────────────────────────────────────────

/// A control character found in a string, with where it was found.
class ControlChar {
  const ControlChar(this.codePoint, this.index);

  final int codePoint;
  final int index;

  String get label =>
      'U+${codePoint.toRadixString(16).padLeft(4, '0').toUpperCase()}';
}

/// Find the first C0/C1 control character, or return null.
///
/// Checked by code point rather than with a regex character class on purpose: a
/// class written as literal control bytes is invisible in a diff and easy for an
/// editor to mangle, and one written with escapes is easy to get subtly wrong.
///
/// Iterates runes, so the index is a character position a person could count to
/// rather than a UTF-16 offset that lands mid-surrogate.
ControlChar? findControlChar(String value) {
  int index = 0;
  for (final int rune in value.runes) {
    final bool isC0 = rune < 0x20;
    final bool isDelOrC1 = rune >= 0x7f && rune <= 0x9f;
    if (isC0 || isDelOrC1) return ControlChar(rune, index);
    index += 1;
  }
  return null;
}

/// Reject C0/C1 control characters in a field being sent to the API.
///
/// A newline or NUL is how log injection and payload smuggling start, and no
/// legitimate excipient, pharmacy name or location ID contains one.
void rejectControlChars(String field, String value) {
  final ControlChar? found = findControlChar(value);
  if (found != null) {
    throw validationError(
      '$field contains a control character (${found.label}); '
      'control characters are not permitted',
    );
  }
}

/// Trim, reject empty, reject control characters, enforce the code-point limit.
///
/// Length is counted in runes, not UTF-16 units, so a Devanagari pharmacy name is
/// measured the way a person would count its characters. `'क्षि'.length` is 4 in
/// Dart but three characters to the person typing it, and a limit that disagrees
/// with the user about what they typed is a limit they cannot satisfy.
String validateText(String field, Object? value, {int? max}) {
  if (value is! String) {
    throw validationError('$field must be a string, got ${value.runtimeType}');
  }
  final String trimmed = value.trim();
  if (trimmed.isEmpty) throw validationError('$field must not be empty');
  rejectControlChars(field, trimmed);
  final int? limit = max ?? limits[field];
  final int length = trimmed.runes.length;
  if (limit != null && length > limit) {
    throw validationError(
      '$field is $length characters, over the $limit-character limit',
    );
  }
  return trimmed;
}

String validateProductID(Object? value) {
  final String text =
      validateText('product_id', value, max: limits['product_id']);
  if (!productIdRe.hasMatch(text)) {
    throw validationError(
      'product_id ${_show(text)} is not in the form GENERIC_BRAND_YEAR_SERIAL '
      '(e.g. PARACETAMOL500MG_PARACIP500_2026_000001)',
    );
  }
  return text;
}

/// Batch numbers are manufacturer-defined (§5), so no character set is imposed —
/// only length and the control-character rule that every signed field gets.
///
/// Restricting these would be wrong twice over: `batch_no` is signed wire data,
/// so anything the Python signer accepts must verify here, and a regulator
/// issuing a recall has to be able to name *any* batch that exists on chain. A
/// recall that cannot be issued because the manufacturer put a space in their
/// batch number is a recall that does not happen.
String validateBatchNo(Object? value) =>
    validateText('batch_no', value, max: limits['batch_no']);

/// Location IDs follow §5: `{TYPE}_{CITY}_{NNN}`.
///
/// Enforced rather than accepted as free text because Grafana groups by this
/// value. `PHARM_MUM_0142`, `pharm mum 142` and `Pharmacy Mumbai 142` are one
/// place to a human and three rows on a dashboard.
String validateLocation(Object? value) {
  final String text = validateText('location', value, max: limits['location']);
  if (!locationRe.hasMatch(text)) {
    throw validationError(
      'location ${_show(text)} must be uppercase in the form TYPE_CITY_NNN, '
      'e.g. FACTORY_PUNE_01, WH_MUM_001, PHARM_MUM_0142',
    );
  }
  return text;
}

String validateSensorID(Object? value) {
  final String text =
      validateText('sensor_id', value, max: limits['sensor_id']).toUpperCase();
  if (!sensorIdRe.hasMatch(text)) {
    throw validationError('sensor_id ${_show(text)} must look like TM-SENSOR-001');
  }
  return text;
}

/// Custody may move forward, or stay on `in_transit` for another hop. §3.1.
///
/// The app enforces this locally so a pharmacist gets an immediate, specific
/// message instead of a round trip that ends in VALIDATION_ERROR. The server and
/// the chaincode enforce it too — this copy is for the user's benefit, never for
/// the system's.
const Map<String, int> _statusRank = <String, int>{
  Status.manufactured: 0,
  Status.inTransit: 1,
  Status.atPharmacy: 2,
  Status.dispensed: 3,
};

String validateTransition(String from, String to) {
  if (!Status.isKnown(to)) {
    throw validationError(
      'status ${_show(to)} is not one of ${Status.all.join(', ')}',
    );
  }
  if (to == Status.recalled) {
    throw validationError(
      'a recall may only be applied through POST /api/recall by the regulator, '
      'never as a custody update',
    );
  }
  if (Status.isTerminal(from)) {
    throw validationError('$from is terminal; this unit cannot move to $to');
  }
  final int? rankFrom = _statusRank[from];
  final int? rankTo = _statusRank[to];
  if (rankFrom == null) {
    throw validationError('current status ${_show(from)} is not recognised');
  }
  if (rankTo == null) {
    throw validationError('status ${_show(to)} has no defined ordering');
  }
  if (rankTo < rankFrom) {
    throw validationError('cannot move backwards from $from to $to');
  }
  if (rankTo == rankFrom && to != Status.inTransit) {
    throw validationError(
      'unit is already $from; only in_transit may repeat, for a further hop',
    );
  }
  return to;
}

double validateTemperature(Object? value) {
  if (value is! num || !value.isFinite) {
    throw validationError('temperature must be a finite number in degrees Celsius');
  }
  final double celsius = value.toDouble();
  if (celsius < sensorTempMinC || celsius > sensorTempMaxC) {
    throw validationError(
      'temperature $celsius C is outside the DS18B20 rated range '
      '$sensorTempMinC..$sensorTempMaxC C, so it is a sensor or wiring fault '
      'rather than a cold-chain reading',
    );
  }
  return celsius;
}

/// `JSON.stringify(value)`-style quoting for error messages, so an empty string
/// or a trailing space is visible in the text a developer reads.
String _show(Object? value) {
  if (value == null) return 'null';
  if (value is String) return '"$value"';
  return value.toString();
}
