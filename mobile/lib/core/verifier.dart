/// Offline verification, and how a server's verdict is folded into it.
///
/// Dart mirror of `backend/src/core/verifier.js` and
/// `qr-generator/truemed_qr/verifier.py`, which is the authoritative definition of
/// what "verified" means in TrueMed.
///
/// # What offline verification can and cannot prove
///
/// A valid signature proves the payload was produced by the holder of the private
/// key registered to that manufacturing licence. It does **not** prove the strip
/// in the patient's hand is genuine, because a counterfeiter can photograph one
/// authentic strip and reprint its perfectly-valid QR onto ten thousand fakes.
/// Cloning is the standard attack on every QR authentication scheme, and no
/// amount of cryptography applied to a static printed square prevents it.
///
/// TrueMed's answer is on-chain scan telemetry — one sellable unit scanned four
/// hundred times across fourteen districts is almost certainly cloned — and that
/// signal exists only online. So a successful offline check yields
/// SIGNATURE_VALID_OFFLINE at severity `warn`, never GENUINE at `ok`. Showing an
/// offline success as an unqualified green tick would be a lie of omission in a
/// safety-critical interface, and DATA-CONTRACT.md §2.2 fixes the wording the app
/// must use instead — see [offlineHeadline].
///
/// # Why the client does not merge chain evidence, and what it does instead
///
/// The server's `mergeOnlineEvidence` folds raw Fabric state — custody events,
/// temperature readings, scan counts — into a verdict. This file has no equivalent
/// and deliberately so: the app receives a *verdict*, not evidence, and rebuilding
/// one from the other in Dart would mean reimplementing the chaincode's rules a
/// third time, in the one language that cannot be tested against Fabric.
///
/// What the client does instead is [mergeServerVerdict], and it is the more
/// important half of the design. **The local verdict is a floor, never a ceiling.**
/// The app verifies the ECDSA signature itself, against a key it learned from a
/// root-signed bundle pinned in its own binary, and then takes the *worse* of its
/// own verdict and the server's. A compromised or impersonated API can therefore
/// make a genuine strip look suspicious — annoying, and visible — but it cannot
/// make a forgery look genuine, which is the attack that matters. Any design where
/// the app simply renders whatever the server says throws away the entire benefit
/// of doing cryptography on the phone.
library;

import 'codec.dart';
import 'ecdsa.dart';
import 'errors.dart';
import 'payload.dart';
import 'rules.dart';
import 'trust_bundle.dart';

/// Mirrors the caveat string in `verifier.js` so the three implementations agree.
const String offlineCaveat =
    'Offline verification only. The signature is authentic, but duplicate-scan '
    'and cold-chain checks require an internet connection.';

/// The exact sentence DATA-CONTRACT.md §2.2 requires when a scan succeeded
/// offline.
///
/// Pinned in code rather than left to the widget tree because the contract fixes
/// it: the app must not imply the item is confirmed genuine, and it must tell the
/// user what connecting would add. The emphasis markers are stripped by the caller
/// that renders it; the words are what is fixed.
String offlineHeadline(String manufacturer) =>
    'Signature verified. This QR was issued by $manufacturer. Connect to the '
    'internet to confirm it is not a duplicate and to check cold-chain status.';

/// The outcome of verifying one scan.
///
/// Immutable. A verdict is computed on one frame and rendered on a later one, so a
/// mutable result could describe something other than what the user is holding by
/// the time they read it.
class VerificationResult {
  VerificationResult({
    required this.valid,
    required this.verdict,
    this.error,
    this.errorCode,
    required Map<String, String> checks,
    List<String> warnings = const <String>[],
    this.medicine,
    this.signingKeyFingerprint,
    this.daysToExpiry,
    this.onChainStatus,
    this.scanCount,
    this.distinctDistricts,
    this.fromServer = false,
  })  : checks = Map<String, String>.unmodifiable(checks),
        warnings = List<String>.unmodifiable(warnings),
        severity = severityFor(verdict);

  /// True only for [Verdict.genuine]. Note that an offline success is *not*
  /// valid in this sense: SIGNATURE_VALID_OFFLINE is a warn-level partial result.
  final bool valid;

  final String verdict;

  /// Derived from [verdict], never passed in — one function decides colour.
  final String severity;

  /// Machine-readable reason, from [Codes]. Null when there is nothing wrong.
  final String? errorCode;

  /// Log-safe prose. Not patient-facing; the UI maps [verdict] to its own text.
  final String? error;

  /// One of [Check] per [CheckName]. Every entry is always present, so a UI can
  /// render six rows without null-checking each.
  final Map<String, String> checks;

  final List<String> warnings;

  /// The parsed payload, when the QR got far enough to produce one. Null for a
  /// malformed frame.
  final MedicineData? medicine;

  /// Which trusted key verified this, for the details screen and for reports.
  final String? signingKeyFingerprint;

  final int? daysToExpiry;

  /// Custody status from the chain. Null until a server verdict is merged.
  final String? onChainStatus;

  final int? scanCount;
  final int? distinctDistricts;

  /// True once server evidence has been folded in, so the UI knows whether to
  /// offer "check online" or "checked online".
  final bool fromServer;

  bool get isOffline => !fromServer;

  /// True when the signature check itself passed, regardless of the final verdict.
  ///
  /// An expired strip or a recalled batch still has an authentic signature, and
  /// the details screen says so — conflating "authentic" with "usable" is how a
  /// pharmacist ends up dispensing an expired vial because the app was green.
  bool get signatureVerified => checks[CheckName.signature] == Check.pass;

  VerificationResult copyWith({
    bool? valid,
    String? verdict,
    String? error,
    String? errorCode,
    Map<String, String>? checks,
    List<String>? warnings,
    MedicineData? medicine,
    String? signingKeyFingerprint,
    int? daysToExpiry,
    String? onChainStatus,
    int? scanCount,
    int? distinctDistricts,
    bool? fromServer,
  }) {
    return VerificationResult(
      valid: valid ?? this.valid,
      verdict: verdict ?? this.verdict,
      error: error ?? this.error,
      errorCode: errorCode ?? this.errorCode,
      checks: checks ?? this.checks,
      warnings: warnings ?? this.warnings,
      medicine: medicine ?? this.medicine,
      signingKeyFingerprint:
          signingKeyFingerprint ?? this.signingKeyFingerprint,
      daysToExpiry: daysToExpiry ?? this.daysToExpiry,
      onChainStatus: onChainStatus ?? this.onChainStatus,
      scanCount: scanCount ?? this.scanCount,
      distinctDistricts: distinctDistricts ?? this.distinctDistricts,
      fromServer: fromServer ?? this.fromServer,
    );
  }

  /// For logs and for the diagnostics screen. Deliberately not the API's `data`
  /// shape — that is `api/models.dart`'s job.
  Map<String, Object?> toDebugMap() => <String, Object?>{
        'valid': valid,
        'verdict': verdict,
        'severity': severity,
        'error_code': errorCode,
        'error': error,
        'checks': checks,
        'warnings': warnings,
        'product_id': medicine?.productId,
        'signing_key_fingerprint': signingKeyFingerprint,
        'days_to_expiry': daysToExpiry,
        'on_chain_status': onChainStatus,
        'scan_count': scanCount,
        'distinct_districts': distinctDistricts,
        'from_server': fromServer,
      };

  @override
  String toString() => 'VerificationResult($verdict/$severity, '
      'product ${medicine?.productId ?? "unknown"})';
}

/// Every check starts as "not evaluated" and is only set once it actually runs.
///
/// The three online checks start as `skipped_offline` rather than `not_evaluated`
/// because on this device that is the truth: they were not attempted, and the
/// reason is the network. A row reading "not evaluated" invites the reader to
/// wonder what went wrong.
Map<String, String> _freshChecks() => <String, String>{
      CheckName.structure: Check.notEvaluated,
      CheckName.signature: Check.notEvaluated,
      CheckName.expiry: Check.notEvaluated,
      CheckName.onChain: Check.skippedOffline,
      CheckName.coldChain: Check.skippedOffline,
      CheckName.cloneTelemetry: Check.skippedOffline,
    };

VerificationResult _failure(
  TrueMedException err,
  String verdict,
  Map<String, String> checks, {
  MedicineData? medicine,
  DateTime? today,
  String? keyFingerprint,
}) {
  return VerificationResult(
    valid: false,
    verdict: verdict,
    error: err.message,
    errorCode: err.code,
    checks: checks,
    medicine: medicine,
    signingKeyFingerprint: keyFingerprint,
    daysToExpiry:
        medicine == null ? null : medicine.daysRemaining(asOf: today),
  );
}

/// Verify a scanned `TM1...` string offline: contract checks 1-3, being structure,
/// signature and expiry.
///
/// Checks 4 and 5 — on-chain existence and cold chain — need the network; feed the
/// result to [mergeServerVerdict] once the API has answered.
///
/// Mirrors `verifyWire` in `verifier.js` step for step, including which failures
/// are amber and which are red. Those two decisions are the whole design:
///
/// - A frame that will not decode is **UNVERIFIABLE**, not counterfeit. Far more
///   often it is the shop's UPI QR, a damaged label, or an app older than the
///   format than it is a forgery.
/// - A frame that decodes but whose payload will not parse is **COUNTERFEIT**. QR
///   error correction at level H makes silent corruption that still base64-decodes
///   vanishingly unlikely, so this is fabrication, not a bad scan.
/// - A signature that cannot be checked because no key is held is **UNVERIFIABLE**.
/// - A signature that is checked and fails is **COUNTERFEIT**.
///
/// Non-[TrueMedException] errors propagate, as in the Node original. Call
/// [verifyWireSafe] from UI code, which has nowhere to propagate them to.
VerificationResult verifyWireOffline(
  String? wire,
  TrustBundle bundle, {
  DateTime? today,
}) {
  final DateTime now = today ?? DateTime.now();
  final Map<String, String> checks = _freshChecks();

  // ── Check 1a: wire structure ───────────────────────────────────────────────
  WireFrame decoded;
  try {
    decoded = decodeWire(wire);
  } on TrueMedException catch (err) {
    checks[CheckName.structure] = Check.fail;
    return _failure(err, Verdict.unverifiable, checks);
  }

  // ── Check 1b: payload well-formedness ──────────────────────────────────────
  MedicineData medicine;
  try {
    medicine = MedicineData.fromCanonicalJSON(decoded.payloadBytes);
  } on TrueMedException catch (err) {
    checks[CheckName.structure] = Check.fail;
    return _failure(err, Verdict.counterfeit, checks);
  }
  checks[CheckName.structure] = Check.pass;

  // ── Check 2: signature ─────────────────────────────────────────────────────
  TrueMedPublicKey publicKey;
  try {
    publicKey = bundle.publicKeyFor(medicine.mfgLicenceNo, now);
  } on TrueMedException catch (err) {
    if (err.code != Codes.signatureKeyUnknown) rethrow;
    // Deliberately UNVERIFIABLE (amber), not COUNTERFEIT (red).
    //
    // A stale key list is far more likely than a forgery here, and showing red on
    // genuine medicine because the app has not refreshed its keys would destroy
    // patient trust in the whole system — the failure mode that actually kills
    // adoption. Amber, with "could not verify, update the app", is honest and
    // safe: nothing has been asserted to be genuine. The signature check is left
    // at `not_evaluated`, because it truly was not run.
    return _failure(
      err,
      Verdict.unverifiable,
      checks,
      medicine: medicine,
      today: now,
    );
  }

  // Verified over `decoded.payloadBytes` — the bytes as received. Never over
  // `medicine.canonicalJSON()`, which would be this app's re-serialisation of its
  // own parse, and would let any parser/serialiser disagreement through as a
  // forged-payload bypass. §1.5.
  if (!verifySignature(publicKey, decoded.payloadBytes, decoded.signatureBytes)) {
    checks[CheckName.signature] = Check.fail;
    return VerificationResult(
      valid: false,
      verdict: Verdict.counterfeit,
      error: 'the signature does not match this payload under the registered '
          'key for licence ${medicine.mfgLicenceNo} - treat as counterfeit',
      errorCode: Codes.signatureInvalid,
      checks: checks,
      medicine: medicine,
      signingKeyFingerprint: publicKey.fingerprint,
      daysToExpiry: medicine.daysRemaining(asOf: now),
    );
  }
  checks[CheckName.signature] = Check.pass;

  // ── Check 3: expiry ────────────────────────────────────────────────────────
  final int daysLeft = medicine.daysRemaining(asOf: now);
  if (medicine.expired(asOf: now)) {
    final int days = -daysLeft;
    checks[CheckName.expiry] = Check.fail;
    return VerificationResult(
      valid: false,
      verdict: Verdict.expired,
      error: 'expired $days day${days == 1 ? '' : 's'} ago on '
          '${medicine.expiryDate}',
      errorCode: Codes.expired,
      checks: checks,
      medicine: medicine,
      signingKeyFingerprint: publicKey.fingerprint,
      daysToExpiry: daysLeft,
    );
  }
  checks[CheckName.expiry] = Check.pass;

  // ── Offline path complete ──────────────────────────────────────────────────
  final List<String> warnings = <String>[offlineCaveat];
  if (daysLeft <= 30) {
    warnings.add('Expires in $daysLeft days on ${medicine.expiryDate}.');
  }

  return VerificationResult(
    valid: true,
    verdict: Verdict.offlineOk,
    checks: checks,
    medicine: medicine,
    signingKeyFingerprint: publicKey.fingerprint,
    daysToExpiry: daysLeft,
    warnings: warnings,
  );
}

/// [verifyWireOffline] with a floor under it: no exception escapes.
///
/// The UI calls this one. A verification path that can throw an unexpected
/// exception into a widget build is a scan screen that shows a red Flutter error
/// box to a pharmacist, which is both useless and alarming. An unexpected failure
/// is reported as UNVERIFIABLE — the app could not verify this, which is exactly
/// what has happened — while [verifyWireOffline] stays strict so that the test
/// suite still sees real bugs instead of amber banners.
VerificationResult verifyWireSafe(
  String? wire,
  TrustBundle bundle, {
  DateTime? today,
}) {
  try {
    return verifyWireOffline(wire, bundle, today: today);
  } on TrueMedException catch (err) {
    final Map<String, String> checks = _freshChecks();
    return _failure(err, Verdict.unverifiable, checks);
  } catch (err) {
    final Map<String, String> checks = _freshChecks();
    return VerificationResult(
      valid: false,
      verdict: Verdict.unverifiable,
      error: 'verification failed unexpectedly: $err',
      errorCode: Codes.internalError,
      checks: checks,
    );
  }
}

/// Fold a server verdict into a local offline result, taking the worse of the two.
///
/// The parameters are primitives rather than an API model on purpose: `core/` must
/// stay free of anything that needs a socket, so it can be tested with nothing but
/// `flutter test`. `api/models.dart` unpacks the §4.4 response and calls this.
///
/// Three rules, in order of importance:
///
/// 1. **A local COUNTERFEIT or UNVERIFIABLE is never upgraded.** If this app could
///    not verify the signature, no amount of reassurance from the network changes
///    that, and a server that says GENUINE over a signature this app just watched
///    fail is either compromised or being impersonated.
/// 2. **The final verdict is [worstVerdict] of both.** The server sees what the
///    phone cannot (clone telemetry, cold chain, recalls) and the phone sees what
///    the server cannot be trusted about (the signature). Neither is authoritative
///    alone, and the pessimistic fold is the only combination that is safe in both
///    directions.
/// 3. **Online checks are copied from the server, local checks are not.** The app
///    has no way to evaluate `on_chain` itself, and the server's opinion of
///    `signature` is irrelevant — on `POST /api/verify/payload` it is
///    `skipped_no_payload` in any case.
VerificationResult mergeServerVerdict(
  VerificationResult offline, {
  required String serverVerdict,
  String? serverError,
  String? serverErrorCode,
  Map<String, String> serverChecks = const <String, String>{},
  List<String> serverWarnings = const <String>[],
  String? onChainStatus,
  int? scanCount,
  int? distinctDistricts,
  DateTime? today,
}) {
  // Rule 1. A forged or unreadable code cannot be rescued by chain data, and this
  // is also what stops a hostile API from clearing a forgery. `fromServer` is set
  // anyway so the UI does not keep offering "check online" for a scan that was
  // already checked, but nothing else the server said is folded in.
  if (offline.verdict == Verdict.counterfeit ||
      offline.verdict == Verdict.unverifiable) {
    return offline.copyWith(fromServer: true);
  }

  final Map<String, String> checks = Map<String, String>.of(offline.checks);
  // Only the three network-only checks are taken from the server. `structure`,
  // `signature` and `expiry` were established locally, from bytes, and the server
  // does not get a vote on them.
  for (final String name in <String>[
    CheckName.onChain,
    CheckName.coldChain,
    CheckName.cloneTelemetry,
  ]) {
    final String? value = serverChecks[name];
    if (value != null) checks[name] = value;
  }

  // Rule 2. An unrecognised verdict is demoted to UNVERIFIABLE *before* ranking,
  // because worstVerdict can only rank the values it knows and would otherwise
  // drop it silently — so a critical verdict added to the API after this APK
  // shipped would be discarded and the scan would render amber. Demoting it
  // instead means an old app says "could not verify, update TrueMed", which is
  // both true and safe.
  final String ranked =
      Verdict.isKnown(serverVerdict) ? serverVerdict : Verdict.unverifiable;
  final String finalVerdict = worstVerdict(<String>[offline.verdict, ranked]);

  final List<String> warnings = <String>[
    // The offline caveat no longer applies once there is chain evidence.
    ...offline.warnings.where((String w) => w != offlineCaveat),
    ...serverWarnings,
  ];

  final List<String> errors = <String>[
    if (offline.error != null) offline.error!,
    if (serverError != null && serverError.isNotEmpty) serverError,
  ];

  // Prefer the server's own code when the server's verdict is the one that won.
  //
  // Deriving the code from the verdict unconditionally would be lossy in a way
  // that matters: verdictToErrorCode(COUNTERFEIT) is SIGNATURE_INVALID, so a unit
  // the chain has never heard of would be reported as a bad signature rather than
  // NOT_ON_CHAIN. Those are different accusations — one says the QR was forged,
  // the other says it was minted with a leaked key — and the UI and the
  // counterfeit report both switch on the code. When the *local* verdict won, the
  // server's code describes something that did not decide this outcome, so it is
  // derived instead.
  final String? finalErrorCode;
  if (finalVerdict == ranked &&
      serverErrorCode != null &&
      serverErrorCode.isNotEmpty) {
    finalErrorCode = serverErrorCode;
  } else {
    finalErrorCode = verdictToErrorCode(finalVerdict);
  }

  return VerificationResult(
    valid: finalVerdict == Verdict.genuine,
    verdict: finalVerdict,
    error: errors.isEmpty ? null : errors.join('; '),
    errorCode: finalErrorCode,
    checks: checks,
    warnings: warnings,
    medicine: offline.medicine,
    signingKeyFingerprint: offline.signingKeyFingerprint,
    daysToExpiry: offline.medicine?.daysRemaining(asOf: today) ??
        offline.daysToExpiry,
    onChainStatus: onChainStatus,
    scanCount: scanCount,
    distinctDistricts: distinctDistricts,
    fromServer: true,
  );
}

/// Build a result for the case where the network failed outright.
///
/// Not an error state in this app. Most of the country TrueMed is built for has
/// intermittent connectivity, so "no signal" is the normal case and the offline
/// result stands on its own — with the caveat kept, and one line explaining why
/// the online checks are blank.
VerificationResult withNetworkFailure(
  VerificationResult offline,
  TrueMedException failure,
) {
  if (!failure.isTransportFailure) return offline;
  return offline.copyWith(
    warnings: <String>[
      ...offline.warnings,
      'Could not reach the TrueMed service, so duplicate-scan and cold-chain '
          'checks were not performed. This does not mean anything is wrong with '
          'the medicine.',
    ],
  );
}
