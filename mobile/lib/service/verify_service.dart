/// The one place a scan becomes a verdict.
///
/// Everything below this file is a pure function or a store; everything above it
/// is a widget. This is the seam: it takes a scanned string, runs data contract
/// §2.1's five checks across the two halves that can run them — the phone for
/// checks 1-3, the API for checks 4-5 — folds the two results together, writes the
/// outcome to [ScanHistory], and hands the UI a [VerificationOutcome] it can render
/// without making any further decisions.
///
/// # The two rules that bind this file
///
/// **1. The fold may only make a verdict more severe.** The signature check happens
/// on the phone against a root key pinned in the binary, so it is the one piece of
/// evidence a compromised API cannot touch. Every merge here goes through
/// [worstVerdict], directly or via [mergeServerVerdict], so the server can raise a
/// verdict (a recall, a cold-chain breach, clone telemetry) and can never lower one.
/// A hostile API can make genuine medicine look suspicious. It cannot clear a
/// forgery.
///
/// **2. A failed API call can never produce GENUINE and can never produce
/// COUNTERFEIT.** It leaves the offline verdict standing, with the offline caveat
/// attached and one line explaining what was not checked. `GENUINE` requires chain
/// evidence, so it is unreachable without a response; `COUNTERFEIT` is an
/// accusation, and "the network is down" is not evidence about anyone's medicine.
/// [_afterApiFailure] enforces both as a data invariant rather than trusting the
/// call order.
///
/// Note on wording: the phase brief for this file says an API failure yields
/// `UNVERIFIABLE`. That is right when the phone could not verify the signature
/// either — and in that case the offline verdict already *is* `UNVERIFIABLE`. When
/// the signature did verify, §2.2 fixes the verdict at `SIGNATURE_VALID_OFFLINE`
/// with severity `warn` and fixes the wording too, so that is what stands. Both are
/// amber, neither is a green tick, and §2.2 is the frozen contract.
///
/// # Three paths, and why they are not one
///
/// - **A payload with a trust bundle** — the normal patient scan.
///   [verifyWireSafe] then [mergeServerVerdict], used exactly as written.
/// - **A payload with no trust bundle** — a fresh install that has never been
///   online, or a device whose key list was discarded as a rollback. The phone can
///   parse the QR but cannot check its signature, so the local verdict is
///   `UNVERIFIABLE`, and `trust_store.dart` is explicit that it must stay that way.
///   This path folds the server result with [worstVerdict] directly instead of
///   calling [mergeServerVerdict], whose rule 1 short-circuits on a local
///   `UNVERIFIABLE` and would therefore discard a server `RECALLED` — turning a red
///   recall into an amber shrug on precisely the devices least likely to have heard
///   about the recall by any other route.
/// - **A bare product ID** — a pharmacist typing a code off a carton, or a re-check
///   from history. There is no signature to check and so no local floor at all; the
///   server's verdict stands on its own, and the `signature` row reads
///   `skipped_no_payload` so the UI cannot present it as a verified one.
library;

import 'dart:async';

import '../api/client.dart';
import '../api/models.dart';
import '../core/errors.dart';
import '../core/payload.dart';
import '../core/rules.dart';
import '../core/trust_bundle.dart';
import '../core/verifier.dart';
import '../store/scan_history.dart';
import '../store/trust_store.dart';

/// How far a verification got, so the UI can say so without inspecting nulls.
enum VerifySource {
  /// The phone only: the API was not reached, or was not asked.
  offline,

  /// Offline evidence and a server response, folded.
  merged,

  /// The server only, because the scan carried no payload to verify.
  server,
}

/// One verified scan, with everything the screens need attached.
///
/// [result] is the verdict and is the only thing that decides colour. The rest is
/// context: the raw server response for the details and temperature screens, the
/// failure for the offline banner, the payload so a report can be filed later.
class VerificationOutcome {
  const VerificationOutcome({
    required this.result,
    required this.source,
    this.online,
    this.failure,
    this.rawPayload,
    this.record,
    this.trustSource,
  });

  final VerificationResult result;
  final VerifySource source;

  /// The §4.4 response, or null when the API was not reached.
  final OnlineVerification? online;

  /// Why the API was not reached. Null when it was.
  final TrueMedException? failure;

  /// The scanned string, kept so the report screen can submit the exact bytes.
  /// Null for a bare product-ID lookup.
  final String? rawPayload;

  /// The history entry written for this scan, or null when nothing was recorded.
  final ScanRecord? record;

  /// Where the key list in force came from, for the diagnostics screen.
  final TrustSource? trustSource;

  String get verdict => result.verdict;

  String get severity => result.severity;

  /// The signed payload when there was one, otherwise whatever the chain holds.
  MedicineData? get medicine => result.medicine ?? online?.medicine;

  String? get productId => medicine?.productId ?? record?.productId;

  List<String> get warnings => result.warnings;

  Map<String, String> get checks => result.checks;

  bool get checkedOnline => online != null;

  /// True when the API was tried and the network was the reason it failed, which is
  /// the case the offline banner is for. A rate-limited or malformed response is a
  /// different message.
  bool get networkFailed => failure != null && failure!.isTransportFailure;

  bool get isVaccine => medicine?.isVaccine ?? false;

  ColdChainStatus get coldChain =>
      online?.coldChain ?? ColdChainStatus.notApplicable;

  ScanTelemetry get telemetry => online?.telemetry ?? ScanTelemetry.empty;

  List<CustodyEvent> get custodyTrail =>
      online?.custodyTrail ?? const <CustodyEvent>[];

  /// A verdict computed from a cached response can be up to an hour old (§4.6),
  /// which matters when the question is whether a recall has landed.
  bool get cached => online?.cached ?? false;

  String? get onChainStatus => result.onChainStatus ?? online?.onChainStatus;

  String? get currentLocation => online?.currentLocation;

  /// Only [Verdict.genuine] is a green tick. An offline success is not.
  bool get isGenuine => result.verdict == Verdict.genuine;

  bool get needsAttention => result.severity != Severity.ok;

  /// A report needs something to report about. A frame that never decoded has no
  /// product ID, and `POST /api/report` requires one.
  bool get canReport {
    final String? id = productId;
    return id != null && id.isNotEmpty;
  }

  Map<String, Object?> toDebugMap() => <String, Object?>{
        'source': source.name,
        'trust_source': trustSource?.name,
        'network_failed': networkFailed,
        'failure_code': failure?.code,
        'cached': cached,
        'took_ms': online?.tookMs,
        'result': result.toDebugMap(),
      };

  @override
  String toString() =>
      'VerificationOutcome(${result.verdict}, ${source.name})';
}

/// Verification, as the screens see it.
///
/// Holds no state of its own. The trust bundle lives in [TrustStore] and the
/// history in [ScanHistory], both of which are `ChangeNotifier`s the widgets listen
/// to directly, so this class stays a set of operations rather than a third copy of
/// the truth.
class VerifyService {
  VerifyService({
    required TrueMedApi api,
    required TrustStore trust,
    required ScanHistory history,
  })  : _api = api,
        _trust = trust,
        _history = history;

  final TrueMedApi _api;
  final TrustStore _trust;
  final ScanHistory _history;

  TrustStore get trust => _trust;

  ScanHistory get history => _history;

  /// Load both stores, then start a key-list refresh without waiting for it.
  ///
  /// The refresh is deliberately not awaited. It is a network call on a connection
  /// that may not exist, and blocking the first frame on it would mean an app that
  /// takes eight seconds to open in exactly the places it is meant for. The store
  /// notifies its listeners when a newer list lands, and the scan after that one
  /// uses it. Never throws: a launch path that can throw is a launch path that can
  /// brick the app.
  Future<void> start() async {
    if (!_trust.isLoaded) await _trust.load();
    if (!_history.isLoaded) await _history.load();
    unawaited(_refreshQuietly(force: false));
  }

  /// Fetch the key list now, for the diagnostics screen's update button. Returns
  /// true only when the list in force changed.
  Future<bool> refreshTrust({bool force = true}) =>
      _refreshQuietly(force: force);

  Future<bool> _refreshQuietly({required bool force}) async {
    try {
      return await _trust.refresh(_api, force: force);
    } on Object {
      // TrustStore.refresh already records its own failures for the diagnostics
      // screen and never throws by design. This is the floor under that promise:
      // an unhandled async error from a background refresh must not reach the
      // Flutter error handler and look like a crash.
      return false;
    }
  }

  /// Verify a scanned `TM1....` string. The whole patient path, in one call.
  ///
  /// [scanned] is passed to the API exactly as scanned — not trimmed, upcased or
  /// re-encoded — because the server verifies the signature over the bytes it
  /// receives (§1.5), and normalising on the way would break a signature over a
  /// payload that is in fact authentic.
  ///
  /// Set [useNetwork] to false to skip the API entirely, and [remember] to false
  /// to keep the scan out of the on-device history.
  Future<VerificationOutcome> verifyScan(
    String? scanned, {
    DateTime? today,
    bool useNetwork = true,
    bool remember = true,
  }) async {
    final DateTime now = today ?? DateTime.now();

    // A keyless bundle rather than a special case. `publicKeyFor` throws
    // SIGNATURE_KEY_UNKNOWN for a licence it does not hold, which verifyWireOffline
    // turns into UNVERIFIABLE with the parsed medicine attached — which is exactly
    // what a device with no key list should show. Reimplementing checks 1 and 2 here
    // for the no-bundle case would be a second copy of the two decisions that matter
    // most in the whole app.
    final bool haveBundle = _trust.hasBundle;
    final VerificationResult offline = verifyWireSafe(
      scanned,
      _trust.current ?? _emptyBundle(),
      today: now,
    );

    // The network is only worth asking once the payload has parsed. A frame that
    // did not decode is most often the shop's UPI QR, and posting a stranger's
    // payment code to the TrueMed API would be both pointless load and a small
    // privacy leak. A payload that decoded but would not parse is fabricated and
    // carries no product ID for the heat map either.
    final bool parsed = offline.checks[CheckName.structure] == Check.pass;
    if (!useNetwork || !parsed || scanned == null) {
      return _finish(
        offline,
        source: VerifySource.offline,
        now: now,
        remember: remember,
        rawPayload: scanned,
      );
    }

    final OnlineVerification server;
    try {
      server = await _api.verifyPayload(scanned);
    } on TrueMedException catch (err) {
      return _finish(
        _afterApiFailure(offline, err),
        source: VerifySource.offline,
        now: now,
        remember: remember,
        failure: err,
        rawPayload: scanned,
      );
    } on Object catch (err) {
      // A bug in this app must not be reportable as bad signal, so it gets
      // INTERNAL_ERROR rather than NETWORK_UNAVAILABLE. The verdict is unaffected:
      // _afterApiFailure treats every failure the same way.
      final TrueMedException wrapped = TrueMedException(
        Codes.internalError,
        'the online check failed unexpectedly: $err',
      );
      return _finish(
        _afterApiFailure(offline, wrapped),
        source: VerifySource.offline,
        now: now,
        remember: remember,
        failure: wrapped,
        rawPayload: scanned,
      );
    }

    final VerificationResult merged = haveBundle
        ? mergeServerVerdict(
            offline,
            serverVerdict: server.verdict,
            serverError: server.errorMessage,
            serverErrorCode: server.errorCode,
            serverChecks: server.checks,
            serverWarnings: server.warnings,
            onChainStatus: server.onChainStatus,
            scanCount: server.telemetry.scanCount,
            distinctDistricts: server.telemetry.distinctDistricts,
            today: now,
          )
        : _foldOntoUnverified(offline, server, now: now);

    return _finish(
      merged,
      source: VerifySource.merged,
      now: now,
      remember: remember,
      online: server,
      rawPayload: scanned,
    );
  }

  /// Verify a bare product ID: `GET /api/verify/:productID`.
  ///
  /// Used by the pharmacy screen, where the code is read off a carton, and by
  /// [recheck] for a history entry stored before payloads were kept. There is no
  /// signature to check, so this asks the server and reports what it says.
  Future<VerificationOutcome> lookUpProductId(
    String productId, {
    DateTime? today,
    bool remember = true,
  }) async {
    final DateTime now = today ?? DateTime.now();
    final String id = productId.trim();

    final OnlineVerification server;
    try {
      server = await _api.verifyProductId(id);
    } on TrueMedException catch (err) {
      return _finish(
        _noPayloadFailure(err),
        source: VerifySource.server,
        now: now,
        remember: remember,
        failure: err,
        productIdFallback: id,
      );
    } on Object catch (err) {
      final TrueMedException wrapped = TrueMedException(
        Codes.internalError,
        'the lookup failed unexpectedly: $err',
      );
      return _finish(
        _noPayloadFailure(wrapped),
        source: VerifySource.server,
        now: now,
        remember: remember,
        failure: wrapped,
        productIdFallback: id,
      );
    }

    return _finish(
      _serverOnly(server),
      source: VerifySource.server,
      now: now,
      remember: remember,
      online: server,
      productIdFallback: id,
    );
  }

  /// Verify a history entry again.
  ///
  /// Prefers the stored payload, because a re-check with the signature is worth
  /// more than one without: an entry saved as `SIGNATURE_VALID_OFFLINE` in a village
  /// can be resolved properly later on a connection, and a recall issued in the
  /// meantime shows up.
  Future<VerificationOutcome> recheck(
    ScanRecord record, {
    DateTime? today,
  }) {
    final String? payload = record.rawPayload;
    if (payload != null && payload.isNotEmpty) {
      return verifyScan(payload, today: today);
    }
    return lookUpProductId(record.productId, today: today);
  }

  /// File a counterfeit report and mark the scan as reported.
  ///
  /// Wrapped here rather than called straight from the screen so that the history
  /// flag is set in the same place as the request. Two screens can file a report —
  /// the verdict screen and the history screen — and a "mark reported" step that
  /// lives in the UI is a step one of them will eventually forget, which shows up as
  /// the app inviting a patient to report the same strip twice.
  Future<ReportReceipt> reportCounterfeit({
    required String productId,
    required String pharmacyName,
    required String district,
    required String state,
    String? rawPayload,
    double? lat,
    double? lon,
    String? photoBase64,
    String? notes,
    String? reporterContact,
  }) async {
    final ReportReceipt receipt = await _api.reportCounterfeit(
      productId: productId,
      rawPayload: rawPayload,
      pharmacyName: pharmacyName,
      district: district,
      state: state,
      lat: lat,
      lon: lon,
      photoBase64: photoBase64,
      notes: notes,
      reporterContact: reporterContact,
    );
    try {
      await _history.markReported(productId);
    } on Object {
      // The report is filed and has a receipt. Failing to tick a local flag must
      // not be reported to the user as a failed report.
    }
    return receipt;
  }

  // ── Folding ────────────────────────────────────────────────────────────────

  /// The result when the API did not answer.
  ///
  /// Two mutations, and nothing else can happen here:
  ///
  /// 1. [withNetworkFailure] adds the line about what was not checked, for a
  ///    transport failure only — a rate-limited or malformed response is not a
  ///    reason to tell someone their signal is bad.
  /// 2. `GENUINE` is impossible without chain evidence, so if it ever appears on
  ///    this path it is downgraded to `SIGNATURE_VALID_OFFLINE`. Today no offline
  ///    path can produce it, which is the point: this is the guard that keeps that
  ///    true if [verifyWireOffline] ever changes, rather than a comment asking a
  ///    future reader to remember.
  ///
  /// The verdict is otherwise the offline one untouched, so no failure here can
  /// introduce `COUNTERFEIT`. `fromServer` stays false, so the UI keeps offering
  /// "check online".
  VerificationResult _afterApiFailure(
    VerificationResult offline,
    TrueMedException failure,
  ) {
    VerificationResult out = withNetworkFailure(offline, failure);
    if (out.verdict == Verdict.genuine) {
      out = out.copyWith(valid: false, verdict: Verdict.offlineOk);
    }
    if (out.verdict == Verdict.offlineOk &&
        !out.warnings.contains(offlineCaveat)) {
      out = out.copyWith(
        warnings: <String>[offlineCaveat, ...out.warnings],
      );
    }
    return out;
  }

  /// Fold a server response onto a payload the phone could not check, because it
  /// holds no key list.
  ///
  /// [worstVerdict] does the same job rule 2 of [mergeServerVerdict] does, and for
  /// the same reason; what is deliberately absent is rule 1's short-circuit, which
  /// exists for a local `UNVERIFIABLE` that came from a *check that ran*. Here
  /// nothing ran, so discarding the server's verdict would discard the only evidence
  /// there is. The floor still holds in the direction that matters: `UNVERIFIABLE`
  /// outranks both `SIGNATURE_VALID_OFFLINE` and `GENUINE`, so a server answer can
  /// only make this scan redder, never green.
  VerificationResult _foldOntoUnverified(
    VerificationResult offline,
    OnlineVerification server, {
    required DateTime now,
  }) {
    final String ranked = Verdict.isKnown(server.verdict)
        ? server.verdict
        : Verdict.unverifiable;
    final String finalVerdict =
        worstVerdict(<String>[offline.verdict, ranked]);

    return VerificationResult(
      valid: finalVerdict == Verdict.genuine,
      verdict: finalVerdict,
      error: _joinErrors(offline.error, server.errorMessage),
      errorCode: _codeFor(
        finalVerdict: finalVerdict,
        ranked: ranked,
        serverErrorCode: server.errorCode,
      ),
      checks: _overlayServerChecks(offline.checks, server.checks),
      warnings: <String>[
        ...offline.warnings.where((String w) => w != offlineCaveat),
        ...server.warnings,
      ],
      medicine: offline.medicine ?? server.medicine,
      signingKeyFingerprint: offline.signingKeyFingerprint,
      daysToExpiry: offline.medicine?.daysRemaining(asOf: now) ??
          offline.daysToExpiry ??
          server.daysToExpiry,
      onChainStatus: server.onChainStatus,
      scanCount: server.telemetry.scanCount,
      distinctDistricts: server.telemetry.distinctDistricts,
      fromServer: true,
    );
  }

  /// The result for a lookup with no payload: the server's verdict, as its own.
  ///
  /// There is no local floor to apply. That is not a hole in rule 1 — rule 1 keeps
  /// the *phone's* signature check from being overridden, and on this path the phone
  /// never had one. What the UI must not do is present this as a verified signature,
  /// which is why every local check stays `skipped_no_payload` and why the
  /// `signature` row is the one value never copied from a response.
  VerificationResult _serverOnly(OnlineVerification server) {
    final String verdict = Verdict.isKnown(server.verdict)
        ? server.verdict
        : Verdict.unverifiable;
    return VerificationResult(
      valid: verdict == Verdict.genuine,
      verdict: verdict,
      error: server.errorMessage,
      errorCode: server.errorCode ?? verdictToErrorCode(verdict),
      checks: _overlayServerChecks(_noPayloadChecks(), server.checks),
      warnings: server.warnings,
      medicine: server.medicine,
      daysToExpiry: server.daysToExpiry,
      onChainStatus: server.onChainStatus,
      scanCount: server.telemetry.scanCount,
      distinctDistricts: server.telemetry.distinctDistricts,
      fromServer: true,
    );
  }

  /// The result for a lookup whose request never landed. Nothing was checked, by
  /// anyone, which is precisely `UNVERIFIABLE`.
  ///
  /// The error code is the failure's own, not `verdictToErrorCode(UNVERIFIABLE)`,
  /// which is `PAYLOAD_INVALID` — a statement about the payload. There is no payload
  /// here and nothing wrong with the product ID; the network is what failed, and the
  /// UI switches on this code to decide between "could not reach TrueMed" and an
  /// accusation.
  VerificationResult _noPayloadFailure(TrueMedException failure) {
    return VerificationResult(
      valid: false,
      verdict: Verdict.unverifiable,
      error: failure.message,
      errorCode: failure.code,
      checks: _noPayloadChecks(),
    );
  }

  // ── Recording ──────────────────────────────────────────────────────────────

  Future<VerificationOutcome> _finish(
    VerificationResult result, {
    required VerifySource source,
    required DateTime now,
    required bool remember,
    OnlineVerification? online,
    TrueMedException? failure,
    String? rawPayload,
    String? productIdFallback,
  }) async {
    final MedicineData? medicine = result.medicine ?? online?.medicine;
    final String? productId = medicine?.productId ?? productIdFallback;

    ScanRecord? record;
    if (remember && productId != null && productId.isNotEmpty) {
      record = await _remember(
        productId: productId,
        result: result,
        medicine: medicine,
        online: online,
        rawPayload: rawPayload,
        now: now,
      );
    }

    return VerificationOutcome(
      result: result,
      source: source,
      online: online,
      failure: failure,
      rawPayload: rawPayload,
      record: record,
      trustSource: _trust.source,
    );
  }

  /// Write one history entry, or nothing at all.
  ///
  /// Returns null on any failure. A scan that was verified and displayed must not
  /// turn into an error because the keystore was busy — the verdict is the product
  /// of this call, and the history is a convenience.
  Future<ScanRecord?> _remember({
    required String productId,
    required VerificationResult result,
    required MedicineData? medicine,
    required OnlineVerification? online,
    required String? rawPayload,
    required DateTime now,
  }) async {
    try {
      // Loading first matters: ScanHistory.load() replaces the in-memory list with
      // what is on disk, so adding before the first load would show one record and
      // then lose it the moment the history screen opened.
      if (!_history.isLoaded) await _history.load();

      // `add` replaces any earlier entry for this product, which would silently
      // clear a report filed against the previous scan of the same strip and invite
      // the patient to report it a second time.
      final bool alreadyReported = _history.find(productId)?.reported ?? false;

      final ScanRecord record = ScanRecord(
        productId: productId,
        // The merged verdict, never the offline half, so the history cannot claim
        // something better than what was on screen.
        verdict: result.verdict,
        scannedAt: stamp(now),
        genericName: medicine?.genericName,
        brandName: medicine?.brandName,
        batchNo: medicine?.batchNo,
        rawPayload: rawPayload,
        checkedOnline: online != null,
        coldChainBreached: online?.coldChain.breached ?? false,
        reported: alreadyReported,
      );
      await _history.add(record);
      return record;
    } on Object {
      return null;
    }
  }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Every §2.1 check, as it stands before anything has run.
///
/// The three local checks are `skipped_no_payload` rather than `not_evaluated`
/// because on a bare product ID that is the reason, and a row reading "not
/// evaluated" invites the reader to wonder what went wrong. The three network
/// checks start `skipped_offline` and are overwritten by whatever the server
/// reported.
Map<String, String> _noPayloadChecks() => <String, String>{
      CheckName.structure: Check.skippedNoPayload,
      CheckName.signature: Check.skippedNoPayload,
      CheckName.expiry: Check.skippedNoPayload,
      CheckName.onChain: Check.skippedOffline,
      CheckName.coldChain: Check.skippedOffline,
      CheckName.cloneTelemetry: Check.skippedOffline,
    };

/// Merge the server's check rows into the local ones under two restrictions.
///
/// `signature` is never taken from a response. The app either checked it against a
/// pinned key or it did not, and a server that reports `pass` for a signature this
/// app never verified is describing something it cannot be trusted about — the
/// whole reason the check is done on the device.
///
/// A row the app actually ran — `pass` or `fail` — is never overwritten either. The
/// server's opinion of `structure` and `expiry` is welcome only where the phone had
/// nothing of its own to say.
Map<String, String> _overlayServerChecks(
  Map<String, String> local,
  Map<String, String> server,
) {
  final Map<String, String> out = Map<String, String>.of(local);
  for (final MapEntry<String, String> entry in server.entries) {
    if (entry.key == CheckName.signature) continue;
    final String? mine = out[entry.key];
    if (mine == Check.pass || mine == Check.fail) continue;
    out[entry.key] = entry.value;
  }
  return out;
}

/// Prefer the server's error code only when the server's verdict is the one that
/// won, matching [mergeServerVerdict]. Deriving it unconditionally would report a
/// unit the chain has never heard of as a bad signature, which is a different
/// accusation from the one the server made.
String? _codeFor({
  required String finalVerdict,
  required String ranked,
  required String? serverErrorCode,
}) {
  if (finalVerdict == ranked &&
      serverErrorCode != null &&
      serverErrorCode.isNotEmpty) {
    return serverErrorCode;
  }
  return verdictToErrorCode(finalVerdict);
}

String? _joinErrors(String? local, String? remote) {
  final List<String> parts = <String>[
    if (local != null && local.isNotEmpty) local,
    if (remote != null && remote.isNotEmpty) remote,
  ];
  return parts.isEmpty ? null : parts.join('; ');
}

/// A bundle that trusts nothing, for a device with no key list.
///
/// Not a fallback and not a stand-in for the real thing: it holds zero keys, so
/// every signature check against it ends as SIGNATURE_KEY_UNKNOWN, which
/// `verifier.dart` renders as UNVERIFIABLE with the medicine details attached. It
/// is unsigned — `isSigned` is false — so nothing can mistake it for a bundle that
/// passed root verification. Its `issued_at` is the epoch so that if one ever
/// reached the rollback comparison it would lose to everything.
TrustBundle _emptyBundle() => TrustBundle(
      const <TrustedKey>[],
      issuedAt: _epochStamp,
    );

final String _epochStamp =
    stamp(DateTime.fromMillisecondsSinceEpoch(0, isUtc: true));
