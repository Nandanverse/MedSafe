/// Typed views over the API's JSON, per DATA-CONTRACT.md §4.4, §4.4a and §4.5.
///
/// One rule governs every parser here, and it is the reason this file is separate
/// from `core/`: **a malformed API response must never produce a verdict.**
///
/// That sounds obvious and the wrong version is easy to write. `MedicineData.fromDict`
/// throws `PAYLOAD_INVALID` when a field is missing, and `verdictToErrorCode` maps
/// `PAYLOAD_INVALID` to `COUNTERFEIT`. So a server that forgot to include
/// `excipients` in its response — a backend bug, an old API version, a truncated
/// proxy body — would paint a red counterfeit warning over genuine medicine. Every
/// call into the core from this file is therefore wrapped so that a parse failure
/// surfaces as [Codes.badResponse], which is a statement about the *response* and
/// renders as "could not reach TrueMed".
///
/// The models are strict about fields they need and silent about fields they do not
/// recognise, so a newer API does not break an older APK.
library;

import '../core/errors.dart';
import '../core/payload.dart';
import '../core/rules.dart';

/// Re-label a core parse failure as a bad *response*.
///
/// See the library note: without this, a backend bug becomes a counterfeit
/// accusation.
T _asResponseFailure<T>(T Function() body, String what) {
  try {
    return body();
  } on TrueMedException catch (err) {
    if (err.code == Codes.badResponse) rethrow;
    throw badResponse('$what: ${err.message}');
  }
}

/// Read a nullable number, tolerating an integer where a double is expected.
double? _optionalDouble(Map<String, Object?> from, String key) {
  final Object? value = from[key];
  if (value == null) return null;
  if (value is num && value.isFinite) return value.toDouble();
  throw badResponse("'$key' is not a number ($value)");
}

/// Read an integer, defaulting when absent.
int _intOr(Map<String, Object?> from, String key, int fallback) {
  final Object? value = from[key];
  if (value == null) return fallback;
  if (value is int) return value;
  if (value is double && value.isFinite && value == value.roundToDouble()) {
    return value.toInt();
  }
  throw badResponse("'$key' is not an integer ($value)");
}

bool _boolOr(Map<String, Object?> from, String key, bool fallback) {
  final Object? value = from[key];
  if (value == null) return fallback;
  if (value is bool) return value;
  throw badResponse("'$key' is not a boolean ($value)");
}

String? _optionalString(Map<String, Object?> from, String key) {
  final Object? value = from[key];
  if (value == null) return null;
  if (value is String) return value.isEmpty ? null : value;
  throw badResponse("'$key' is not a string ($value)");
}

String _stringOr(Map<String, Object?> from, String key, String fallback) =>
    _optionalString(from, key) ?? fallback;

Map<String, Object?>? _optionalMap(Map<String, Object?> from, String key) {
  final Object? value = from[key];
  if (value == null) return null;
  if (value is Map) return value.cast<String, Object?>();
  throw badResponse("'$key' is not an object");
}

List<Object?> _listOr(Map<String, Object?> from, String key) {
  final Object? value = from[key];
  if (value == null) return const <Object?>[];
  if (value is List) return value;
  throw badResponse("'$key' is not an array");
}

/// Normalise a severity from the API.
///
/// An unrecognised value becomes [Severity.warn], not [Severity.critical]. This is
/// the opposite of `severityFor` in the core, deliberately: `severityFor` maps a
/// *verdict*, where an unknown value must fail loudly, whereas this maps a
/// dashboard row's colour, where an unknown value screaming red would send a
/// regulator to the wrong district. Nothing on the verification path uses this.
String _severityOrWarn(String? raw) {
  switch (raw) {
    case Severity.ok:
    case Severity.warn:
    case Severity.critical:
      return raw!;
    default:
      return Severity.warn;
  }
}

// ── Verification ─────────────────────────────────────────────────────────────

/// `data.cold_chain` from §4.4.
class ColdChainStatus {
  const ColdChainStatus({
    required this.applicable,
    required this.breached,
    this.minC,
    this.maxC,
    this.readingCount = 0,
  });

  /// False for medicines: only vaccines have a cold chain (§3.3). A medicine may
  /// still have temperature readings logged, and they never constitute a breach.
  final bool applicable;

  final bool breached;

  /// Coldest and warmest readings seen, or null when none were logged.
  final double? minC;
  final double? maxC;

  final int readingCount;

  /// Not applicable, or applicable with no readings at all — which is not the same
  /// as compliant, and the UI must not render it green. A vaccine with zero
  /// readings has an unmonitored cold chain.
  bool get isUnmonitored => applicable && readingCount == 0;

  static const ColdChainStatus notApplicable =
      ColdChainStatus(applicable: false, breached: false);

  factory ColdChainStatus.fromJson(Map<String, Object?>? json) {
    if (json == null) return notApplicable;
    return ColdChainStatus(
      applicable: _boolOr(json, 'applicable', false),
      breached: _boolOr(json, 'breached', false),
      minC: _optionalDouble(json, 'min_c'),
      maxC: _optionalDouble(json, 'max_c'),
      readingCount: _intOr(json, 'reading_count', 0),
    );
  }

  /// `2.1 °C to 7.8 °C` — the range as a person reads it, or null when empty.
  ///
  /// Dart source is UTF-8, so the degree sign is written literally here. (The ESP32
  /// firmware writes `degC` instead, because a C++ toolchain's handling of non-ASCII
  /// in string literals is not worth relying on.)
  String? get rangeLabel {
    final double? lo = minC;
    final double? hi = maxC;
    if (lo == null || hi == null) return null;
    return '${lo.toStringAsFixed(1)} °C to ${hi.toStringAsFixed(1)} °C';
  }
}

/// `data.telemetry` from §4.4 — the anti-photocopy evidence.
class ScanTelemetry {
  const ScanTelemetry({
    this.scanCount = 0,
    this.distinctDistricts = 0,
    this.firstScanAt,
  });

  final int scanCount;
  final int distinctDistricts;
  final String? firstScanAt;

  static const ScanTelemetry empty = ScanTelemetry();

  factory ScanTelemetry.fromJson(Map<String, Object?>? json) {
    if (json == null) return empty;
    return ScanTelemetry(
      scanCount: _intOr(json, 'scan_count', 0),
      distinctDistricts: _intOr(json, 'distinct_districts', 0),
      firstScanAt: _optionalString(json, 'first_scan_at'),
    );
  }

  /// The §7.1 rule, evaluated locally on the numbers the server reported.
  ///
  /// The server has already applied it and sent a verdict; this is here so the
  /// details screen can explain *why* a clone was suspected using the same
  /// thresholds, rather than restating the verdict.
  bool get suspicious => cloneSuspected(scanCount, distinctDistricts);
}

/// One `data.custody_trail` entry.
class CustodyEvent {
  const CustodyEvent({
    required this.status,
    required this.location,
    required this.timestamp,
    this.actorMsp,
  });

  final String status;
  final String location;
  final String timestamp;
  final String? actorMsp;

  /// Human label from the core's status table.
  String get label => Status.label(status);

  factory CustodyEvent.fromJson(Object? raw) {
    if (raw is! Map) {
      throw badResponse('a custody_trail entry is not an object');
    }
    final Map<String, Object?> json = raw.cast<String, Object?>();
    return CustodyEvent(
      status: _stringOr(json, 'status', 'unknown'),
      location: _stringOr(json, 'location', 'unknown'),
      timestamp: _stringOr(json, 'timestamp', ''),
      actorMsp: _optionalString(json, 'actor_msp'),
    );
  }
}

/// The full `GET /api/verify/:productID` or `POST /api/verify/payload` result.
///
/// This is the server's opinion. It is never shown to a patient on its own — it
/// goes through `mergeServerVerdict` in `core/verifier.dart`, which takes the worse
/// of this and the app's own offline signature check. A compromised API can make
/// genuine medicine look suspicious; it cannot make a forgery look genuine.
class OnlineVerification {
  const OnlineVerification({
    required this.verdict,
    required this.severity,
    required this.checks,
    required this.coldChain,
    required this.telemetry,
    required this.custodyTrail,
    required this.warnings,
    this.medicine,
    this.onChainStatus,
    this.currentLocation,
    this.daysToExpiry,
    this.errorCode,
    this.errorMessage,
    this.cached = false,
    this.tookMs,
  });

  final String verdict;
  final String severity;

  /// §2.1 check name → outcome. Only `on_chain`, `cold_chain` and
  /// `clone_telemetry` are taken from here by the merge; the app's own signature
  /// and structure results always win.
  final Map<String, String> checks;

  final ColdChainStatus coldChain;
  final ScanTelemetry telemetry;
  final List<CustodyEvent> custodyTrail;
  final List<String> warnings;

  /// Null when the product is not on chain, so there is nothing to describe.
  final MedicineData? medicine;

  /// `medicine.status` — the custody state, one of [Status].
  final String? onChainStatus;

  final String? currentLocation;

  /// The server's own expiry arithmetic. The app computes its own from the signed
  /// payload and prefers that, because the signed date is the authoritative one.
  final int? daysToExpiry;

  final String? errorCode;
  final String? errorMessage;

  /// From `meta.cached`. A cached answer can be up to an hour old (§4.6), which
  /// matters when the question is whether a recall has landed.
  final bool cached;

  final int? tookMs;

  /// The most recent custody event, which is the one worth showing first.
  CustodyEvent? get latestCustody =>
      custodyTrail.isEmpty ? null : custodyTrail.last;

  factory OnlineVerification.fromData(
    Map<String, Object?> data, {
    bool cached = false,
    int? tookMs,
  }) {
    final String? verdict = _optionalString(data, 'verdict');
    if (verdict == null) {
      throw badResponse(
        'the verification response carries no verdict, so there is nothing to '
        'show',
      );
    }

    // `checks` values are strings from the Check enumeration. An unknown value is
    // kept verbatim rather than dropped: the details screen shows it, and losing
    // it would make a newer API's richer answer invisible.
    final Map<String, String> checks = <String, String>{};
    final Map<String, Object?>? rawChecks = _optionalMap(data, 'checks');
    if (rawChecks != null) {
      for (final MapEntry<String, Object?> entry in rawChecks.entries) {
        final Object? value = entry.value;
        if (value is String) checks[entry.key] = value;
      }
    }

    MedicineData? medicine;
    String? onChainStatus;
    String? currentLocation;
    int? daysToExpiry;
    final Map<String, Object?>? rawMedicine = _optionalMap(data, 'medicine');
    if (rawMedicine != null) {
      // Wrapped: see the library note. A missing field here is a backend defect,
      // and must not be reported to the patient as a counterfeit.
      medicine = _asResponseFailure(
        () => MedicineData.fromDict(rawMedicine),
        'the medicine object in the verification response is not usable',
      );
      onChainStatus = _optionalString(rawMedicine, 'status');
      currentLocation = _optionalString(rawMedicine, 'current_location');
      final Object? days = rawMedicine['days_to_expiry'];
      if (days is int) {
        daysToExpiry = days;
      } else if (days is double && days.isFinite) {
        daysToExpiry = days.round();
      }
    }

    final List<String> warnings = <String>[];
    for (final Object? entry in _listOr(data, 'warnings')) {
      if (entry is String && entry.isNotEmpty) warnings.add(entry);
    }

    final List<CustodyEvent> trail = <CustodyEvent>[];
    for (final Object? entry in _listOr(data, 'custody_trail')) {
      trail.add(CustodyEvent.fromJson(entry));
    }

    // Some endpoints report a failing verdict inside a 200 envelope with an
    // `error` object alongside it (a recalled unit is a successful lookup with a
    // bad answer), so both shapes are read.
    final Map<String, Object?>? error = _optionalMap(data, 'error');

    return OnlineVerification(
      verdict: verdict,
      severity: _severityOrWarn(
        _optionalString(data, 'severity') ?? severityFor(verdict),
      ),
      checks: Map<String, String>.unmodifiable(checks),
      coldChain: ColdChainStatus.fromJson(_optionalMap(data, 'cold_chain')),
      telemetry: ScanTelemetry.fromJson(_optionalMap(data, 'telemetry')),
      custodyTrail: List<CustodyEvent>.unmodifiable(trail),
      warnings: List<String>.unmodifiable(warnings),
      medicine: medicine,
      onChainStatus: onChainStatus,
      currentLocation: currentLocation,
      daysToExpiry: daysToExpiry,
      errorCode: _optionalString(data, 'error_code') ??
          (error == null ? null : _optionalString(error, 'code')),
      errorMessage:
          error == null ? null : _optionalString(error, 'message'),
      cached: cached,
      tookMs: tookMs,
    );
  }
}

// ── Reports and recalls ──────────────────────────────────────────────────────

/// `POST /api/report` → 201.
class ReportReceipt {
  const ReportReceipt({this.reportId, this.receivedAt});

  /// The reference a patient can quote. Optional, because a report must succeed
  /// even from a build of the API that does not issue one — the report itself is
  /// what matters, and failing the call over a missing receipt would lose it.
  final String? reportId;
  final String? receivedAt;

  factory ReportReceipt.fromData(Map<String, Object?> data) => ReportReceipt(
        reportId: _optionalString(data, 'report_id'),
        receivedAt: _optionalString(data, 'received_at'),
      );
}

/// `POST /api/recall` → the chaincode's `RecallResult`, passed through (§4.5).
class RecallResult {
  const RecallResult({
    required this.batchNo,
    required this.recalled,
    required this.alreadyRecalled,
    required this.moreRemaining,
    required this.productIds,
  });

  final String batchNo;

  /// Units recalled by *this* call, capped at `maxRecallPerTx`.
  final int recalled;

  /// Units that were already recalled before this call, so a repeated request is
  /// visibly idempotent rather than looking like it did nothing.
  final int alreadyRecalled;

  /// True when the batch is larger than one transaction can cover, so the caller
  /// must call again. A client that ignores this leaves part of a recalled batch
  /// live on chain — which is why §4.4a defines a `recall_incomplete` alert.
  final bool moreRemaining;

  final List<String> productIds;

  factory RecallResult.fromData(Map<String, Object?> data) {
    final List<String> ids = <String>[];
    for (final Object? entry in _listOr(data, 'product_ids')) {
      if (entry is String) ids.add(entry);
    }
    return RecallResult(
      batchNo: _stringOr(data, 'batch_no', ''),
      recalled: _intOr(data, 'recalled', 0),
      alreadyRecalled: _intOr(data, 'already_recalled', 0),
      moreRemaining: _boolOr(data, 'more_remaining', false),
      productIds: List<String>.unmodifiable(ids),
    );
  }
}

/// The running total across a multi-call recall, so the UI can report one number.
class RecallProgress {
  const RecallProgress({
    required this.batchNo,
    required this.recalled,
    required this.alreadyRecalled,
    required this.calls,
    required this.complete,
  });

  final String batchNo;
  final int recalled;
  final int alreadyRecalled;
  final int calls;

  /// False when the loop gave up with units still live on chain — which the UI
  /// must say out loud, because the batch is then partly recalled.
  final bool complete;

  int get total => recalled + alreadyRecalled;
}

// ── Dashboards (§4.4a) ───────────────────────────────────────────────────────

/// The aggregation window both dashboards report.
class DashboardWindow {
  const DashboardWindow({this.from, this.to, this.days = 30});

  final String? from;
  final String? to;
  final int days;

  factory DashboardWindow.fromJson(Map<String, Object?>? json) {
    if (json == null) return const DashboardWindow();
    return DashboardWindow(
      from: _optionalString(json, 'from'),
      to: _optionalString(json, 'to'),
      days: _intOr(json, 'days', 30),
    );
  }
}

/// One row of the CDSCO heat map.
class DistrictRow {
  const DistrictRow({
    required this.district,
    required this.state,
    required this.reports,
    required this.distinctBatches,
    required this.severity,
  });

  final String district;
  final String state;
  final int reports;
  final int distinctBatches;
  final String severity;

  factory DistrictRow.fromJson(Object? raw) {
    if (raw is! Map) throw badResponse('a districts entry is not an object');
    final Map<String, Object?> json = raw.cast<String, Object?>();
    return DistrictRow(
      district: _stringOr(json, 'district', 'Unknown'),
      state: _stringOr(json, 'state', ''),
      reports: _intOr(json, 'reports', 0),
      distinctBatches: _intOr(json, 'distinct_batches', 0),
      severity: _severityOrWarn(_optionalString(json, 'severity')),
    );
  }
}

/// One CDSCO alert.
class RegulatorAlert {
  const RegulatorAlert({
    required this.kind,
    required this.severity,
    required this.detail,
    this.productId,
    this.batchNo,
    this.manufacturer,
    this.at,
  });

  /// `counterfeit_report`, `clone_suspected`, `cold_chain_breach`,
  /// `recall_incomplete`, or something newer. §4.4a requires clients to render an
  /// unrecognised kind rather than drop it, so this is kept as a raw string and
  /// [label] falls back to it.
  final String kind;

  final String severity;
  final String detail;
  final String? productId;
  final String? batchNo;
  final String? manufacturer;
  final String? at;

  String get label {
    switch (kind) {
      case 'counterfeit_report':
        return 'Counterfeit report';
      case 'clone_suspected':
        return 'Duplicate scans';
      case 'cold_chain_breach':
        return 'Cold chain breach';
      case 'recall_incomplete':
        return 'Recall incomplete';
      default:
        return kind.replaceAll('_', ' ');
    }
  }

  factory RegulatorAlert.fromJson(Object? raw) {
    if (raw is! Map) throw badResponse('an alerts entry is not an object');
    final Map<String, Object?> json = raw.cast<String, Object?>();
    return RegulatorAlert(
      kind: _stringOr(json, 'kind', 'unknown'),
      severity: _severityOrWarn(_optionalString(json, 'severity')),
      detail: _stringOr(json, 'detail', ''),
      productId: _optionalString(json, 'product_id'),
      batchNo: _optionalString(json, 'batch_no'),
      manufacturer: _optionalString(json, 'manufacturer'),
      at: _optionalString(json, 'at'),
    );
  }
}

/// `GET /api/dashboard/cdsco`.
class CdscoDashboard {
  const CdscoDashboard({
    required this.window,
    required this.reports,
    required this.reportsOpen,
    required this.unitsRecalled,
    required this.coldChainBreaches,
    required this.cloneSuspected,
    required this.districts,
    required this.alerts,
    required this.truncated,
  });

  final DashboardWindow window;
  final int reports;
  final int reportsOpen;
  final int unitsRecalled;
  final int coldChainBreaches;
  final int cloneSuspected;
  final List<DistrictRow> districts;
  final List<RegulatorAlert> alerts;

  /// True when rows were dropped to fit `?limit=`.
  final bool truncated;

  factory CdscoDashboard.fromData(Map<String, Object?> data) {
    final Map<String, Object?> totals =
        _optionalMap(data, 'totals') ?? <String, Object?>{};
    final List<DistrictRow> districts = <DistrictRow>[];
    for (final Object? entry in _listOr(data, 'districts')) {
      districts.add(DistrictRow.fromJson(entry));
    }
    final List<RegulatorAlert> alerts = <RegulatorAlert>[];
    for (final Object? entry in _listOr(data, 'alerts')) {
      alerts.add(RegulatorAlert.fromJson(entry));
    }
    return CdscoDashboard(
      window: DashboardWindow.fromJson(_optionalMap(data, 'window')),
      reports: _intOr(totals, 'reports', 0),
      reportsOpen: _intOr(totals, 'reports_open', 0),
      unitsRecalled: _intOr(totals, 'units_recalled', 0),
      coldChainBreaches: _intOr(totals, 'cold_chain_breaches', 0),
      cloneSuspected: _intOr(totals, 'clone_suspected', 0),
      districts: List<DistrictRow>.unmodifiable(districts),
      alerts: List<RegulatorAlert>.unmodifiable(alerts),
      truncated: _boolOr(data, 'truncated', false),
    );
  }
}

/// One batch row of the pharma dashboard.
class BatchRow {
  const BatchRow({
    required this.batchNo,
    required this.genericName,
    required this.brandName,
    required this.type,
    required this.expiryDate,
    required this.daysToExpiry,
    required this.unitCount,
    required this.statusCounts,
    required this.coldChain,
    required this.reports,
    required this.worstSeverity,
    this.mfgDate,
  });

  final String batchNo;
  final String genericName;
  final String brandName;
  final String type;
  final String? mfgDate;
  final String expiryDate;
  final int daysToExpiry;
  final int unitCount;

  /// All five §3.1 statuses, always present, per §4.4a.
  final Map<String, int> statusCounts;

  final ColdChainStatus coldChain;
  final int reports;
  final String worstSeverity;

  int countOf(String status) => statusCounts[status] ?? 0;

  /// Units neither dispensed nor recalled — the number that decides whether to
  /// pull stock from shelves.
  int get unitsRemaining =>
      countOf(Status.manufactured) +
      countOf(Status.inTransit) +
      countOf(Status.atPharmacy);

  factory BatchRow.fromJson(Object? raw) {
    if (raw is! Map) throw badResponse('a batches entry is not an object');
    final Map<String, Object?> json = raw.cast<String, Object?>();
    final Map<String, Object?> rawCounts =
        _optionalMap(json, 'status_counts') ?? <String, Object?>{};
    final Map<String, int> counts = <String, int>{};
    for (final String status in Status.all) {
      counts[status] = _intOr(rawCounts, status, 0);
    }
    return BatchRow(
      batchNo: _stringOr(json, 'batch_no', ''),
      genericName: _stringOr(json, 'generic_name', ''),
      brandName: _stringOr(json, 'brand_name', ''),
      type: _stringOr(json, 'type', MedType.medicine),
      mfgDate: _optionalString(json, 'mfg_date'),
      expiryDate: _stringOr(json, 'expiry_date', ''),
      daysToExpiry: _intOr(json, 'days_to_expiry', 0),
      unitCount: _intOr(json, 'unit_count', 0),
      statusCounts: Map<String, int>.unmodifiable(counts),
      coldChain: ColdChainStatus.fromJson(_optionalMap(json, 'cold_chain')),
      reports: _intOr(json, 'reports', 0),
      worstSeverity: _severityOrWarn(_optionalString(json, 'worst_severity')),
    );
  }
}

/// One `expiring_soon` row.
class ExpiringBatch {
  const ExpiringBatch({
    required this.batchNo,
    required this.expiryDate,
    required this.daysToExpiry,
    required this.unitsRemaining,
  });

  final String batchNo;
  final String expiryDate;
  final int daysToExpiry;
  final int unitsRemaining;

  factory ExpiringBatch.fromJson(Object? raw) {
    if (raw is! Map) {
      throw badResponse('an expiring_soon entry is not an object');
    }
    final Map<String, Object?> json = raw.cast<String, Object?>();
    return ExpiringBatch(
      batchNo: _stringOr(json, 'batch_no', ''),
      expiryDate: _stringOr(json, 'expiry_date', ''),
      daysToExpiry: _intOr(json, 'days_to_expiry', 0),
      unitsRemaining: _intOr(json, 'units_remaining', 0),
    );
  }
}

/// `GET /api/dashboard/pharma`.
class PharmaDashboard {
  const PharmaDashboard({
    required this.manufacturer,
    required this.mfgLicenceNo,
    required this.window,
    required this.unitsMinted,
    required this.unitsDispensed,
    required this.unitsRecalled,
    required this.batchCount,
    required this.batches,
    required this.expiringSoon,
    required this.truncated,
  });

  final String manufacturer;
  final String mfgLicenceNo;
  final DashboardWindow window;
  final int unitsMinted;
  final int unitsDispensed;
  final int unitsRecalled;
  final int batchCount;
  final List<BatchRow> batches;
  final List<ExpiringBatch> expiringSoon;
  final bool truncated;

  factory PharmaDashboard.fromData(Map<String, Object?> data) {
    final Map<String, Object?> totals =
        _optionalMap(data, 'totals') ?? <String, Object?>{};
    final List<BatchRow> batches = <BatchRow>[];
    for (final Object? entry in _listOr(data, 'batches')) {
      batches.add(BatchRow.fromJson(entry));
    }
    final List<ExpiringBatch> expiring = <ExpiringBatch>[];
    for (final Object? entry in _listOr(data, 'expiring_soon')) {
      expiring.add(ExpiringBatch.fromJson(entry));
    }
    return PharmaDashboard(
      manufacturer: _stringOr(data, 'manufacturer', ''),
      mfgLicenceNo: _stringOr(data, 'mfg_licence_no', ''),
      window: DashboardWindow.fromJson(_optionalMap(data, 'window')),
      unitsMinted: _intOr(totals, 'units_minted', 0),
      unitsDispensed: _intOr(totals, 'units_dispensed', 0),
      unitsRecalled: _intOr(totals, 'units_recalled', 0),
      batchCount: _intOr(totals, 'batches', 0),
      batches: List<BatchRow>.unmodifiable(batches),
      expiringSoon: List<ExpiringBatch>.unmodifiable(expiring),
      truncated: _boolOr(data, 'truncated', false),
    );
  }
}

/// `GET /healthz` and `/readyz`.
class HealthStatus {
  const HealthStatus({required this.ready, this.detail});

  final bool ready;
  final String? detail;

  factory HealthStatus.fromData(Map<String, Object?> data) => HealthStatus(
        // A 200 with an envelope is itself the signal; `status` is read when
        // present so a degraded-but-answering API can say so.
        ready: _stringOr(data, 'status', 'ok') != 'degraded',
        detail: _optionalString(data, 'status'),
      );
}
