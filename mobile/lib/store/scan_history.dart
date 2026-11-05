/// On-device scan history.
///
/// # Why this is in the *secure* store when the trust bundle is not
///
/// The trust bundle is public data with a signature, so it sits in plaintext
/// preferences. This file holds the opposite kind of data and gets the opposite
/// treatment.
///
/// A list of medicines someone scanned, with timestamps, is health information
/// about an identifiable individual: diabetes medication every month, an
/// antiretroviral, a fertility drug, a psychiatric prescription. Under India's
/// Digital Personal Data Protection Act that is personal data the app is
/// accountable for, and the sensitivity is not in any one entry but in the
/// sequence — a pattern of refills is a diagnosis. So it is encrypted at rest by
/// the Keystore/Keychain, capped so it cannot silently accumulate for years, and
/// erasable in one action from the history screen.
///
/// Encryption here is worth the cost precisely because it was not worth it for the
/// bundle. Both decisions come from asking what an attacker gains by reading the
/// file, and the answers are different: nothing in one case, a person's medical
/// history in the other.
///
/// # Why the raw payload is kept
///
/// [ScanRecord.rawPayload] is the scanned string, signature included. Keeping it
/// makes a report filable *later* — a pharmacist who notices a pattern after the
/// third suspicious strip can still submit the exact bytes from all three, and an
/// investigator can re-run verification on them months afterwards. Without it, a
/// report filed after the fact is one person's recollection.
///
/// It also enlarges what a compromise of this store yields, which is the reason
/// [maxHistory] is a hundred and not ten thousand, and why nothing here is ever
/// sent anywhere: history is uploaded only when the user files a report about a
/// specific scan.
library;

import 'dart:async';
import 'dart:convert';

import 'package:flutter/foundation.dart' show ChangeNotifier;

import '../core/rules.dart';
import 'secure_store.dart';

const String _kHistory = 'history.scans';

/// How many scans are retained.
///
/// A cap rather than a time window, because a pharmacy scanning stock all day and
/// a patient scanning one strip a month need very different windows, and a count is
/// predictable in storage terms: a hundred records with payloads is roughly 40 kB,
/// which the encrypted store handles without a perceptible delay.
const int maxHistory = 100;

/// One past scan, as shown on the history screen.
class ScanRecord {
  const ScanRecord({
    required this.productId,
    required this.verdict,
    required this.scannedAt,
    this.genericName,
    this.brandName,
    this.batchNo,
    this.rawPayload,
    this.checkedOnline = false,
    this.coldChainBreached = false,
    this.reported = false,
  });

  final String productId;

  /// The verdict shown to the user — already the merged offline/online result, so
  /// the history cannot claim something better than what was displayed.
  final String verdict;

  /// RFC 3339 UTC, from [stamp].
  final String scannedAt;

  final String? genericName;
  final String? brandName;
  final String? batchNo;

  /// The scanned string, for a later report. Null for a scan of a bare product ID.
  final String? rawPayload;

  /// True when the API was reached. A false here is why an old GENUINE in the
  /// history is weaker evidence than it looks — see §2.2 on offline limits.
  final bool checkedOnline;

  final bool coldChainBreached;

  /// True once a counterfeit report has been filed for this scan, so the history
  /// screen does not invite the same report twice.
  final bool reported;

  String get severity => severityFor(verdict);

  String get title => brandName ?? genericName ?? productId;

  DateTime? get scannedAtInstant {
    try {
      return parseInstant('scanned_at', scannedAt).toLocal();
    } on Object {
      return null;
    }
  }

  ScanRecord copyWith({bool? reported}) => ScanRecord(
        productId: productId,
        verdict: verdict,
        scannedAt: scannedAt,
        genericName: genericName,
        brandName: brandName,
        batchNo: batchNo,
        rawPayload: rawPayload,
        checkedOnline: checkedOnline,
        coldChainBreached: coldChainBreached,
        reported: reported ?? this.reported,
      );

  Map<String, Object?> toJson() => <String, Object?>{
        'product_id': productId,
        'verdict': verdict,
        'scanned_at': scannedAt,
        if (genericName != null) 'generic_name': genericName,
        if (brandName != null) 'brand_name': brandName,
        if (batchNo != null) 'batch_no': batchNo,
        if (rawPayload != null) 'raw_payload': rawPayload,
        'checked_online': checkedOnline,
        'cold_chain_breached': coldChainBreached,
        'reported': reported,
      };

  /// Parse one record, or null if it is unusable.
  ///
  /// Returns null rather than throwing so that one corrupt entry cannot take the
  /// whole history down with it. This store is written by this app alone, so a bad
  /// record means an interrupted write or a format change across an app update —
  /// both of which should cost the user one row, not the entire list.
  static ScanRecord? tryFromJson(Object? raw) {
    if (raw is! Map) return null;
    final Object? productId = raw['product_id'];
    final Object? verdict = raw['verdict'];
    final Object? scannedAt = raw['scanned_at'];
    if (productId is! String || productId.isEmpty) return null;
    if (verdict is! String || verdict.isEmpty) return null;
    if (scannedAt is! String || scannedAt.isEmpty) return null;
    String? optional(String key) {
      final Object? value = raw[key];
      return value is String && value.isNotEmpty ? value : null;
    }

    bool flag(String key) => raw[key] == true;

    return ScanRecord(
      productId: productId,
      // Kept verbatim even if this build does not recognise it. An unknown verdict
      // renders through `severityFor`, which returns `critical` for anything it
      // does not know, so an older app showing a newer verdict errs towards
      // caution rather than towards green.
      verdict: verdict,
      scannedAt: scannedAt,
      genericName: optional('generic_name'),
      brandName: optional('brand_name'),
      batchNo: optional('batch_no'),
      rawPayload: optional('raw_payload'),
      checkedOnline: flag('checked_online'),
      coldChainBreached: flag('cold_chain_breached'),
      reported: flag('reported'),
    );
  }
}

class ScanHistory extends ChangeNotifier {
  ScanHistory({required KeyValueStore secure}) : _secure = secure;

  final KeyValueStore _secure;

  List<ScanRecord> _records = const <ScanRecord>[];
  bool _loaded = false;

  /// Newest first.
  List<ScanRecord> get records => List<ScanRecord>.unmodifiable(_records);

  bool get isEmpty => _records.isEmpty;

  bool get isLoaded => _loaded;

  int get length => _records.length;

  /// Scans whose verdict is anything other than GENUINE, for the summary count on
  /// the home screen.
  int get concerningCount =>
      _records.where((ScanRecord r) => r.verdict != Verdict.genuine).length;

  Future<void> load() async {
    _loaded = true;
    String? text;
    try {
      text = await _secure.read(_kHistory);
    } on Object {
      _records = const <ScanRecord>[];
      notifyListeners();
      return;
    }
    _records = _decode(text);
    notifyListeners();
  }

  static List<ScanRecord> _decode(String? text) {
    if (text == null || text.isEmpty) return const <ScanRecord>[];
    Object? decoded;
    try {
      decoded = jsonDecode(text);
    } on FormatException {
      return const <ScanRecord>[];
    }
    if (decoded is! List) return const <ScanRecord>[];
    final List<ScanRecord> out = <ScanRecord>[];
    for (final Object? entry in decoded) {
      final ScanRecord? record = ScanRecord.tryFromJson(entry);
      if (record != null) out.add(record);
    }
    return out;
  }

  /// Record a scan, replacing any earlier entry for the same product.
  ///
  /// Deduplicating by product ID is what makes the clone signal legible: a patient
  /// who rescans the same strip four times should see one row, so that four rows
  /// for the same ID never appear and get mistaken for the duplicate-scan pattern
  /// that §2.2's clone rule is about. Cross-device duplicate detection is the
  /// server's job and requires data no phone has.
  Future<void> add(ScanRecord record) async {
    final List<ScanRecord> next = <ScanRecord>[
      record,
      ..._records.where((ScanRecord r) => r.productId != record.productId),
    ];
    if (next.length > maxHistory) next.removeRange(maxHistory, next.length);
    _records = next;
    notifyListeners();
    await _persist();
  }

  /// Mark a scan as reported.
  Future<void> markReported(String productId) async {
    bool changed = false;
    _records = _records.map((ScanRecord r) {
      if (r.productId == productId && !r.reported) {
        changed = true;
        return r.copyWith(reported: true);
      }
      return r;
    }).toList(growable: false);
    if (!changed) return;
    notifyListeners();
    await _persist();
  }

  ScanRecord? find(String productId) {
    for (final ScanRecord record in _records) {
      if (record.productId == productId) return record;
    }
    return null;
  }

  /// Erase everything. The DPDP Act's right to erasure, as one button.
  Future<void> clear() async {
    _records = const <ScanRecord>[];
    notifyListeners();
    try {
      await _secure.delete(_kHistory);
    } on Object {
      // The in-memory list is already empty and the next write overwrites the
      // record, so a failure here cannot resurrect the history in the UI.
    }
  }

  /// Write the list, notifying listeners *before* the write.
  ///
  /// The order is intentional: the history screen updates as soon as the scan is
  /// recorded rather than after an encrypted write completes. A failed write loses
  /// history, which is a real but minor loss; a UI that stalls on the keystore
  /// after every scan is felt on every single scan.
  Future<void> _persist() async {
    try {
      await _secure.write(
        _kHistory,
        jsonEncode(_records.map((ScanRecord r) => r.toJson()).toList()),
      );
    } on Object {
      // Nothing to tell the user: the scan itself succeeded and was displayed.
    }
  }
}
