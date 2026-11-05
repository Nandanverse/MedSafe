/// The on-device trust store: which manufacturer signing keys this app believes.
///
/// # What this file is defending
///
/// Offline verification is only as good as the key list. Every attack on TrueMed
/// that does not require stealing a manufacturer's private key is an attack on this
/// file: get a revoked key back into the list, or keep an old list alive, and
/// forged strips signed with a compromised key verify as GENUINE on every phone
/// that fell for it.
///
/// Three defences, in order of how much they matter:
///
/// **1. The root signature, checked on every load.** A bundle is never trusted
/// because of where it came from. The copy shipped in the APK, the copy cached on
/// disk and the copy fetched from the API all go through the same
/// `TrustBundle.fromJson`, which verifies the root signature against the key pinned
/// in the binary by `--dart-define`. A hostile API cannot add a key. Neither can
/// anything that rewrites the cache file.
///
/// **2. A high-water mark on `issued_at`, in hardware-backed storage.** The root
/// signature alone does not stop a *rollback*: an old bundle is authentically
/// signed, so replaying one is a valid-looking way to resurrect a revoked key.
/// `TrustBundle.isNewerThan` blocks that on the network path, but on its own it
/// would not survive the cache being replaced, because after a restart the app has
/// nothing to compare against. So the newest `issued_at` ever accepted is written
/// to the Keystore/Keychain, where an attacker who can rewrite app files still
/// cannot lower it, and any bundle at or below it is refused wherever it came from.
///
/// **3. Failing amber, never red.** Every failure in this file ends with no bundle
/// or an old-but-verified bundle, which makes scans UNVERIFIABLE. None of them can
/// produce COUNTERFEIT. A trust-store problem is the app's problem and must never
/// be reported to a patient as an accusation against their medicine.
///
/// # What it does not defend
///
/// A rooted device where the attacker can modify the APK. The pinned root key is
/// the anchor for everything here, and an attacker who can replace it has already
/// won. That is a limitation of client-side verification in general, not of this
/// design, and it is why §2.2 treats the online check as the authority when it is
/// available.
library;

import 'dart:async';

import 'package:flutter/foundation.dart' show ChangeNotifier;
import 'package:flutter/services.dart' show rootBundle;

import '../api/client.dart';
import '../config.dart';
import '../core/errors.dart';
import '../core/pinned_root_key.dart';
import '../core/rules.dart';
import '../core/trust_bundle.dart';
import 'secure_store.dart';

/// Where a loaded bundle came from. Shown on the diagnostics screen, because
/// "running on the list baked into the APK in June" and "refreshed an hour ago"
/// are very different states to be debugging in.
enum TrustSource {
  /// `assets/trust_bundle.json`, shipped in the APK.
  asset,

  /// The on-disk cache, from an earlier successful refresh.
  cache,

  /// Just fetched from `GET /api/public-keys`.
  network,
}

/// Asset text loader, injected so the rollback logic is testable without a
/// platform channel.
typedef AssetReader = Future<String> Function(String key);

Future<String> _defaultAssetReader(String key) => rootBundle.loadString(key);

/// The asset path, matching the `flutter: assets:` entry in `pubspec.yaml`.
const String trustBundleAsset = 'assets/trust_bundle.json';

const String _kBundle = 'trust.bundle';
const String _kLastRefresh = 'trust.last_refresh';
const String _kMinIssuedAt = 'trust.min_issued_at';
const String _kMarkRootFp = 'trust.min_root_fingerprint';

class TrustStore extends ChangeNotifier {
  TrustStore({
    required KeyValueStore prefs,
    required KeyValueStore secure,
    AssetReader? assetReader,
  })  : _prefs = prefs,
        _secure = secure,
        _readAsset = assetReader ?? _defaultAssetReader;

  /// Convenience constructor for a test that wants a store with no platform
  /// dependencies at all.
  factory TrustStore.inMemory({
    required String assetJson,
    Map<String, String>? prefs,
    Map<String, String>? secure,
  }) =>
      TrustStore(
        prefs: MemoryStore(prefs),
        secure: MemoryStore(secure),
        assetReader: (String _) async => assetJson,
      );

  final KeyValueStore _prefs;
  final KeyValueStore _secure;
  final AssetReader _readAsset;

  TrustBundle? _current;
  TrustSource? _source;
  String? _lastError;
  DateTime? _lastRefreshAt;
  bool _loaded = false;

  /// The bundle in force, or null when nothing verified.
  ///
  /// A null here means every offline scan resolves to UNVERIFIABLE. That is the
  /// correct failure and the UI must say why rather than showing a verdict.
  TrustBundle? get current => _current;

  bool get hasBundle => _current != null;

  TrustSource? get source => _source;

  /// The most recent failure, for the diagnostics screen and the amber banner.
  /// Cleared by a successful load or refresh.
  String? get lastError => _lastError;

  DateTime? get lastRefreshAt => _lastRefreshAt;

  bool get isLoaded => _loaded;

  /// True when the key list is old enough to be worth refreshing.
  ///
  /// A bundle is not *invalid* for being stale — it is signed, and its keys carry
  /// their own validity windows — so this only decides whether to spend a network
  /// call, never whether to trust what we have.
  bool get needsRefresh {
    final DateTime? last = _lastRefreshAt;
    if (last == null) return true;
    return DateTime.now().difference(last) >= trustBundleRefreshInterval;
  }

  // ── Loading ────────────────────────────────────────────────────────────────

  /// Load the best available bundle. Call once, before the first scan.
  ///
  /// Never throws. A total failure leaves [current] null and [lastError] set,
  /// because a launch path that can throw is a launch path that can brick the app,
  /// and the app is still useful with no key list: it can read QR codes, show
  /// medicine details, verify online, and file reports.
  Future<void> load() async {
    _loaded = true;
    final List<String> problems = <String>[];

    final DateTime? floor = await _readHighWaterMark(problems);

    // Both candidates are parsed and root-verified before either is compared. A
    // shortcut that trusted the cache when present would mean a cache that fails
    // to verify leaves the app with nothing, even though the APK's own copy was
    // sitting right there.
    final TrustBundle? cached = await _loadCached(problems, floor);
    final TrustBundle? asset = await _loadAssetBundle(problems, floor);

    TrustBundle? best;
    TrustSource? bestSource;
    if (cached != null) {
      best = cached;
      bestSource = TrustSource.cache;
    }
    if (asset != null && (best == null || asset.isNewerThan(best))) {
      // The asset being newer than the cache is normal after an app update:
      // the new APK ships a list issued later than whatever was cached.
      best = asset;
      bestSource = TrustSource.asset;
    }

    _current = best;
    _source = bestSource;
    _lastRefreshAt = await _readLastRefresh();
    _lastError = _describe(problems, haveBundle: best != null);
    notifyListeners();
  }

  Future<TrustBundle?> _loadCached(List<String> problems, DateTime? floor) async {
    String? text;
    try {
      text = await _prefs.read(_kBundle);
    } on Object catch (err) {
      problems.add('the cached key list could not be read ($err)');
      return null;
    }
    if (text == null || text.isEmpty) return null;

    final TrustBundle? bundle = _parse(text, 'cached key list', problems);
    if (bundle == null) {
      // Verification failed, so this cache is either corrupt or forged. Either
      // way it will fail identically on every launch, so drop it now: keeping it
      // costs a pointless parse at every start and would mask the real state
      // behind a permanent error message.
      await _discardCache();
      return null;
    }
    if (_isRollback(bundle, floor)) {
      problems.add(
        'the cached key list is dated ${bundle.issuedAt}, which is older than '
        'the newest list this device has already accepted '
        '(${stamp(floor)}). It has been discarded as a rollback.',
      );
      await _discardCache();
      return null;
    }
    return bundle;
  }

  Future<TrustBundle?> _loadAssetBundle(
    List<String> problems,
    DateTime? floor,
  ) async {
    String text;
    try {
      text = await _readAsset(trustBundleAsset);
    } on Object catch (err) {
      // A missing asset is a build error, not a runtime condition: it means
      // `pubspec.yaml` lost its `assets:` entry. Named plainly so it is fixed
      // rather than mistaken for a network problem.
      problems.add(
        '$trustBundleAsset is not bundled in this build ($err), so there is no '
        'built-in key list to fall back on',
      );
      return null;
    }

    final TrustBundle? bundle = _parse(text, 'built-in key list', problems);
    if (bundle == null) return null;

    if (_isRollback(bundle, floor)) {
      // Deliberate, and the sharper edge of the two rollback checks. The built-in
      // list ages every day the APK is not updated, so once a device has accepted
      // anything newer this copy is permanently refused — including when the cache
      // is gone and this is all that is left. That trades availability for
      // integrity: accepting it would re-trust every key revoked since the build,
      // which is exactly the attack the mark exists to stop, while refusing it
      // costs amber verdicts until one successful refresh.
      problems.add(
        'the key list built into this app is dated ${bundle.issuedAt} and is '
        'older than the newest list this device has accepted (${stamp(floor)}), '
        'so it is not being used. Connect to the internet to update it.',
      );
      return null;
    }
    return bundle;
  }

  /// Parse and root-verify, converting any failure into a recorded problem.
  TrustBundle? _parse(String text, String what, List<String> problems) {
    try {
      return TrustBundle.fromJson(text);
    } on TrueMedException catch (err) {
      problems.add('the $what was rejected: ${err.message}');
      return null;
    } on Object catch (err) {
      problems.add('the $what could not be read: $err');
      return null;
    }
  }

  bool _isRollback(TrustBundle bundle, DateTime? floor) =>
      floor != null && !bundle.issuedAtInstant.isAfter(floor);

  Future<void> _discardCache() async {
    try {
      await _prefs.delete(_kBundle);
    } on Object {
      // If the cache cannot be deleted it will simply be rejected again next
      // launch. Nothing is trusted as a result of this failing.
    }
  }

  // ── The high-water mark ────────────────────────────────────────────────────

  /// Read the rollback floor, resetting it if the pinned root key has changed.
  ///
  /// The reset is what makes root rotation survivable. Ship a new APK with a new
  /// pinned root and the old cache stops verifying; without this the recorded mark
  /// would still be sitting above the new APK's own bundle, so the cache would be
  /// rejected for failing verification and the asset rejected as a rollback,
  /// leaving a permanently empty trust store that only reinstalling would fix.
  ///
  /// It is not a downgrade path. Lowering the mark this way requires changing the
  /// root key compiled into the binary, which requires re-signing the APK with the
  /// publisher's key. An attacker who can do that does not need a rollback.
  Future<DateTime?> _readHighWaterMark(List<String> problems) async {
    String? recorded;
    String? markFp;
    try {
      recorded = await _secure.read(_kMinIssuedAt);
      markFp = await _secure.read(_kMarkRootFp);
    } on Object catch (err) {
      // Reads from the secure store are already fail-soft (see SecureStore.read),
      // so reaching here means something worse. Treated as no mark: the root
      // signature check still stands, and refusing to start would be worse.
      problems.add('the rollback record could not be read ($err)');
      return null;
    }
    if (recorded == null || recorded.isEmpty) return null;

    if (markFp != null && markFp != pinnedRootFingerprint) {
      problems.add(
        'this build pins a different root key ($pinnedRootFingerprint) than the '
        'one the rollback record was written under ($markFp), so the record has '
        'been reset',
      );
      await _clearHighWaterMark();
      return null;
    }

    try {
      return parseInstant('min_issued_at', recorded);
    } on TrueMedException {
      // An unparseable mark is not usable as a floor and cannot be repaired.
      // Clearing it is safe: the next accepted bundle rewrites it.
      await _clearHighWaterMark();
      return null;
    }
  }

  Future<void> _clearHighWaterMark() async {
    try {
      await _secure.delete(_kMinIssuedAt);
      await _secure.delete(_kMarkRootFp);
    } on Object {
      // Ignored: a stale mark can only ever cause a bundle to be *refused*.
    }
  }

  /// Raise the mark to this bundle's `issued_at`.
  ///
  /// Only ever called after the bundle's bytes are safely cached. The order is
  /// load-bearing: raising the mark first and then failing to write the cache
  /// would leave a floor above every bundle on the device, so the next launch
  /// would refuse the cache (old) and the asset (older) and come up with no keys
  /// at all — a self-inflicted denial of service that survives restarts.
  Future<void> _raiseHighWaterMark(TrustBundle bundle) async {
    try {
      await _secure.write(_kMinIssuedAt, stamp(bundle.issuedAtInstant));
      await _secure.write(_kMarkRootFp, pinnedRootFingerprint);
    } on Object {
      // Not fatal. The bundle is cached and will be used; the device just loses
      // rollback protection for it until the next successful refresh. Worth
      // knowing about, so it is recorded rather than swallowed silently.
      _lastError = 'the new key list was saved, but this device could not record '
          'it for rollback protection';
    }
  }

  // ── Refreshing ─────────────────────────────────────────────────────────────

  /// Fetch `GET /api/public-keys` and adopt it if it is genuinely newer.
  ///
  /// Returns true only when the bundle in force changed. Never throws: a refresh
  /// is opportunistic and a failure must not interrupt whatever the user was
  /// doing. [force] skips the [needsRefresh] interval check.
  Future<bool> refresh(TrueMedApi api, {bool force = false}) async {
    if (!force && !needsRefresh) return false;

    String text;
    try {
      text = await api.fetchTrustBundle();
    } on TrueMedException catch (err) {
      // A refresh failing offline is expected, not noteworthy — the whole point
      // of the cache is to work without a network — so it does not overwrite
      // `lastError` and pester the user with a banner about it.
      if (!err.isTransportFailure) {
        _lastError = 'the key list could not be updated: ${err.message}';
        notifyListeners();
      }
      return false;
    } on Object catch (err) {
      _lastError = 'the key list could not be updated: $err';
      notifyListeners();
      return false;
    }

    final List<String> problems = <String>[];
    final TrustBundle? fetched = _parse(text, 'downloaded key list', problems);
    if (fetched == null) {
      // The API served something that does not verify against the pinned root.
      // That is either a server misconfiguration or an attempt to inject a key,
      // and in both cases the right move is to keep using what we have.
      _lastError = problems.join('; ');
      notifyListeners();
      return false;
    }

    final DateTime? floor = await _readHighWaterMark(problems);
    if (_isRollback(fetched, floor)) {
      _lastError =
          'the server offered a key list dated ${fetched.issuedAt}, which is '
          'older than one this device has already accepted. It has been ignored.';
      notifyListeners();
      return false;
    }

    final TrustBundle? existing = _current;
    if (existing != null && !fetched.isNewerThan(existing)) {
      // Same list, or an older one that predates the mark being written. Not an
      // error and not worth telling anyone about; just note that we checked.
      await _recordRefreshTime();
      notifyListeners();
      return false;
    }

    // `raw` is what came off the wire. It is non-null for anything built by
    // `fromJson`; the fallback keeps a null-safety analysis honest rather than
    // covering a case that can happen.
    final String toCache = fetched.raw ?? text;
    try {
      await _prefs.write(_kBundle, toCache);
    } on Object catch (err) {
      // Adopt it for this session anyway — it verified, it is newer, and refusing
      // to use a good key list because it could not be *saved* would be perverse.
      // The mark is deliberately not raised, so the next launch is free to fall
      // back to the cache or the asset.
      _current = fetched;
      _source = TrustSource.network;
      _lastError = 'the updated key list is in use but could not be saved ($err)';
      await _recordRefreshTime();
      notifyListeners();
      return true;
    }

    await _raiseHighWaterMark(fetched);
    await _recordRefreshTime();

    _current = fetched;
    _source = TrustSource.network;
    if (problems.isEmpty) _lastError = null;
    notifyListeners();
    return true;
  }

  Future<void> _recordRefreshTime() async {
    final DateTime now = DateTime.now();
    _lastRefreshAt = now;
    try {
      await _prefs.write(_kLastRefresh, stamp(now));
    } on Object {
      // Only affects when the next refresh is attempted.
    }
  }

  Future<DateTime?> _readLastRefresh() async {
    try {
      final String? raw = await _prefs.read(_kLastRefresh);
      if (raw == null || raw.isEmpty) return null;
      return parseInstant('last_refresh', raw).toLocal();
    } on Object {
      return null;
    }
  }

  // ── Diagnostics ────────────────────────────────────────────────────────────

  /// Reset to the built-in list: clears the cache, the refresh time and the
  /// rollback mark.
  ///
  /// Exposed on the diagnostics screen because the rollback mark can legitimately
  /// strand a device — a server that once served a bundle dated in the future
  /// would raise the mark above everything real, and no amount of waiting would
  /// clear it. Lowering the mark is only safe as an explicit human action on a
  /// device the human controls, which is why nothing calls this automatically.
  Future<void> resetToBuiltIn() async {
    await _discardCache();
    try {
      await _prefs.delete(_kLastRefresh);
    } on Object {
      // Non-fatal.
    }
    await _clearHighWaterMark();
    _current = null;
    _source = null;
    _lastError = null;
    _lastRefreshAt = null;
    await load();
  }

  Map<String, Object?> diagnostics() => <String, Object?>{
        'loaded': _loaded,
        'source': _source?.name,
        'last_refresh': _lastRefreshAt == null ? null : stamp(_lastRefreshAt),
        'needs_refresh': needsRefresh,
        'pinned_root': pinnedRootFingerprint,
        'development_root': isDevelopmentRootKey,
        'last_error': _lastError,
        if (_current != null) ...?_current?.summary(),
      };

  /// Collapse a list of problems into one message, or null.
  ///
  /// When a bundle did load, the problems are still reported: "the cache was
  /// discarded as a rollback but the built-in list is in use" is a state someone
  /// needs to see, even though scanning works.
  String? _describe(List<String> problems, {required bool haveBundle}) {
    if (problems.isEmpty) return null;
    final String joined = problems.join(' ');
    if (haveBundle) return joined;
    return '$joined No manufacturer key list is available, so medicines cannot '
        'be checked offline. Scans will still work online.';
  }
}
