/// The trust bundle: which manufacturer public keys are legitimate.
///
/// Dart mirror of `backend/src/core/trust-bundle.js` and the `TrustBundle` half of
/// `qr-generator/truemed_qr/crypto.py`.
///
/// Two levels of key, and the second one is the whole point. Manufacturer keys
/// sign individual QR payloads, one per manufacturing licence number. A root key —
/// conceptually CDSCO's, kept offline — signs the bundle itself. See
/// `pinned_root_key.dart` for why the second level exists at all.
///
/// # How this differs from the server's copy, and why
///
/// The server loads a bundle from a file the operator controls, at startup, once.
/// A bad bundle there is a misconfiguration, so `trust-bundle.js` raises
/// INTERNAL_ERROR and the process refuses to start. None of that holds here:
///
/// 1. **Every failure is SIGNATURE_KEY_UNKNOWN**, via `trustBundleError`. On a
///    phone a bad bundle is a stale cache, a truncated download, or an attack —
///    never a config file somebody can fix. All three mean the same operational
///    thing: *this licence has no key this app can verify against*, which is
///    UNVERIFIABLE and amber. It must never be COUNTERFEIT and red. A trust store
///    problem is the app's problem; blaming the medicine for it is the one
///    mistake that destroys the app's credibility.
/// 2. **The root key is pinned, not supplied.** [loadTrustBundle] takes the root
///    key from `pinned_root_key.dart` by default and there is no code path that
///    accepts an unsigned bundle outside a test.
/// 3. **Rollback is checked.** A bundle can be *correctly signed* and still
///    hostile if it is an old one replayed to un-revoke a key that has since been
///    withdrawn. The server never sees this because nobody hands it files over a
///    network. Here, [TrustBundle.isNewerThan] gates every replacement, and the
///    cache only ever moves forward. This is the same reasoning as a TLS CRL
///    "this update" field, and it is the check that is easiest to leave out.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'base64url.dart';
import 'canonical.dart' as canonical;
import 'ecdsa.dart';
import 'errors.dart';
import 'pinned_root_key.dart';
import 'rules.dart';

const int trustBundleVersion = 1;

abstract final class KeyStatus {
  static const String active = 'active';
  static const String revoked = 'revoked';
}

const List<String> _requiredKeyFields = <String>[
  'mfg_licence_no',
  'manufacturer',
  'public_key_pem',
  'fingerprint',
  'valid_from',
  'valid_until',
];

/// Re-label any failure from `rules.dart` as a trust-store failure.
///
/// This is not tidying, it is a containment boundary, and leaving it out is a real
/// bug. `parseDate` raises PAYLOAD_INVALID and `parseInstant` raises
/// VALIDATION_ERROR — sensible codes for their usual callers, and both wrong here.
/// PAYLOAD_INVALID maps to verdict COUNTERFEIT through `verdictToErrorCode`, so a
/// single typo in a `valid_until` field, or a bundle served with a malformed
/// `issued_at`, would paint a red counterfeit banner over genuine medicine. The
/// medicine is not implicated by a defect in the app's key list, and nothing that
/// happens inside this file is allowed to say otherwise.
T _asTrustFailure<T>(T Function() body, String what) {
  try {
    return body();
  } on TrueMedException catch (err) {
    if (err.code == Codes.signatureKeyUnknown) rethrow;
    throw trustBundleError('$what: ${err.message}');
  }
}

/// One manufacturer signing key, as distributed to the app.
class TrustedKey {
  TrustedKey(Object? raw) {
    if (raw is! Map) {
      throw trustBundleError(
        'a trusted key entry must be a JSON object',
      );
    }
    for (final String field in _requiredKeyFields) {
      final Object? value = raw[field];
      if (value is! String || value.isEmpty) {
        throw trustBundleError(
          "a trusted key entry is missing or has a non-string '$field'",
        );
      }
    }
    mfgLicenceNo = raw['mfg_licence_no'] as String;
    manufacturer = raw['manufacturer'] as String;
    publicKeyPem = raw['public_key_pem'] as String;
    fingerprint = raw['fingerprint'] as String;
    validFrom = raw['valid_from'] as String;
    validUntil = raw['valid_until'] as String;

    final Object? rawStatus = raw['status'];
    if (rawStatus == null) {
      status = KeyStatus.active;
    } else if (rawStatus is String && rawStatus.isNotEmpty) {
      status = rawStatus;
    } else {
      throw trustBundleError(
        "the 'status' of licence $mfgLicenceNo is not a string",
      );
    }

    // Validate the dates now rather than at verification time. A typo in
    // valid_until should be caught while loading the bundle, not silently make
    // every strip from one manufacturer unverifiable at 3am in a rural pharmacy.
    _validFromDay = _asTrustFailure(
      () => parseDate('valid_from', validFrom),
      'licence $mfgLicenceNo',
    );
    _validUntilDay = _asTrustFailure(
      () => parseDate('valid_until', validUntil),
      'licence $mfgLicenceNo',
    );
    if (_validUntilDay.isBefore(_validFromDay)) {
      throw trustBundleError(
        'licence $mfgLicenceNo has valid_until $validUntil before valid_from '
        '$validFrom, so its key could never be used',
      );
    }
  }

  late final String mfgLicenceNo;
  late final String manufacturer;
  late final String publicKeyPem;

  /// The fingerprint the bundle *claims*. [publicKey] checks it against the PEM.
  late final String fingerprint;

  late final String validFrom;
  late final String validUntil;

  /// [KeyStatus.active] or [KeyStatus.revoked]. Any other value is accepted at
  /// load time and treated as not-active, matching the Node original: a bundle is
  /// allowed to name a status this build has not heard of, and the safe reading of
  /// an unknown status is "do not use this key".
  late final String status;

  late final DateTime _validFromDay;
  late final DateTime _validUntilDay;

  TrueMedPublicKey? _cached;

  /// The parsed key, cached.
  ///
  /// Parsing is done once per key per session rather than per scan: a pharmacist
  /// checking a carton of forty strips would otherwise pay for forty DER walks and
  /// forty PEM base64 decodes on a phone that may well be a 2GB Android Go device.
  TrueMedPublicKey publicKey() {
    final TrueMedPublicKey? cached = _cached;
    if (cached != null) return cached;

    final TrueMedPublicKey loaded = loadPublicKey(publicKeyPem);
    if (!constantTimeEquals(loaded.fingerprint, fingerprint)) {
      // Not a security control on its own — an attacker editing the bundle would
      // simply fix both fields, and the root signature is what actually stops
      // them. It catches a bundle assembled by hand or by a buggy export script
      // before those keys quietly fail to match anything.
      throw trustBundleError(
        'the entry for licence $mfgLicenceNo claims fingerprint $fingerprint '
        'but its PEM hashes to ${loaded.fingerprint}',
      );
    }
    _cached = loaded;
    return loaded;
  }

  /// Active, and [when] falls inside the validity window (inclusive at both ends).
  bool isValidOn([DateTime? when]) {
    if (status != KeyStatus.active) return false;
    final DateTime day = dayOf(when ?? DateTime.now());
    return !day.isBefore(_validFromDay) && !day.isAfter(_validUntilDay);
  }

  /// Exactly the shape the root signature is computed over.
  ///
  /// The field set and the defaulting of `status` must match `crypto.py` and
  /// `trust-bundle.js` exactly: these dictionaries are canonicalised and hashed,
  /// so an extra key, a missing key, or a differently-defaulted `status` changes
  /// the bytes and fails the signature on a perfectly genuine bundle.
  Map<String, Object?> toDict() => <String, Object?>{
        'mfg_licence_no': mfgLicenceNo,
        'manufacturer': manufacturer,
        'public_key_pem': publicKeyPem,
        'fingerprint': fingerprint,
        'valid_from': validFrom,
        'valid_until': validUntil,
        'status': status,
      };

  @override
  String toString() =>
      'TrustedKey($mfgLicenceNo, $fingerprint, $status, $validFrom..$validUntil)';
}

/// A parsed, root-verified set of manufacturer keys.
class TrustBundle {
  TrustBundle(
    this.keys, {
    required this.issuedAt,
    this.raw,
    this.rootSignatureHex,
    this.declaredRootFingerprint,
  }) {
    for (final TrustedKey key in keys) {
      if (_byLicence.containsKey(key.mfgLicenceNo)) {
        throw trustBundleError(
          'duplicate manufacturing licence "${key.mfgLicenceNo}" - one licence '
          'maps to exactly one signing key, and two entries would make which key '
          'verifies a strip depend on list order',
        );
      }
      _byLicence[key.mfgLicenceNo] = key;
    }
    _issuedAtInstant = _asTrustFailure(
      () => parseInstant('issued_at', issuedAt),
      'key list',
    );
  }

  final List<TrustedKey> keys;

  /// RFC 3339. Part of the signed bytes, and the basis of the rollback check.
  final String issuedAt;

  /// The bytes as received, kept verbatim.
  ///
  /// This is what gets written to the on-device cache. Note carefully that,
  /// unlike §1.5, that is **not** because verification depends on it: the root
  /// signature covers [signableBytes], a canonical re-serialisation of the
  /// *parsed* fields, so a JSON round-trip through the cache cannot change what
  /// gets verified. Whitespace and key order are discarded by the canonicaliser
  /// either way. A QR payload is the opposite case and the distinction is easy to
  /// blur — there the signature is over received bytes, so re-serialising one is a
  /// signature bypass.
  ///
  /// What keeping the original bytes actually buys is diagnosis. When a bundle
  /// stops verifying, the cached text is the evidence, and a re-encode would have
  /// destroyed the difference between "the server sent this" and "we parsed it
  /// this way". That difference is the whole answer to the most likely cause: a
  /// server bundle carrying a field inside `keys[]` that this build's [TrustedKey]
  /// does not know about, which [signableBytes] would then omit, producing a
  /// signature mismatch over a bundle that is in fact authentic. That fails
  /// closed — UNVERIFIABLE, never COUNTERFEIT — but only the raw text tells you
  /// why. If the signature ever moves to covering received bytes, this field stops
  /// being a convenience and becomes load-bearing.
  final String? raw;

  final String? rootSignatureHex;

  /// The `root_fingerprint` the bundle claims. Advisory only — it is inside the
  /// signed region but an attacker forging a bundle would set it to whatever they
  /// liked, so the pin in the binary is the authority.
  final String? declaredRootFingerprint;

  final Map<String, TrustedKey> _byLicence = <String, TrustedKey>{};

  late final DateTime _issuedAtInstant;

  int get size => keys.length;

  int get activeKeyCount =>
      keys.where((TrustedKey k) => k.status == KeyStatus.active).length;

  bool get isSigned => rootSignatureHex != null;

  DateTime get issuedAtInstant => _issuedAtInstant;

  bool has(String mfgLicenceNo) => _byLicence.containsKey(mfgLicenceNo);

  TrustedKey? entryFor(String mfgLicenceNo) => _byLicence[mfgLicenceNo];

  /// Every licence in the bundle, for the developer-tools screen.
  List<String> get licences => List<String>.unmodifiable(_byLicence.keys);

  /// Resolve a licence number to its trusted public key.
  ///
  /// Throws SIGNATURE_KEY_UNKNOWN for both "no such licence" and "revoked or out
  /// of window". `verifier.dart` turns that into UNVERIFIABLE (amber), never
  /// COUNTERFEIT (red), because the app not holding a key is not evidence about
  /// the medicine.
  TrueMedPublicKey publicKeyFor(String mfgLicenceNo, [DateTime? when]) {
    final TrustedKey? entry = _byLicence[mfgLicenceNo];
    if (entry == null) {
      throw trustBundleError(
        'no trusted signing key is registered for manufacturing licence '
        '"$mfgLicenceNo"; either this app\'s key list is out of date or the QR '
        'was signed by a party CDSCO has not registered',
      );
    }
    if (!entry.isValidOn(when)) {
      throw trustBundleError(
        'the signing key for licence "$mfgLicenceNo" is ${entry.status} or '
        'outside its validity window ${entry.validFrom}..${entry.validUntil}',
      );
    }
    return entry.publicKey();
  }

  /// The canonical bytes the root signature covers.
  ///
  /// Note what is *absent*: `root_signature` and `root_fingerprint`. A signature
  /// cannot cover itself.
  Uint8List signableBytes() => canonical.canonicalJSONBytes(<String, Object?>{
        'version': trustBundleVersion,
        'issued_at': issuedAt,
        'keys': keys.map((TrustedKey k) => k.toDict()).toList(growable: false),
      });

  /// True when [other] is older than this bundle, so replacing this with [other]
  /// would be a rollback.
  ///
  /// Equal timestamps count as *not* newer: a re-serve of the same bundle is not
  /// an upgrade, and treating it as one would let an attacker with a captured
  /// response keep a revoked key alive by replaying it forever.
  bool isNewerThan(TrustBundle other) =>
      _issuedAtInstant.isAfter(other._issuedAtInstant);

  /// Metadata for the diagnostics screen and for logs.
  Map<String, Object?> summary() => <String, Object?>{
        'version': trustBundleVersion,
        'issued_at': issuedAt,
        'key_count': keys.length,
        'active_key_count': activeKeyCount,
        'root_fingerprint': declaredRootFingerprint,
        'signed': isSigned,
        'development_root': isDevelopmentRootKey,
      };

  /// Parse a bundle and verify its root signature.
  ///
  /// [rootPublicKey] defaults to the key pinned in the binary. Pass
  /// `requireSignature: false` only from a test — there is no legitimate reason
  /// for the shipped app to trust an unsigned key list, and the parameter exists
  /// so that the fixture case `trust_bundle_unsigned` can be parsed in order to
  /// prove it is *rejected* by the default path.
  static TrustBundle fromJson(
    String text, {
    TrueMedPublicKey? rootPublicKey,
    bool requireSignature = true,
  }) {
    Object? decoded;
    try {
      decoded = jsonDecode(text);
    } on FormatException catch (err) {
      throw trustBundleError('not valid JSON: ${err.message}');
    }
    if (decoded is! Map) {
      throw trustBundleError('must be a JSON object');
    }

    final Object? version = decoded['version'];
    if (version != trustBundleVersion) {
      throw trustBundleError(
        'unsupported bundle version ${version ?? 'null'}; this build understands '
        'version $trustBundleVersion. Update TrueMed.',
      );
    }

    final Object? issuedAt = decoded['issued_at'];
    if (issuedAt is! String || issuedAt.isEmpty) {
      // The server defaults a missing issued_at to "now"; the client must not.
      // issued_at is inside the signed bytes, so inventing one guarantees the
      // signature check fails with a misleading message, and it would defeat the
      // rollback check besides.
      throw trustBundleError("'issued_at' is missing or not a string");
    }

    final Object? rawKeys = decoded['keys'];
    if (rawKeys is! List) {
      throw trustBundleError("'keys' must be an array");
    }

    final Object? signature = decoded['root_signature'];
    final Object? rootFp = decoded['root_fingerprint'];

    final TrustBundle bundle = TrustBundle(
      rawKeys.map<TrustedKey>((Object? entry) => TrustedKey(entry)).toList(
            growable: false,
          ),
      issuedAt: issuedAt,
      raw: text,
      rootSignatureHex: signature is String ? signature : null,
      declaredRootFingerprint: rootFp is String ? rootFp : null,
    );

    if (!requireSignature) return bundle;

    final TrueMedPublicKey root = rootPublicKey ?? pinnedRootKey();

    final String? hex = bundle.rootSignatureHex;
    if (hex == null) {
      throw trustBundleError(
        'this key list carries no root signature, so there is nothing to prove '
        'it came from CDSCO rather than from whoever answered the request',
      );
    }
    // fromHex rejects a leading sign as well as non-hex characters; see the note
    // in base64url.dart about why that specific case matters.
    final Uint8List signatureBytes = fromHexSignature(hex);

    if (!verifySignature(root, bundle.signableBytes(), signatureBytes)) {
      throw trustBundleError(
        'the root signature over this key list is invalid, so it is being '
        'refused. Either it was altered in transit or it was signed by a key '
        'this build of TrueMed does not pin.',
      );
    }

    // Advisory, and checked after the signature so a forged bundle cannot use a
    // mismatched fingerprint to produce a more helpful error message than it
    // deserves.
    final String? declared = bundle.declaredRootFingerprint;
    if (declared != null && !constantTimeEquals(declared, root.fingerprint)) {
      throw trustBundleError(
        'the key list was signed by root ${root.fingerprint} but declares '
        'root_fingerprint $declared; refusing a bundle that disagrees with '
        'itself',
      );
    }

    return bundle;
  }

  /// A one-key bundle, unsigned. Tests and single-manufacturer demos only.
  static TrustBundle single({
    required String mfgLicenceNo,
    required String manufacturer,
    required String publicKeyPem,
    String validFrom = '2020-01-01',
    String validUntil = '2099-12-31',
    String status = KeyStatus.active,
    String issuedAt = '2020-01-01T00:00:00Z',
  }) {
    return TrustBundle(
      <TrustedKey>[
        TrustedKey(<String, Object?>{
          'mfg_licence_no': mfgLicenceNo,
          'manufacturer': manufacturer,
          'public_key_pem': publicKeyPem,
          'fingerprint': fingerprintOfPem(publicKeyPem),
          'valid_from': validFrom,
          'valid_until': validUntil,
          'status': status,
        }),
      ],
      issuedAt: issuedAt,
    );
  }

  @override
  String toString() =>
      'TrustBundle($size keys, $activeKeyCount active, issued $issuedAt, '
      'signed: $isSigned)';
}

/// Decode a root signature from hex, rejecting anything that is not exactly a
/// 64-byte raw `r||s`.
///
/// The length is checked here rather than left to [verifySignature]'s silent
/// `false` so that "the bundle is malformed" and "the signature does not match"
/// stay distinguishable in a log. Both are refusals; only one suggests tampering.
/// The character validation is delegated to [fromHex], which rejects a leading
/// sign as well as non-hex digits — see the note there about why `-1` parsing to
/// `0xff` would have turned a malformed signature into a well-formed one.
Uint8List fromHexSignature(String hex) {
  if (hex.length != signatureLen * 2) {
    throw trustBundleError(
      'root_signature is ${hex.length} hex characters, but a P-256 signature is '
      '${signatureLen * 2} (r and s, 32 bytes each)',
    );
  }
  return fromHex(hex, 'root_signature');
}

TrueMedPublicKey? _pinnedRoot;

/// The root key compiled into this build, parsed once.
///
/// Throws SIGNATURE_KEY_UNKNOWN if the `--dart-define` was mangled — which is a
/// build error, but one that can only be discovered at runtime, so it is reported
/// in terms of what it means rather than what it is.
TrueMedPublicKey pinnedRootKey() {
  final TrueMedPublicKey? cached = _pinnedRoot;
  if (cached != null) return cached;

  Uint8List der;
  try {
    der = base64.decode(pinnedRootSpkiBase64);
  } on FormatException catch (err) {
    throw trustBundleError(
      'the root key compiled into this build is not valid base64 '
      '(${err.message}); it was probably line-wrapped by the build command. '
      'Re-run with: openssl pkey -pubin -in root_public.pem -outform DER | '
      'base64 -w0',
    );
  }

  final TrueMedPublicKey key = loadPublicKeyDer(der);
  if (!constantTimeEquals(key.fingerprint, pinnedRootFingerprint)) {
    throw trustBundleError(
      'the root key compiled into this build has fingerprint ${key.fingerprint} '
      'but TRUEMED_ROOT_FINGERPRINT says $pinnedRootFingerprint; the two '
      '--dart-define values do not describe the same key',
    );
  }
  _pinnedRoot = key;
  return key;
}

/// Clear the cached pinned root key. Tests only.
void resetPinnedRootKeyCache() {
  _pinnedRoot = null;
}
