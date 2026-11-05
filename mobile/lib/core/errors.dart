/// Typed errors carrying the machine-readable codes from DATA-CONTRACT.md §2.4.
///
/// Dart mirror of `backend/src/core/errors.js` and
/// `qr-generator/truemed_qr/errors.py`. The UI switches on [code], never on
/// prose, so these strings are part of the frozen v1 contract.
///
/// The HTTP-status table from the Node version is deliberately absent: this is a
/// client. It receives statuses, it does not choose them. What it does need — and
/// what Node does not — is the ability to tell a *transport* failure (no signal
/// in a village, DNS down, TLS handshake refused) apart from a *verdict*, because
/// the first one must silently fall back to offline verification while the second
/// must be shown to the patient. That is [isTransportFailure].
library;

/// Every code in DATA-CONTRACT.md §2.4, plus the internal catch-all.
abstract final class Codes {
  static const String qrMalformed = 'QR_MALFORMED';
  static const String qrUnknownVersion = 'QR_UNKNOWN_VERSION';
  static const String payloadInvalid = 'PAYLOAD_INVALID';
  static const String signatureInvalid = 'SIGNATURE_INVALID';
  static const String signatureKeyUnknown = 'SIGNATURE_KEY_UNKNOWN';
  static const String expired = 'EXPIRED';
  static const String notOnChain = 'NOT_ON_CHAIN';
  static const String recalled = 'RECALLED';
  static const String coldChainBreach = 'COLD_CHAIN_BREACH';
  static const String cloneSuspected = 'CLONE_SUSPECTED';
  static const String upstreamUnavailable = 'UPSTREAM_UNAVAILABLE';
  static const String rateLimited = 'RATE_LIMITED';
  static const String unauthorized = 'UNAUTHORIZED';
  static const String forbidden = 'FORBIDDEN';
  static const String validationError = 'VALIDATION_ERROR';
  static const String notFound = 'NOT_FOUND';
  static const String conflict = 'CONFLICT';
  static const String internalError = 'INTERNAL_ERROR';

  /// Client-only: the request never reached the API.
  ///
  /// Not in §2.4 because the server can never emit it — by the time a response
  /// exists, the network worked. It is nonetheless a first-class code here
  /// because it is the single most common outcome in the deployments this app is
  /// built for, and the UI must react to it by degrading to offline rather than
  /// by showing an error.
  static const String networkUnavailable = 'NETWORK_UNAVAILABLE';

  /// Client-only: the API answered, but not with something this build understands.
  static const String badResponse = 'BAD_RESPONSE';

  static const Set<String> all = <String>{
    qrMalformed,
    qrUnknownVersion,
    payloadInvalid,
    signatureInvalid,
    signatureKeyUnknown,
    expired,
    notOnChain,
    recalled,
    coldChainBreach,
    cloneSuspected,
    upstreamUnavailable,
    rateLimited,
    unauthorized,
    forbidden,
    validationError,
    notFound,
    conflict,
    internalError,
    networkUnavailable,
    badResponse,
  };

  static bool isKnown(String? code) => code != null && all.contains(code);
}

/// The one exception type this app throws for anything contract-shaped.
class TrueMedException implements Exception {
  TrueMedException(String code, this.message, {this.details, this.status})
      : code = Codes.isKnown(code) ? code : Codes.internalError;

  /// One of [Codes].
  final String code;

  /// Human-readable and safe to log. Not necessarily safe to *show*: use
  /// `friendlyMessage` from the UI layer for patient-facing text.
  final String message;

  /// Whatever `error.details` carried, when the API supplied it.
  final Object? details;

  /// HTTP status, when this came from a response. Null for local failures.
  final int? status;

  /// True when the request never got an answer, so falling back to the offline
  /// path is the correct response rather than an error to display.
  bool get isTransportFailure =>
      code == Codes.networkUnavailable || code == Codes.upstreamUnavailable;

  /// True when the caller's credentials are the problem, so re-authenticating
  /// might fix it. Used by the pharmacy and regulator screens to bounce back to
  /// the login sheet instead of showing a dead end.
  bool get isAuthFailure =>
      code == Codes.unauthorized || code == Codes.forbidden;

  @override
  String toString() => 'TrueMedException($code): $message';
}

TrueMedException qrMalformed(String message) =>
    TrueMedException(Codes.qrMalformed, message);

TrueMedException qrUnknownVersion(String message) =>
    TrueMedException(Codes.qrUnknownVersion, message);

TrueMedException payloadInvalid(String message) =>
    TrueMedException(Codes.payloadInvalid, message);

TrueMedException signatureKeyUnknown(String message) =>
    TrueMedException(Codes.signatureKeyUnknown, message);

TrueMedException validationError(String message, {Object? details}) =>
    TrueMedException(Codes.validationError, message, details: details);

TrueMedException networkUnavailable(String message) =>
    TrueMedException(Codes.networkUnavailable, message);

TrueMedException badResponse(String message) =>
    TrueMedException(Codes.badResponse, message);

/// Trust-bundle problems.
///
/// Node maps these to INTERNAL_ERROR because there the bundle is a file the
/// operator controls and a bad one is a server misconfiguration. Here the bundle
/// arrived over the network or came out of the APK, so a bad one is either a
/// stale cache or an attack — both of which mean "this key cannot be trusted",
/// which is exactly SIGNATURE_KEY_UNKNOWN.
TrueMedException trustBundleError(String message) =>
    TrueMedException(Codes.signatureKeyUnknown, 'trust bundle: $message');
