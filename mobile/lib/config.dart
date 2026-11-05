/// Build-time configuration, supplied with `--dart-define`.
///
/// Everything here is a compile-time constant so it can be baked into a release
/// APK without a config file to ship, misplace, or edit on a rooted device. The
/// pinned root key is deliberately *not* here — it lives in
/// `core/pinned_root_key.dart`, beside the code that consumes it, because the core
/// must stay importable without any of the app layers.
///
/// ```
/// flutter run \
///   --dart-define=TRUEMED_API_BASE=http://192.168.1.7:3000
///
/// flutter build apk --release \
///   --dart-define=TRUEMED_API_BASE=https://api.truemed.example \
///   --dart-define=TRUEMED_ROOT_SPKI_B64=<base64 DER SPKI> \
///   --dart-define=TRUEMED_ROOT_FINGERPRINT=<16 hex chars>
/// ```
library;

import 'core/pinned_root_key.dart';

/// Where the REST API lives, without a trailing slash.
///
/// The default is the Android emulator's alias for the host machine's loopback
/// interface. `localhost` inside an emulator is the emulator itself, which is the
/// single most common wasted hour when first wiring a Flutter app to a local API,
/// so the default is the one that works out of the box for `flutter run` on an
/// emulator with `npm start` running on the laptop. A physical phone on the same
/// Wi-Fi needs the laptop's LAN address instead.
const String apiBaseUrl = String.fromEnvironment(
  'TRUEMED_API_BASE',
  defaultValue: 'http://10.0.2.2:3000',
);

/// How long to wait for the API before falling back to offline verification.
///
/// Eight seconds, which is longer than it sounds and shorter than it should be for
/// a rural 2G connection. The number is a compromise with a specific failure in
/// mind: a patient standing at a pharmacy counter holding a strip. The offline
/// result is already on screen by the time this request is made — the network call
/// only ever *adds* duplicate-scan and cold-chain information — so a timeout
/// costs completeness, never correctness. Waiting thirty seconds for that would
/// be worse than not waiting at all, because the patient will have paid and left.
const Duration apiTimeout = Duration(seconds: 8);

/// A shorter budget for the health probe, which only ever decides whether to show
/// an "offline" chip in the app bar.
const Duration healthTimeout = Duration(seconds: 3);

/// How often to re-fetch the trust bundle when online, at most.
///
/// Six hours. The bundle is the app's revocation list, so a longer interval leaves
/// a withdrawn key usable for longer; a shorter one costs data on connections
/// billed by the megabyte. CDSCO revoking a manufacturer licence is a rare,
/// deliberate event, and six hours is well inside the time it takes for a recall
/// to reach pharmacies by any other channel.
const Duration trustBundleRefreshInterval = Duration(hours: 6);

/// True when this build talks to the API over plaintext HTTP.
///
/// Not fatal, and worth surfacing. Verification does not depend on TLS — the QR
/// signature is checked against a pinned root, so a network attacker cannot forge
/// a GENUINE verdict over plain HTTP any more than over HTTPS. What they *can* do
/// is read which medicines a person is scanning, which is health data about an
/// identifiable individual and squarely within the DPDP Act. So: allowed for
/// development, flagged in the UI, and the release checklist in mobile/README.md
/// treats shipping it as a blocker.
bool get isInsecureTransport => !apiBaseUrl.startsWith('https://');

/// True when nothing about this build is safe for real medicine.
///
/// Either half being true is enough. A build with a real API but the public
/// development trust root would verify forged QR codes; a build with the real root
/// but a development API would leak scan history. Neither is a production build.
bool get isDevelopmentBuild => isDevelopmentRootKey || isInsecureTransport;

/// Shown in the diagnostics screen, and in a bug report.
Map<String, Object?> buildInfo() => <String, Object?>{
      'api_base': apiBaseUrl,
      'root_fingerprint': pinnedRootFingerprint,
      'development_root': isDevelopmentRootKey,
      'insecure_transport': isInsecureTransport,
      'api_timeout_ms': apiTimeout.inMilliseconds,
    };
