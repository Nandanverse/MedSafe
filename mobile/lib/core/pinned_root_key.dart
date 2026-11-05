/// The pinned CDSCO root public key.
///
/// This constant is the single reason the app cannot be lied to by its own API.
/// `GET /api/public-keys` returns a bundle of manufacturer signing keys; if the
/// app trusted whatever came back, then anyone who could impersonate that
/// endpoint — a compromised server, a hostile Wi-Fi captive portal, a repackaged
/// APK on a third-party store — would insert their own key and mint QR codes that
/// verify perfectly, showing a bright green GENUINE over a bottle of chalk. With a
/// root key compiled into the binary and a root signature required over the whole
/// bundle, an attacker has to reach a key that is meant to live offline in a safe,
/// not merely a web server.
///
/// # Replacing it for a real deployment
///
/// The key is supplied as base64 of the DER SubjectPublicKeyInfo, one line, no
/// newlines, so it can travel as a `--dart-define`:
///
/// ```
/// openssl pkey -pubin -in root_public.pem -outform DER | base64 -w0
/// flutter build apk --release \
///   --dart-define=TRUEMED_ROOT_SPKI_B64=<that string> \
///   --dart-define=TRUEMED_API_BASE=https://api.truemed.example
/// ```
///
/// DER rather than PEM because [String.fromEnvironment] values cannot carry
/// newlines cleanly, and base64-of-DER is exactly the PEM body with the header
/// stripped — there is no new encoding to get wrong.
///
/// # The development default
///
/// The default below is the throwaway root key from
/// `backend/tests/fixtures/fixtures.json`, present so that `flutter test` and
/// `flutter run` work with no ceremony. Its private half is in the repository's
/// test fixtures, which is to say it is public. [isDevelopmentRootKey] is true
/// whenever it is in use, and the UI shows a permanent banner in that state. The
/// app deliberately still *works*: a build that silently refused to verify would
/// be debugged for a day, whereas a build that says "development trust root, not
/// for clinical use" across the top of every verdict is understood in a second.
library;

/// Base64 of the DER SubjectPublicKeyInfo for the trust-bundle signing root.
const String pinnedRootSpkiBase64 = String.fromEnvironment(
  'TRUEMED_ROOT_SPKI_B64',
  defaultValue: _developmentRootSpkiBase64,
);

/// The fingerprint the pinned key is expected to have.
///
/// Redundant with [pinnedRootSpkiBase64] — it is derived from it — and included
/// anyway as a cross-check on the build command, because a truncated or
/// line-wrapped `--dart-define` is otherwise discovered only when every scan in
/// the field starts returning UNVERIFIABLE.
const String pinnedRootFingerprint = String.fromEnvironment(
  'TRUEMED_ROOT_FINGERPRINT',
  defaultValue: _developmentRootFingerprint,
);

/// Throwaway root key from the test fixtures. Its private half is public.
const String _developmentRootSpkiBase64 =
    'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEHHSP9H8sB+yXOBxNJD3pc1wo0AlX'
    '+Z4QQSy/JFTzJ3BNM2D+qNvtM7O2qf1fOmDChdPE7OBLXjxo/I8VLbr6CA==';

const String _developmentRootFingerprint = 'bff333b3eef9f2df';

/// True when this build is pinned to the public development root key.
///
/// Drives the warning banner. Checked against both constants so that overriding
/// one but not the other does not quietly look like a production build.
bool get isDevelopmentRootKey =>
    pinnedRootSpkiBase64 == _developmentRootSpkiBase64 ||
    pinnedRootFingerprint == _developmentRootFingerprint;
