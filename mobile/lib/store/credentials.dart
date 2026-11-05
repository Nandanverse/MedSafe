/// The signed-in API key, and the role it grants.
///
/// # The one rule here
///
/// **The role is always derived from the key, never stored beside it.** That is the
/// only design decision in this file that matters, and it is easy to get wrong: it
/// would be simpler to save `{"key": "...", "role": "pharmacy"}` and read the role
/// straight back. But a stored role is a separate, editable claim about what the
/// key can do. Anything that could rewrite it — a rooted device, a backup restore,
/// a bug in this file — would unlock the regulator screens for a chemist's key.
/// The server would still refuse every request, so nothing would actually be
/// recalled; what the user would get instead is a recall screen that fails with
/// FORBIDDEN and no explanation of why they can see a button they cannot use.
///
/// Deriving it with [roleOfApiKey] makes the two impossible to disagree.
///
/// # Why the key is re-read for every request
///
/// [provider] hits the secure store each time rather than holding the key in a
/// field. It costs a few milliseconds per call and buys two things: a key revoked
/// or replaced mid-session takes effect on the next request instead of after a
/// restart, and the plaintext key is not sitting in the heap for the lifetime of
/// the process, where a memory dump on a rooted device would find it.
library;

import 'dart:async';

import 'package:flutter/foundation.dart' show ChangeNotifier;

import '../core/errors.dart';
import '../core/rules.dart';
import 'secure_store.dart';

const String _kApiKey = 'auth.api_key';

/// Roles that may sign in to this app.
///
/// `manufacturer`, `distributor` and `sensor` are deliberately absent even though
/// §4.2 defines them. Minting belongs to factory tooling that holds a signing key
/// this app does not have, and `sensor` keys belong to ESP32 devices. Accepting
/// them here would present screens that cannot work and would encourage a
/// production signing credential to be typed into a phone.
const List<String> signInRoles = <String>['pharmacy', 'regulator', 'pharma'];

/// What each role is called on screen, and what it may do.
///
/// `pharma` and `pharmacy` are one letter apart and mean very different things —
/// see §4.2. The labels are written to be impossible to confuse even though the
/// role names are not.
String roleLabel(String? role) {
  switch (role) {
    case 'pharmacy':
      return 'Pharmacy — receive and dispense stock';
    case 'regulator':
      return 'CDSCO — recalls and national overview';
    case 'pharma':
      return 'Manufacturer — batch analytics (read-only)';
    case 'manufacturer':
      return 'Manufacturer — minting';
    case 'distributor':
      return 'Distributor';
    case 'sensor':
      return 'Cold-chain sensor';
    default:
      return 'Not signed in';
  }
}

class Credentials extends ChangeNotifier {
  Credentials({required KeyValueStore secure}) : _secure = secure;

  final KeyValueStore _secure;

  String? _role;
  bool _loaded = false;
  String? _maskedKey;

  /// The role granted by the stored key, or null when signed out.
  String? get role => _role;

  bool get isSignedIn => _role != null;

  bool get isLoaded => _loaded;

  /// The key with its middle removed, for display. Never the whole key: a
  /// screenshot of a settings screen is a credential leak, and support requests
  /// come with screenshots.
  String? get maskedKey => _maskedKey;

  bool get canRecall => _role == 'regulator';

  bool get canRecordCustody => _role == 'pharmacy';

  bool get canSeeCdscoDashboard => _role == 'regulator';

  bool get canSeePharmaDashboard => _role == 'pharma';

  /// Pass this to `TrueMedApi`'s `apiKeyProvider`.
  Future<String?> provider() async {
    try {
      final String? key = await _secure.read(_kApiKey);
      if (key == null || key.isEmpty) return null;
      // Re-validated on the way out. A stored value that no longer matches the
      // format is not sent: see the note in `TrueMedApi._authorised` about not
      // putting a mistyped secret into a server access log.
      if (!apiKeyRe.hasMatch(key)) return null;
      return key;
    } on Object {
      return null;
    }
  }

  /// Restore the session. Never throws.
  Future<void> load() async {
    _loaded = true;
    final String? key = await provider();
    _apply(key);
    notifyListeners();
  }

  /// Store a key after checking its shape.
  ///
  /// Throws [TrueMedException] with a message written for the person typing, since
  /// this is the one place in the app where a user enters a secret by hand and the
  /// commonest failures — a trailing space from a paste, the wrong role's key — are
  /// worth naming exactly.
  Future<void> signIn(String rawKey) async {
    final String key = rawKey.trim();
    if (key.isEmpty) {
      throw validationError('Enter the API key CDSCO issued you.');
    }
    final String? role = roleOfApiKey(key);
    if (role == null) {
      throw validationError(
        'That does not look like a TrueMed API key. Keys look like '
        'tm_pharmacy_ followed by 32 letters and digits. Check for a missing '
        'character or an extra space from copying.',
      );
    }
    if (!signInRoles.contains(role)) {
      throw validationError(
        'This is a $role key. The TrueMed app accepts pharmacy, CDSCO and '
        'manufacturer-analytics keys; $role keys are used by other parts of the '
        'system and are not typed into a phone.',
      );
    }

    try {
      await _secure.write(_kApiKey, key);
    } on Object catch (err) {
      // Deliberately not falling back to memory-only. A session that works until
      // the app restarts, with no indication that the key was never saved, wastes
      // more of a pharmacist's shift than an honest failure does.
      throw TrueMedException(
        Codes.internalError,
        'The key could not be saved to this device\'s secure storage ($err). '
        'Signing in would not survive a restart, so it has been cancelled.',
      );
    }

    _apply(key);
    notifyListeners();
  }

  /// Forget the key.
  ///
  /// In-memory state is cleared even if the delete fails, so the UI locks
  /// immediately: a sign-out button that visibly does nothing because a keystore
  /// write failed is worse than one that locks the screen and leaves a stale record
  /// to be overwritten by the next sign-in.
  Future<void> signOut() async {
    try {
      await _secure.delete(_kApiKey);
    } on Object {
      // Reported through nothing: there is no recovery, and the next `signIn`
      // overwrites the record anyway.
    }
    _apply(null);
    notifyListeners();
  }

  void _apply(String? key) {
    _role = key == null ? null : roleOfApiKey(key);
    _maskedKey = key == null ? null : _mask(key);
  }

  /// `tm_pharmacy_1a2b...ef90` — enough to tell two keys apart, not enough to use.
  ///
  /// The last four characters are kept as well as the first four because that is
  /// how a person checks a key against the one on the paper CDSCO sent them, and
  /// eight hex characters out of thirty-two leaves 96 bits unknown.
  static String _mask(String key) {
    final int underscore = key.lastIndexOf('_');
    if (underscore < 0 || key.length - underscore < 10) return 'tm_...';
    final String prefix = key.substring(0, underscore + 1);
    final String secret = key.substring(underscore + 1);
    return '$prefix${secret.substring(0, 4)}...'
        '${secret.substring(secret.length - 4)}';
  }
}
