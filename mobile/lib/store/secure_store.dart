/// Key-value persistence, behind one interface with three implementations.
///
/// # Why an interface at all
///
/// The two Flutter plugins involved — `flutter_secure_storage` and
/// `shared_preferences` — both need a platform channel, which means a real device
/// or an emulator. Everything interesting in [TrustStore] is decision logic:
/// is this bundle a rollback, does this cache still verify, should we refresh yet.
/// Behind this interface that logic runs in `dart test` against a map, so the
/// rollback rules can be tested with a dozen string literals instead of an
/// instrumentation harness. Security logic that is awkward to test does not get
/// tested.
///
/// # Which store holds what, and why the split is not arbitrary
///
/// [SecureStore] is backed by the Android Keystore / iOS Keychain. It is slow
/// (every read is an IPC round trip and a decryption) and size-limited in
/// practice, so only two kinds of thing go in it: the API key, which is a
/// credential, and the trust-store high-water mark, which is an *integrity* anchor
/// an attacker must not be able to lower.
///
/// [PrefsStore] is plaintext `SharedPreferences`. The trust bundle itself lives
/// here, which looks wrong at a glance and is not: the bundle is public data whose
/// integrity comes from a root signature verified on every load against a key
/// pinned in the APK. Encrypting it would protect nothing — the attacker who can
/// read it can read it from the network too — while making a 200 kB read slow
/// enough to notice at launch. Confidentiality and integrity are different
/// properties and this is a case where only one of them is needed.
library;

import 'dart:async';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:shared_preferences/shared_preferences.dart';

/// The persistence surface the rest of the app depends on.
///
/// Deliberately tiny: four methods, all `String`-valued. Anything richer would
/// have to be reimplemented in [MemoryStore] and would drift from the real thing.
abstract interface class KeyValueStore {
  Future<String?> read(String key);
  Future<void> write(String key, String value);
  Future<void> delete(String key);

  /// Remove every key this store owns. Used by "sign out" and by the recovery
  /// path when stored data turns out to be unreadable.
  Future<void> clear();
}

/// Hardware-backed storage for credentials and integrity anchors.
class SecureStore implements KeyValueStore {
  SecureStore({FlutterSecureStorage? storage})
      : _storage = storage ??
            const FlutterSecureStorage(
              aOptions: AndroidOptions(
                // Jetpack Security's `EncryptedSharedPreferences`, whose master
                // key lives in the Android Keystore and, on devices with a secure
                // element, never enters application memory. The plugin's older
                // default wrapped values with an RSA key it managed itself; this
                // is both faster and harder to extract from a rooted device.
                encryptedSharedPreferences: true,
              ),
              iOptions: IOSOptions(
                // `first_unlock_this_device`: readable by background refresh after
                // the first unlock following a reboot, but never migrated to a new
                // device by an iCloud backup. An API key restored onto a stranger's
                // phone along with a backup would be a credential leak that no one
                // would think to look for.
                accountName: 'truemed',
                accessibility: KeychainAccessibility.first_unlock_this_device,
              ),
            );

  final FlutterSecureStorage _storage;

  /// Reads that fail are reported as "absent", not as an error.
  ///
  /// This is not laziness about error handling — it is the fix for a real and
  /// well-known crash. The keystore entry backing these values can become
  /// undecryptable while the app's data survives: a device-to-device transfer, an
  /// Android backup restore, or a fingerprint-enrolment change can all invalidate
  /// the master key, and the plugin then throws [PlatformException] on *every*
  /// read. An app that lets that propagate from its launch path crashes on start,
  /// forever, and the only user-discoverable fix is uninstalling. Treating the
  /// value as missing degrades to "please sign in again", which is recoverable.
  ///
  /// The unreadable entry is deleted on the way out so the next write starts
  /// clean rather than hitting the same corrupt record.
  @override
  Future<String?> read(String key) async {
    try {
      return await _storage.read(key: key);
    } on Object {
      try {
        await _storage.delete(key: key);
      } on Object {
        // Nothing further to try. The caller sees `null`, which is the truth from
        // its point of view: there is no readable value here.
      }
      return null;
    }
  }

  @override
  Future<void> write(String key, String value) =>
      _storage.write(key: key, value: value);

  @override
  Future<void> delete(String key) => _storage.delete(key: key);

  @override
  Future<void> clear() => _storage.deleteAll();
}

/// Plaintext storage for public, integrity-protected and non-sensitive data.
///
/// One [SharedPreferences] instance is shared across every [PrefsStore], because
/// `getInstance` is cheap only after the first call and the first call reads the
/// whole file.
class PrefsStore implements KeyValueStore {
  PrefsStore({String prefix = 'truemed.'}) : _prefix = prefix;

  final String _prefix;
  static Future<SharedPreferences>? _instance;

  static Future<SharedPreferences> _prefs() =>
      _instance ??= SharedPreferences.getInstance();

  /// Preload the preferences file.
  ///
  /// Called once from `main()` before the first frame so that no screen's build
  /// method is the thing that first hits disk. Without it the first scan pays for
  /// the file read while the camera is also starting.
  static Future<void> warmUp() async {
    await _prefs();
  }

  @override
  Future<String?> read(String key) async =>
      (await _prefs()).getString('$_prefix$key');

  @override
  Future<void> write(String key, String value) async {
    await (await _prefs()).setString('$_prefix$key', value);
  }

  @override
  Future<void> delete(String key) async {
    await (await _prefs()).remove('$_prefix$key');
  }

  /// Removes only this store's prefixed keys.
  ///
  /// Not `SharedPreferences.clear()`, which would wipe every preference the app
  /// has including ones other stores own.
  @override
  Future<void> clear() async {
    final SharedPreferences prefs = await _prefs();
    final List<String> mine = prefs
        .getKeys()
        .where((String k) => k.startsWith(_prefix))
        .toList(growable: false);
    for (final String key in mine) {
      await prefs.remove(key);
    }
  }
}

/// In-memory store for tests.
class MemoryStore implements KeyValueStore {
  MemoryStore([Map<String, String>? initial])
      : _values = <String, String>{...?initial};

  final Map<String, String> _values;

  /// Set true to make every operation throw, so callers can be tested against a
  /// store that is present but broken — the [SecureStore] corruption case above,
  /// which is otherwise almost impossible to reproduce.
  bool failEverything = false;

  /// Every key currently held, for assertions.
  Map<String, String> get snapshot => Map<String, String>.unmodifiable(_values);

  void _check() {
    if (failEverything) {
      throw StateError('MemoryStore was told to fail');
    }
  }

  @override
  Future<String?> read(String key) async {
    _check();
    return _values[key];
  }

  @override
  Future<void> write(String key, String value) async {
    _check();
    _values[key] = value;
  }

  @override
  Future<void> delete(String key) async {
    _check();
    _values.remove(key);
  }

  @override
  Future<void> clear() async {
    _check();
    _values.clear();
  }
}
