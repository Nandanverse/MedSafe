/// ECDSA P-256 verification and the key fingerprint scheme.
///
/// Dart mirror of the verifying half of `backend/src/core/ecdsa.js` and
/// `qr-generator/truemed_qr/crypto.py`. There is no `sign()` here, for the same
/// reason there is none in the backend: a private key never leaves the
/// manufacturer's host, and an unused signing path in an app that ships to a
/// million phones is an invitation.
///
/// Signature encoding is raw `r||s`, 64 bytes, not the ASN.1 DER most libraries
/// emit natively. DER is variable-length (70-72 bytes typically), carries
/// redundant structure, and has a long history of parser-differential bugs; raw
/// is fixed-length, 8 bytes shorter, and has no parser at all. Eight bytes is
/// eleven base64url characters of QR budget, which is not nothing when the budget
/// is a printed square centimetre.
///
/// # Why the SPKI parser is written out by hand
///
/// Node has `createPublicKey`, Python has `cryptography`. Dart has neither in its
/// SDK, and `pointycastle` — which does the elliptic-curve arithmetic here —
/// deliberately does not parse X.509. The usual answer is a package like
/// `basic_utils`; the answer taken here is 90 lines of DER walking, because this
/// is the one piece of the app whose failure mode is silent. A parser that
/// misreads a key does not crash: it produces a *different* public key, every
/// signature then fails, and every genuine medicine in the country reads as
/// COUNTERFEIT. So the exact byte-walk below was first written in Python and
/// diffed against `cryptography` over all eight keys in the fixture bundles — x,
/// y, DER round-trip and fingerprint — plus five malformed inputs it must refuse.
/// See `docs/VERIFICATION.md`. Keeping the algorithm hand-written is what made
/// that cross-check possible: an oracle diff against a library only proves
/// something if the thing being tested is the thing that ships.
///
/// # What is pinned, and why pinning is the point
///
/// The curve is pinned to `prime256v1` by comparing the raw OID bytes, rather than
/// inferred from whatever the key claims. Accepting the key's own choice of curve
/// would let an attacker who can get one entry into a trust bundle downgrade to a
/// weak curve — and signatures under that key would then verify *perfectly*, so
/// nothing downstream would notice anything was wrong. TrueMed v1 is P-256, full
/// stop.
///
/// # What is deliberately not checked
///
/// Low-S normalisation. Some protocols (Bitcoin, and lately WebAuthn) reject
/// signatures whose `s` is above n/2 to make them non-malleable. TrueMed must not,
/// because the Python signer emits whatever `s` the RNG produces, and roughly half
/// of all genuine QR codes therefore carry a high `s`. Rejecting them would fail
/// half the medicine in the country closed. Malleability is harmless here anyway:
/// the QR is a fixed printed artefact, and the clone-telemetry defence keys on the
/// scanned string, which base64url canonicality already pins byte for byte.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:pointycastle/export.dart';

import 'errors.dart';

/// P-256 field size in bytes. Each of r and s occupies exactly this.
const int coordLen = 32;

/// Raw `r||s`.
const int signatureLen = coordLen * 2;

/// The number of leading bytes of the SHA-256 digest that make a fingerprint.
const int fingerprintBytes = 8;

/// `1.2.840.10045.2.1` — id-ecPublicKey, as DER content bytes with no tag or
/// length. Compared byte for byte rather than decoded into a dotted string,
/// because a decoder is another parser and this needs no flexibility.
const List<int> _oidEcPublicKey = <int>[
  0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
];

/// `1.2.840.10045.3.1.7` — prime256v1, a.k.a. P-256, a.k.a. secp256r1.
const List<int> _oidPrime256v1 = <int>[
  0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
];

const int _tagSequence = 0x30;
const int _tagOid = 0x06;
const int _tagBitString = 0x03;

/// The P-256 domain parameters, from SEC 2 v2 §2.4.2 / FIPS 186-4 D.1.2.3.
///
/// Written out rather than read off `pointycastle`'s curve object so that
/// [_assertOnCurve] below is an independent check rather than a tautology: if the
/// registry ever handed back the wrong curve, comparing its parameters against
/// themselves would not notice.
final BigInt _p = BigInt.parse(
  'ffffffff00000001000000000000000000000000ffffffffffffffffffffffff',
  radix: 16,
);
final BigInt _a = BigInt.parse(
  'ffffffff00000001000000000000000000000000fffffffffffffffffffffffc',
  radix: 16,
);
final BigInt _b = BigInt.parse(
  '5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b',
  radix: 16,
);

/// Order of the base point. r and s must both lie in `[1, n-1]`.
final BigInt _n = BigInt.parse(
  'ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551',
  radix: 16,
);

/// A parsed, curve-checked P-256 public key.
///
/// Immutable, and cheap to hold: the app keeps one of these per manufacturing
/// licence in memory for the life of a scan session, so a scan in a village with
/// no signal costs no parsing.
class TrueMedPublicKey {
  const TrueMedPublicKey._({
    required this.der,
    required this.x,
    required this.y,
    required this.fingerprint,
    required ECPublicKey key,
  }) : _key = key;

  /// The DER SubjectPublicKeyInfo exactly as it arrived, before any
  /// re-encoding. The fingerprint is over these bytes.
  final Uint8List der;

  final BigInt x;
  final BigInt y;

  /// 16 lowercase hex characters: `sha256(der)[0..8]`. Byte-identical to
  /// `fingerprint()` in `crypto.py` and `ecdsa.js`, because all three hash the
  /// same DER encoding of the same key.
  final String fingerprint;

  final ECPublicKey _key;

  /// The 65-byte uncompressed point, `0x04 || X || Y`.
  Uint8List get uncompressedPoint {
    final Uint8List out = Uint8List(1 + coordLen * 2);
    out[0] = 0x04;
    out.setRange(1, 1 + coordLen, _bigIntToFixedBytes(x, coordLen));
    out.setRange(1 + coordLen, out.length, _bigIntToFixedBytes(y, coordLen));
    return out;
  }

  @override
  String toString() => 'TrueMedPublicKey(P-256, $fingerprint)';
}

// ── DER reading ──────────────────────────────────────────────────────────────

/// A cursor over a byte range. Every read is bounds-checked against [end] rather
/// than against the buffer, so a nested structure cannot read past its parent's
/// declared length — the classic way a length-confusion bug turns into reading
/// somebody else's key material.
class _DerReader {
  _DerReader(this.bytes, this.pos, this.end);

  final Uint8List bytes;
  int pos;
  final int end;

  int get remaining => end - pos;

  int readByte() {
    if (pos >= end) {
      throw trustBundleError('truncated DER: expected another byte');
    }
    final int value = bytes[pos];
    pos += 1;
    return value;
  }

  /// Read a DER length, enforcing the shortest form.
  ///
  /// BER allows `81 05` for the length 5; DER does not, and accepting both would
  /// mean one key has two encodings and therefore two fingerprints. A trust
  /// bundle keyed by fingerprint cannot afford that.
  int readLength() {
    final int first = readByte();
    if (first < 0x80) return first;
    final int count = first & 0x7f;
    if (count == 0) {
      throw trustBundleError('indefinite DER length is not permitted');
    }
    if (count > 4) {
      throw trustBundleError(
        'a DER length spanning $count bytes is implausible in a P-256 key',
      );
    }
    int length = 0;
    for (int i = 0; i < count; i += 1) {
      length = (length << 8) | readByte();
    }
    if (length < 0x80) {
      throw trustBundleError(
        'DER length $length is not in shortest form (it fits in one byte)',
      );
    }
    return length;
  }

  /// Read one tag-length-value and return the content range as `[start, end)`.
  List<int> readTlv(int expectedTag, String what) {
    final int tag = readByte();
    if (tag != expectedTag) {
      throw trustBundleError(
        '$what: expected DER tag 0x${expectedTag.toRadixString(16).padLeft(2, '0')} '
        'but found 0x${tag.toRadixString(16).padLeft(2, '0')}',
      );
    }
    final int length = readLength();
    if (length > remaining) {
      throw trustBundleError(
        '$what: declared length $length runs past the end of the structure',
      );
    }
    final int start = pos;
    pos += length;
    return <int>[start, start + length];
  }
}

bool _rangeEquals(Uint8List bytes, int start, int end, List<int> expected) {
  if (end - start != expected.length) return false;
  for (int i = 0; i < expected.length; i += 1) {
    if (bytes[start + i] != expected[i]) return false;
  }
  return true;
}

BigInt _bigIntFromBytes(Uint8List bytes, int start, int end) {
  BigInt out = BigInt.zero;
  for (int i = start; i < end; i += 1) {
    out = (out << 8) | BigInt.from(bytes[i]);
  }
  return out;
}

Uint8List _bigIntToFixedBytes(BigInt value, int length) {
  final Uint8List out = Uint8List(length);
  BigInt rest = value;
  final BigInt mask = BigInt.from(0xff);
  for (int i = length - 1; i >= 0; i -= 1) {
    out[i] = (rest & mask).toInt();
    rest = rest >> 8;
  }
  return out;
}

/// Reject a point that is not actually on P-256.
///
/// `pointycastle`'s `createPoint` builds whatever coordinates it is given without
/// checking the curve equation. Feeding a verifier an off-curve point is the
/// invalid-curve attack: the arithmetic then happens in a group of the attacker's
/// choosing, and results in that group tell them nothing about the real key but
/// can be made to satisfy the verifier. Cheap to prevent, so prevented.
void _assertOnCurve(BigInt x, BigInt y) {
  if (x < BigInt.zero || x >= _p) {
    throw trustBundleError('public key X coordinate is outside the P-256 field');
  }
  if (y < BigInt.zero || y >= _p) {
    throw trustBundleError('public key Y coordinate is outside the P-256 field');
  }
  if (x == BigInt.zero && y == BigInt.zero) {
    throw trustBundleError('public key is the point at infinity');
  }
  final BigInt left = (y * y) % _p;
  final BigInt right = (((x * x) % _p) * x + _a * x + _b) % _p;
  if (left != right) {
    throw trustBundleError(
      'public key point is not on curve P-256; this is not a usable key and '
      'may be an attempt at an invalid-curve attack',
    );
  }
}

/// Strip a PEM envelope and base64-decode the body.
///
/// Only the first block with the given label is read, and anything outside the
/// BEGIN/END markers is ignored, which is how PEM files with comment headers
/// behave everywhere else.
Uint8List stripPem(String pemText, [String label = 'PUBLIC KEY']) {
  final String begin = '-----BEGIN $label-----';
  final String end = '-----END $label-----';
  final int i = pemText.indexOf(begin);
  if (i < 0) {
    throw trustBundleError('PEM is missing $begin');
  }
  final int j = pemText.indexOf(end, i + begin.length);
  if (j < 0) {
    throw trustBundleError('PEM is missing $end');
  }
  final String body = pemText.substring(i + begin.length, j);

  // Strip CR, LF, space and tab only. Not "all whitespace" and not a regex over
  // Unicode spaces: a non-breaking space inside base64 is corruption, and
  // silently tolerating it would change the bytes and so the fingerprint.
  final StringBuffer cleaned = StringBuffer();
  for (int k = 0; k < body.length; k += 1) {
    final int unit = body.codeUnitAt(k);
    if (unit == 0x0a || unit == 0x0d || unit == 0x20 || unit == 0x09) continue;
    cleaned.writeCharCode(unit);
  }
  final String joined = cleaned.toString();
  if (joined.isEmpty) {
    throw trustBundleError('PEM block for $label is empty');
  }
  final int remainder = joined.length % 4;
  final String padded =
      remainder == 0 ? joined : joined + '=' * (4 - remainder);
  try {
    return base64.decode(padded);
  } on FormatException catch (err) {
    throw trustBundleError('PEM body is not valid base64: ${err.message}');
  }
}

/// SHA-256 as lowercase hex.
String sha256Hex(List<int> data) {
  final SHA256Digest digest = SHA256Digest();
  final Uint8List out = digest.process(Uint8List.fromList(data));
  final StringBuffer hex = StringBuffer();
  for (final int byte in out) {
    hex.write(byte.toRadixString(16).padLeft(2, '0'));
  }
  return hex.toString();
}

/// Parse a P-256 public key from SubjectPublicKeyInfo PEM, refusing anything else.
///
/// Throws [TrueMedException] with SIGNATURE_KEY_UNKNOWN, because on a client every
/// reason a key will not load — corrupt cache, truncated download, hostile bundle,
/// wrong curve — reduces to the same operational fact: this licence has no key
/// this app can verify against.
TrueMedPublicKey loadPublicKey(String pem) {
  final Uint8List der = stripPem(pem);
  return loadPublicKeyDer(der);
}

/// As [loadPublicKey], but from DER bytes already stripped of their PEM envelope.
TrueMedPublicKey loadPublicKeyDer(Uint8List der) {
  final _DerReader outer = _DerReader(der, 0, der.length);
  final List<int> seq = outer.readTlv(_tagSequence, 'SubjectPublicKeyInfo');
  if (outer.remaining != 0) {
    // Trailing bytes would give one key two DER encodings and so two
    // fingerprints, which breaks the trust bundle's primary key.
    throw trustBundleError(
      'there are ${outer.remaining} trailing bytes after SubjectPublicKeyInfo',
    );
  }

  final _DerReader body = _DerReader(der, seq[0], seq[1]);
  final List<int> algId = body.readTlv(_tagSequence, 'AlgorithmIdentifier');

  final _DerReader alg = _DerReader(der, algId[0], algId[1]);
  final List<int> algOid = alg.readTlv(_tagOid, 'algorithm OID');
  if (!_rangeEquals(der, algOid[0], algOid[1], _oidEcPublicKey)) {
    throw trustBundleError(
      'this is not an id-ecPublicKey key; TrueMed v1 verifies ECDSA P-256 only',
    );
  }
  final List<int> curveOid = alg.readTlv(_tagOid, 'curve OID');
  if (!_rangeEquals(der, curveOid[0], curveOid[1], _oidPrime256v1)) {
    throw trustBundleError(
      'key is not on prime256v1 (P-256); the curve is pinned, not inferred, '
      'because a downgraded curve would still verify signatures perfectly',
    );
  }
  if (alg.remaining != 0) {
    throw trustBundleError(
      'unexpected trailing bytes in AlgorithmIdentifier '
      '(an EC key carries no algorithm parameters beyond the curve)',
    );
  }

  final List<int> bits = body.readTlv(_tagBitString, 'subjectPublicKey');
  if (body.remaining != 0) {
    throw trustBundleError(
      'unexpected trailing bytes inside SubjectPublicKeyInfo',
    );
  }

  int p = bits[0];
  if (p >= bits[1]) {
    throw trustBundleError('subjectPublicKey BIT STRING is empty');
  }
  if (der[p] != 0x00) {
    throw trustBundleError(
      'subjectPublicKey declares ${der[p]} unused bits; an EC point is a whole '
      'number of bytes, so this must be 0',
    );
  }
  p += 1;

  final int pointLen = bits[1] - p;
  if (pointLen == 0) {
    throw trustBundleError('the EC point is empty');
  }
  final int form = der[p];
  if (form == 0x02 || form == 0x03) {
    // Point decompression is a modular square root — implementable, but it would
    // be code with no oracle to check it against, guarding a case that cannot
    // occur: the Python signer's public_bytes(PEM, SubjectPublicKeyInfo) always
    // emits the uncompressed form. Refusing loudly beats shipping untested
    // arithmetic in the one place where a wrong answer is silent.
    throw trustBundleError(
      'the EC point is in compressed form (0x'
      '${form.toRadixString(16).padLeft(2, '0')}); TrueMed keys are stored '
      'uncompressed. Re-export this key with OpenSSL default settings.',
    );
  }
  if (form != 0x04) {
    throw trustBundleError(
      'the EC point starts with 0x${form.toRadixString(16).padLeft(2, '0')}, '
      'not 0x04, so it is not an uncompressed point',
    );
  }
  if (pointLen != 1 + coordLen * 2) {
    throw trustBundleError(
      'an uncompressed P-256 point is ${1 + coordLen * 2} bytes, got $pointLen',
    );
  }

  final BigInt x = _bigIntFromBytes(der, p + 1, p + 1 + coordLen);
  final BigInt y = _bigIntFromBytes(der, p + 1 + coordLen, p + 1 + coordLen * 2);
  _assertOnCurve(x, y);

  final ECDomainParameters domain = ECDomainParameters('prime256v1');
  final ECPublicKey key = ECPublicKey(domain.curve.createPoint(x, y), domain);

  return TrueMedPublicKey._(
    der: Uint8List.fromList(der),
    x: x,
    y: y,
    fingerprint: sha256Hex(der).substring(0, fingerprintBytes * 2),
    key: key,
  );
}

/// Fingerprint a PEM public key without keeping it.
String fingerprintOfPem(String pem) => loadPublicKey(pem).fingerprint;

/// Verify a raw 64-byte signature. Returns false rather than throwing.
///
/// Every failure mode — wrong length, wrong key, tampered data, a zero or
/// out-of-range r or s, an internal library error — collapses to `false`. Callers
/// decide what a failure means; here it is uniformly "not authentic", and no
/// return value or message distinguishes *why* a forgery failed. That uniformity
/// is deliberate: an attacker holding a QR code and a phone can call this as often
/// as they like, and a verifier that explains itself is a verifier that helps.
///
/// [data] must be the bytes **as received**, never a re-serialisation of a parse
/// of them (§1.5).
bool verifySignature(
  TrueMedPublicKey publicKey,
  List<int> data,
  List<int> signature,
) {
  try {
    if (signature.length != signatureLen) return false;

    final Uint8List sig = signature is Uint8List
        ? signature
        : Uint8List.fromList(signature);

    final BigInt r = _bigIntFromBytes(sig, 0, coordLen);
    final BigInt s = _bigIntFromBytes(sig, coordLen, signatureLen);

    // r = 0 or s = 0 is never a valid ECDSA signature, and naive verifiers have
    // historically accepted them; r or s at or above n is a non-canonical
    // re-encoding of another signature. Both are checked here rather than relying
    // on the library, and neither rejects anything a genuine signer produces.
    if (r < BigInt.one || r >= _n) return false;
    if (s < BigInt.one || s >= _n) return false;

    final ECDSASigner signer = ECDSASigner(SHA256Digest(), null);
    signer.init(false, PublicKeyParameter<ECPublicKey>(publicKey._key));
    return signer.verifySignature(
      data is Uint8List ? data : Uint8List.fromList(data),
      ECSignature(r, s),
    );
  } catch (_) {
    // A library-level rejection is still just "not authentic".
    return false;
  }
}

/// Verify, throwing SIGNATURE_INVALID on failure.
///
/// The message is written for a pharmacist reading a log, not for a developer:
/// the actionable fact is that the item should be treated as counterfeit.
void verifyOrThrow(
  TrueMedPublicKey publicKey,
  List<int> data,
  List<int> signature,
) {
  if (!verifySignature(publicKey, data, signature)) {
    throw TrueMedException(
      Codes.signatureInvalid,
      'the ECDSA signature does not match the payload under the trusted key for '
      'this manufacturing licence - treat this item as counterfeit',
    );
  }
}

/// HMAC-SHA256 as lowercase hex, over UTF-8 of [message].
///
/// Present for the sensor-attestation string in DATA-CONTRACT.md §4.7 so that the
/// regulator screen can check a reading's HMAC without a round trip. The app never
/// *produces* one — only the ESP32 holds a sensor secret.
String hmacSha256Hex(List<int> secret, String message) {
  final HMac mac = HMac(SHA256Digest(), 64)
    ..init(KeyParameter(Uint8List.fromList(secret)));
  final Uint8List out = mac.process(Uint8List.fromList(utf8.encode(message)));
  final StringBuffer hex = StringBuffer();
  for (final int byte in out) {
    hex.write(byte.toRadixString(16).padLeft(2, '0'));
  }
  return hex.toString();
}

/// Compare two strings without leaking where they first differ.
///
/// Used for fingerprints and HMAC digests. A fingerprint is not a secret, so this
/// is belt-and-braces there; for an HMAC comparison it is the difference between a
/// check and a decoration.
bool constantTimeEquals(String a, String b) {
  if (a.length != b.length) return false;
  int diff = 0;
  for (int i = 0; i < a.length; i += 1) {
    diff |= a.codeUnitAt(i) ^ b.codeUnitAt(i);
  }
  return diff == 0;
}
